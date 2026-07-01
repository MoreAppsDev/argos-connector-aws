/**
 * Argos V2 — AWS CloudTrail connector / núcleo de detecção.
 *
 * Recebe um registro CloudTrail (event.detail vindo do EventBridge) e decide:
 *  - se casa com alguma das regras de segurança (push-down filter: só o que
 *    importa vira evento; o resto é descartado no edge — disciplina anti-custo);
 *  - qual severidade (1-10) e como mapear actor/target/action pro payload do
 *    endpoint `POST /api/ingest/security-event`.
 *
 * Zero dependências externas — roda em Node 20 (Lambda) e em teste local.
 */

/** @typedef {{ key: string, title: string, severity: number, actor: string|null, target: string|null, action: string }} Detection */

const ADMIN_POLICY_HINTS = [
  'AdministratorAccess',
  'IAMFullAccess',
  'arn:aws:iam::aws:policy/AdministratorAccess',
];
const PUBLIC_GRANTEES = [
  'AllUsers',
  'AuthenticatedUsers',
  'global/AllUsers',
  'global/AuthenticatedUsers',
];

/** Nome legível do ator a partir do userIdentity do CloudTrail. */
function actorOf(record) {
  const id = record.userIdentity ?? {};
  if (id.type === 'Root') return 'root';
  return (
    id.userName ??
    id.sessionContext?.sessionIssuer?.userName ??
    id.arn ??
    id.principalId ??
    id.type ??
    null
  );
}

/** JSON do requestParameters em string (best-effort) pra varreduras textuais. */
function paramsText(record) {
  try {
    return JSON.stringify(record.requestParameters ?? {});
  } catch {
    return '';
  }
}

// Portas cuja exposição a 0.0.0.0/0 é perigosa (admin/bancos/serviços internos).
// 80/443 ficam de fora de propósito — servidor web público é normal.
const SENSITIVE_PORTS = new Set([
  21, 22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
]);
const ADMIN_PORTS = new Set([22, 3389]); // SSH / RDP — os mais críticos

/** CloudTrail ora entrega listas como array cru, ora como { items: [...] }. */
function toArray(x) {
  if (!x) return [];
  if (Array.isArray(x)) return x;
  if (Array.isArray(x.items)) return x.items;
  return [x];
}

/**
 * Analisa um AuthorizeSecurityGroupIngress: retorna as portas sensíveis abertas
 * ao mundo (0.0.0.0/0 ou ::/0) e se é "todas as portas". null se não abre nada
 * relevante ao mundo.
 */
function openToWorldIngress(r) {
  const perms = toArray(r.requestParameters?.ipPermissions);
  let allPorts = false;
  const ports = [];
  let world = false;
  for (const p of perms) {
    const v4 = toArray(p.ipRanges).some((x) => x?.cidrIp === '0.0.0.0/0');
    const v6 = toArray(p.ipv6Ranges).some((x) => x?.cidrIpv6 === '::/0');
    if (!v4 && !v6) continue;
    world = true;
    if (String(p.ipProtocol ?? '') === '-1') {
      allPorts = true;
      continue;
    }
    const from = Number(p.fromPort);
    const to = Number(p.toPort);
    if (Number.isFinite(from) && Number.isFinite(to)) {
      for (const port of SENSITIVE_PORTS) if (port >= from && port <= to) ports.push(port);
    }
  }
  if (!world) return null;
  return { allPorts, ports };
}

/**
 * Catálogo de regras de detecção. Cada uma recebe o registro CloudTrail e
 * devolve uma Detection (match) ou null. `detect()` escolhe a de maior severidade.
 */
const RULES = [
  // root_login — uso da conta root no console (deveria ser raríssimo).
  function rootLogin(r) {
    if (r.eventName !== 'ConsoleLogin') return null;
    if (r.userIdentity?.type !== 'Root') return null;
    const success = r.responseElements?.ConsoleLogin === 'Success';
    return {
      key: 'root_login',
      title: 'Login da conta root no console',
      severity: success ? 9 : 7,
      actor: 'root',
      target: r.recipientAccountId ?? r.userIdentity?.accountId ?? null,
      action: 'ConsoleLogin',
    };
  },

  // console_login_no_mfa — login de usuário IAM no console sem MFA.
  function consoleLoginNoMfa(r) {
    if (r.eventName !== 'ConsoleLogin') return null;
    if (r.userIdentity?.type === 'Root') return null;
    if (r.additionalEventData?.MFAUsed !== 'No') return null;
    if (r.responseElements?.ConsoleLogin !== 'Success') return null;
    return {
      key: 'console_login_no_mfa',
      title: 'Login no console sem MFA',
      severity: 7,
      actor: actorOf(r),
      target: r.recipientAccountId ?? null,
      action: 'ConsoleLogin',
    };
  },

  // iam_attach_admin_policy — concessão de política de administrador.
  function iamAttachAdminPolicy(r) {
    const names = ['AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy'];
    if (!names.includes(r.eventName)) return null;
    const policyArn = r.requestParameters?.policyArn ?? '';
    const hit = ADMIN_POLICY_HINTS.some((h) => policyArn.includes(h));
    if (!hit) return null;
    const targetName =
      r.requestParameters?.userName ??
      r.requestParameters?.roleName ??
      r.requestParameters?.groupName ??
      null;
    return {
      key: 'iam_attach_admin_policy',
      title: 'Política de administrador anexada',
      severity: 8,
      actor: actorOf(r),
      target: targetName,
      action: r.eventName,
    };
  },

  // s3_public_acl — bucket/objeto exposto publicamente.
  function s3PublicAcl(r) {
    const names = ['PutBucketAcl', 'PutObjectAcl', 'PutBucketPolicy'];
    if (!names.includes(r.eventName)) return null;
    const text = paramsText(r);
    const publicGrant = PUBLIC_GRANTEES.some((g) => text.includes(g));
    const publicPolicy =
      r.eventName === 'PutBucketPolicy' &&
      (text.includes('"Principal":"*"') || text.includes('"AWS":"*"'));
    if (!publicGrant && !publicPolicy) return null;
    return {
      key: 's3_public_acl',
      title: 'Recurso S3 tornado público',
      severity: 8,
      actor: actorOf(r),
      target: r.requestParameters?.bucketName ?? null,
      action: r.eventName,
    };
  },

  // iam_no_mfa — usuário ganhou acesso ao console (login profile) — sem MFA por padrão.
  function iamNoMfa(r) {
    if (r.eventName !== 'CreateLoginProfile' && r.eventName !== 'CreateUser') return null;
    return {
      key: 'iam_no_mfa',
      title: 'Usuário IAM criado/com acesso ao console (verificar MFA)',
      severity: 5,
      actor: actorOf(r),
      target: r.requestParameters?.userName ?? null,
      action: r.eventName,
    };
  },

  // cloudtrail_tamper — mexer na auditoria (desligar/apagar trilha) = cobrir rastros.
  function cloudtrailTamper(r) {
    const sev = { StopLogging: 9, DeleteTrail: 9, UpdateTrail: 7 }[r.eventName];
    if (!sev) return null;
    return {
      key: 'cloudtrail_tamper',
      title: 'Auditoria CloudTrail desligada/alterada',
      severity: sev,
      actor: actorOf(r),
      target: r.requestParameters?.name ?? r.requestParameters?.trailName ?? null,
      action: r.eventName,
    };
  },

  // security_group_open_world — porta sensível aberta à internet (0.0.0.0/0).
  function securityGroupOpenWorld(r) {
    if (r.eventName !== 'AuthorizeSecurityGroupIngress') return null;
    const res = openToWorldIngress(r);
    if (!res) return null;
    const adminHit = res.ports.some((p) => ADMIN_PORTS.has(p));
    // 0.0.0.0/0 em porta NÃO sensível (ex.: 443) não vira evento — menos ruído.
    const severity = res.allPorts ? 9 : adminHit ? 8 : res.ports.length ? 7 : null;
    if (severity === null) return null;
    return {
      key: 'security_group_open_world',
      title: 'Porta exposta à internet (0.0.0.0/0)',
      severity,
      actor: actorOf(r),
      target: r.requestParameters?.groupId ?? null,
      action: r.eventName,
    };
  },

  // kms_key_destruction — desabilitar/agendar exclusão de chave KMS (destruição).
  function kmsKeyDestruction(r) {
    const sev = { ScheduleKeyDeletion: 9, DisableKey: 8 }[r.eventName];
    if (!sev) return null;
    return {
      key: 'kms_key_destruction',
      title: 'Chave KMS desabilitada/agendada p/ exclusão',
      severity: sev,
      actor: actorOf(r),
      target: r.requestParameters?.keyId ?? null,
      action: r.eventName,
    };
  },

  // iam_access_key_created — nova chave de acesso (credencial de longa duração =
  // persistência). Criar chave PRA OUTRO usuário é mais suspeito que pra si mesmo.
  function iamAccessKeyCreated(r) {
    if (r.eventName !== 'CreateAccessKey') return null;
    const actor = actorOf(r);
    const forUser = r.requestParameters?.userName ?? null;
    const forOther = Boolean(forUser && actor && forUser !== actor);
    return {
      key: 'iam_access_key_created',
      title: 'Nova chave de acesso IAM criada',
      severity: forOther ? 7 : 6,
      actor,
      target: forUser ?? actor,
      action: r.eventName,
    };
  },
];

/**
 * Avalia um registro CloudTrail contra todas as regras.
 * @returns {Detection|null} a detecção de maior severidade, ou null se nada casa.
 */
export function detect(record) {
  if (!record || typeof record !== 'object') return null;
  let best = null;
  for (const rule of RULES) {
    let result = null;
    try {
      result = rule(record);
    } catch {
      result = null;
    }
    if (result && (!best || result.severity > best.severity)) {
      best = result;
    }
  }
  return best;
}

/**
 * Monta o corpo aceito pelo endpoint de ingestão a partir do registro + detecção.
 * external_event_id = eventID do CloudTrail → idempotência natural no replay.
 */
export function toIngestPayload(record, detection) {
  return {
    external_event_id: record.eventID ?? `${record.eventName}-${record.eventTime}`,
    event_time: record.eventTime ?? new Date().toISOString(),
    actor: detection.actor,
    target: detection.target,
    action: detection.action,
    severity: detection.severity,
    raw: {
      rule_key: detection.key,
      rule_title: detection.title,
      event_source: record.eventSource ?? null,
      aws_region: record.awsRegion ?? null,
      source_ip: record.sourceIPAddress ?? null,
      account_id: record.recipientAccountId ?? record.userIdentity?.accountId ?? null,
      cloudtrail: record,
    },
  };
}

export const __rulesForTest = RULES;
