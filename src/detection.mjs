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

/**
 * As 5 regras iniciais da Fase 2. Cada uma recebe o registro CloudTrail e
 * devolve uma Detection (match) ou null.
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
