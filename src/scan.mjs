/**
 * Argos V2 — Varredura de postura (Tema O, Fase 2).
 *
 * Enumera o estado ATUAL da conta AWS via APIs read-only (SecurityAudit) e monta
 * um inventário normalizado. O connector só COLETA fatos; quem calcula risco/score
 * é o Argos (lib/posture/risk.ts) — assim a inteligência evolui sem redeploy.
 *
 * O AWS SDK v3 já vem no runtime do Lambda (nodejs20). Os imports são DINÂMICOS
 * (dentro de runScan) pra manter os normalizadores puros testáveis localmente sem
 * o SDK instalado. Cada seção é best-effort (try/catch): uma lacuna de permissão
 * não derruba a varredura inteira — inventário parcial ainda vale.
 */

// ── normalizadores PUROS (sem SDK — testáveis) ───────────────────────────────

/** Nome amigável a partir das tags EC2. */
export function tagName(tags) {
  return (tags ?? []).find((t) => t.Key === 'Name')?.Value ?? null;
}

/** Extrai as portas abertas ao mundo (0.0.0.0/0 ou ::/0) de um security group. */
export function sgOpenToWorld(sg) {
  const out = [];
  for (const perm of sg.IpPermissions ?? []) {
    const v4 = (perm.IpRanges ?? []).some((r) => r.CidrIp === '0.0.0.0/0');
    const v6 = (perm.Ipv6Ranges ?? []).some((r) => r.CidrIpv6 === '::/0');
    if (!v4 && !v6) continue;
    const ipv6 = !v4 && v6;
    const protocol = perm.IpProtocol === '-1' ? 'all' : String(perm.IpProtocol ?? 'tcp');
    if (perm.IpProtocol === '-1' || perm.FromPort == null) {
      out.push({ port: 'all', protocol, ipv6 });
      continue;
    }
    const from = Number(perm.FromPort);
    const to = Number(perm.ToPort ?? perm.FromPort);
    if (!Number.isFinite(from)) continue;
    // range largo aberto ao mundo ≈ "todas as portas"; range pequeno vira portas discretas.
    if (to - from > 20) {
      out.push({ port: 'all', protocol, ipv6 });
    } else {
      for (let p = from; p <= to; p++) out.push({ port: p, protocol, ipv6 });
    }
  }
  return out;
}

function ageDays(date) {
  if (!date) return 0;
  return Math.floor((Date.now() - new Date(date).getTime()) / 86_400_000);
}

// ── varredura (usa o SDK, só roda no Lambda) ─────────────────────────────────

/**
 * Roda a varredura read-only e devolve o inventário normalizado (PostureInventory).
 * @param {string} [region]
 */
export async function runScan(region) {
  const inv = {
    account_id: null,
    region: region ?? null,
    instances: [],
    security_groups: [],
    vpcs: [],
    buckets: [],
    iam_users: [],
    root: null,
    kms_keys: [],
    trails: [],
  };

  const [ec2m, s3m, iamm, ctm, kmsm, stsm] = await Promise.all([
    import('@aws-sdk/client-ec2'),
    import('@aws-sdk/client-s3'),
    import('@aws-sdk/client-iam'),
    import('@aws-sdk/client-cloudtrail'),
    import('@aws-sdk/client-kms'),
    import('@aws-sdk/client-sts'),
  ]);

  const ec2 = new ec2m.EC2Client({});
  const s3 = new s3m.S3Client({ region: region ?? 'us-east-1' });
  const iam = new iamm.IAMClient({});
  const ct = new ctm.CloudTrailClient({});
  const kms = new kmsm.KMSClient({});
  const sts = new stsm.STSClient({});

  // identidade da conta
  try {
    const id = await sts.send(new stsm.GetCallerIdentityCommand({}));
    inv.account_id = id.Account ?? null;
  } catch {}

  // EC2: instâncias
  try {
    let token;
    do {
      const r = await ec2.send(new ec2m.DescribeInstancesCommand({ NextToken: token, MaxResults: 200 }));
      for (const res of r.Reservations ?? []) {
        for (const i of res.Instances ?? []) {
          inv.instances.push({
            id: i.InstanceId,
            name: tagName(i.Tags),
            state: i.State?.Name ?? null,
            publicIp: i.PublicIpAddress ?? null,
            privateIp: i.PrivateIpAddress ?? null,
            type: i.InstanceType ?? null,
            az: i.Placement?.AvailabilityZone ?? null,
            vpcId: i.VpcId ?? null,
            securityGroups: (i.SecurityGroups ?? []).map((g) => g.GroupId),
          });
        }
      }
      token = r.NextToken;
    } while (token);
  } catch (e) {
    console.error('[argos] scan EC2 instances:', e?.name);
  }

  // EC2: security groups
  try {
    let token;
    do {
      const r = await ec2.send(new ec2m.DescribeSecurityGroupsCommand({ NextToken: token, MaxResults: 500 }));
      for (const sg of r.SecurityGroups ?? []) {
        inv.security_groups.push({
          id: sg.GroupId,
          name: sg.GroupName ?? null,
          vpcId: sg.VpcId ?? null,
          openToWorld: sgOpenToWorld(sg),
        });
      }
      token = r.NextToken;
    } while (token);
  } catch (e) {
    console.error('[argos] scan security groups:', e?.name);
  }

  // EC2: VPCs
  try {
    const r = await ec2.send(new ec2m.DescribeVpcsCommand({}));
    for (const v of r.Vpcs ?? []) {
      inv.vpcs.push({ id: v.VpcId, cidr: v.CidrBlock ?? null, isDefault: Boolean(v.IsDefault) });
    }
  } catch (e) {
    console.error('[argos] scan VPCs:', e?.name);
  }

  // S3: buckets + público + criptografia (best-effort, limitado)
  try {
    const list = await s3.send(new s3m.ListBucketsCommand({}));
    for (const b of (list.Buckets ?? []).slice(0, 150)) {
      const entry = { name: b.Name, public: false, encrypted: null };
      try {
        const ps = await s3.send(new s3m.GetBucketPolicyStatusCommand({ Bucket: b.Name }));
        if (ps.PolicyStatus?.IsPublic) entry.public = true;
      } catch {}
      try {
        await s3.send(new s3m.GetBucketEncryptionCommand({ Bucket: b.Name }));
        entry.encrypted = true;
      } catch (e) {
        if (e?.name === 'ServerSideEncryptionConfigurationNotFoundError') entry.encrypted = false;
      }
      inv.buckets.push(entry);
    }
  } catch (e) {
    console.error('[argos] scan S3:', e?.name);
  }

  // IAM: root (via account summary) + usuários (MFA, console, access keys)
  try {
    const s = await iam.send(new iamm.GetAccountSummaryCommand({}));
    const m = s.SummaryMap ?? {};
    inv.root = { mfa: m.AccountMFAEnabled === 1, accessKeys: m.AccountAccessKeysPresent ?? 0 };
  } catch (e) {
    console.error('[argos] scan account summary:', e?.name);
  }
  try {
    let marker;
    let count = 0;
    do {
      const r = await iam.send(new iamm.ListUsersCommand({ Marker: marker, MaxItems: 100 }));
      for (const u of r.Users ?? []) {
        if (count++ >= 300) break;
        const user = { name: u.UserName, hasConsole: false, mfa: false, accessKeys: [] };
        try {
          const mfa = await iam.send(new iamm.ListMFADevicesCommand({ UserName: u.UserName }));
          user.mfa = (mfa.MFADevices ?? []).length > 0;
        } catch {}
        try {
          await iam.send(new iamm.GetLoginProfileCommand({ UserName: u.UserName }));
          user.hasConsole = true;
        } catch {}
        try {
          const keys = await iam.send(new iamm.ListAccessKeysCommand({ UserName: u.UserName }));
          for (const k of keys.AccessKeyMetadata ?? []) {
            let lastUsedDays = null;
            try {
              const lu = await iam.send(new iamm.GetAccessKeyLastUsedCommand({ AccessKeyId: k.AccessKeyId }));
              const d = lu.AccessKeyLastUsed?.LastUsedDate;
              lastUsedDays = d ? ageDays(d) : null;
            } catch {}
            user.accessKeys.push({
              id: k.AccessKeyId,
              active: k.Status === 'Active',
              ageDays: ageDays(k.CreateDate),
              lastUsedDays,
            });
          }
        } catch {}
        inv.iam_users.push(user);
      }
      marker = r.IsTruncated ? r.Marker : undefined;
    } while (marker);
  } catch (e) {
    console.error('[argos] scan IAM users:', e?.name);
  }

  // CloudTrail: trilhas + status
  try {
    const r = await ct.send(new ctm.DescribeTrailsCommand({}));
    for (const t of r.trailList ?? []) {
      let isLogging = false;
      try {
        const st = await ct.send(new ctm.GetTrailStatusCommand({ Name: t.TrailARN ?? t.Name }));
        isLogging = Boolean(st.IsLogging);
      } catch {}
      inv.trails.push({
        name: t.Name,
        isLogging,
        multiRegion: Boolean(t.IsMultiRegionTrail),
      });
    }
  } catch (e) {
    console.error('[argos] scan CloudTrail:', e?.name);
  }

  // KMS: chaves gerenciadas pelo cliente + estado (limitado)
  try {
    const r = await kms.send(new kmsm.ListKeysCommand({ Limit: 150 }));
    for (const k of r.Keys ?? []) {
      try {
        const d = await kms.send(new kmsm.DescribeKeyCommand({ KeyId: k.KeyId }));
        if (d.KeyMetadata?.KeyManager === 'AWS') continue; // ignora chaves gerenciadas pela AWS
        inv.kms_keys.push({ id: k.KeyId, state: d.KeyMetadata?.KeyState ?? 'unknown' });
      } catch {}
    }
  } catch (e) {
    console.error('[argos] scan KMS:', e?.name);
  }

  return inv;
}
