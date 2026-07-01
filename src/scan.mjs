/**
 * Argos V2 — Varredura de postura (Tema O, Fase 2) — MULTI-REGIÃO.
 *
 * Enumera o estado ATUAL da conta AWS via APIs read-only (SecurityAudit) e monta
 * um inventário normalizado. Recursos de rede/compute/kms/trilha são POR REGIÃO
 * (datacenter) — então varremos TODAS as regiões habilitadas e marcamos `region`
 * em cada recurso. IAM e S3 (list) são globais. O connector só COLETA; quem calcula
 * risco/score é o Argos (lib/posture/risk.ts).
 *
 * AWS SDK v3 vem no runtime (nodejs20); imports DINÂMICOS (normalizadores puros
 * testáveis sem SDK). Cada seção é best-effort — região sem opt-in/permite lança e
 * é ignorada, o resto do inventário continua.
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

// Fallback de regiões se DescribeRegions falhar.
const FALLBACK_REGIONS = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
  'sa-east-1',
  'eu-west-1',
  'eu-central-1',
  'ca-central-1',
];

// ── varredura (usa o SDK, só roda no Lambda) ─────────────────────────────────

export async function runScan(defaultRegion) {
  const inv = {
    account_id: null,
    account_alias: null,
    region: defaultRegion ?? null,
    instances: [],
    security_groups: [],
    vpcs: [],
    buckets: [],
    databases: [],
    lightsail: [],
    snapshots: [],
    unattached_volumes: [],
    unused_eips: [],
    iam_users: [],
    root: null,
    kms_keys: [],
    trails: [],
    regions_scanned: [],
  };

  const [ec2m, s3m, iamm, ctm, kmsm, stsm, rdsm, lsm] = await Promise.all([
    import('@aws-sdk/client-ec2'),
    import('@aws-sdk/client-s3'),
    import('@aws-sdk/client-iam'),
    import('@aws-sdk/client-cloudtrail'),
    import('@aws-sdk/client-kms'),
    import('@aws-sdk/client-sts'),
    import('@aws-sdk/client-rds'),
    import('@aws-sdk/client-lightsail'),
  ]);

  const base = defaultRegion ?? 'us-east-1';
  const iam = new iamm.IAMClient({});
  const s3 = new s3m.S3Client({ region: base });
  const sts = new stsm.STSClient({});

  // ── conta (id + alias/nome) ────────────────────────────────────────────────
  try {
    const id = await sts.send(new stsm.GetCallerIdentityCommand({}));
    inv.account_id = id.Account ?? null;
  } catch {}
  try {
    const al = await iam.send(new iamm.ListAccountAliasesCommand({}));
    inv.account_alias = (al.AccountAliases ?? [])[0] ?? null;
  } catch {}

  // ── IAM global: root + usuários ────────────────────────────────────────────
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
              const lu = await iam.send(
                new iamm.GetAccessKeyLastUsedCommand({ AccessKeyId: k.AccessKeyId }),
              );
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

  // ── S3 global: buckets + público + criptografia ────────────────────────────
  try {
    const list = await s3.send(new s3m.ListBucketsCommand({}));
    for (const b of (list.Buckets ?? []).slice(0, 200)) {
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

  // ── descobre as regiões habilitadas ────────────────────────────────────────
  let regions = [];
  try {
    const ec2base = new ec2m.EC2Client({ region: base });
    const rr = await ec2base.send(new ec2m.DescribeRegionsCommand({}));
    regions = (rr.Regions ?? []).map((x) => x.RegionName).filter(Boolean);
  } catch (e) {
    console.error('[argos] describeRegions:', e?.name);
  }
  if (regions.length === 0) regions = FALLBACK_REGIONS;
  inv.regions_scanned = regions;

  const seenTrails = new Set();

  // ── varre CADA região (EC2/KMS/CloudTrail) em paralelo, best-effort ─────────
  await Promise.all(
    regions.map(async (region) => {
      // EC2: instâncias, security groups, VPCs
      try {
        const ec2 = new ec2m.EC2Client({ region });

        // discos (EBS) → soma por instância + coleta os SOLTOS (desperdício)
        const diskByInstance = new Map();
        try {
          let vt;
          do {
            const vr = await ec2.send(
              new ec2m.DescribeVolumesCommand({ NextToken: vt, MaxResults: 500 }),
            );
            for (const v of vr.Volumes ?? []) {
              const atts = v.Attachments ?? [];
              if (atts.length === 0) {
                inv.unattached_volumes.push({
                  id: v.VolumeId,
                  sizeGB: v.Size ?? null,
                  ageDays: ageDays(v.CreateTime),
                  region,
                });
                continue;
              }
              for (const a of atts) {
                if (!a.InstanceId) continue;
                diskByInstance.set(
                  a.InstanceId,
                  (diskByInstance.get(a.InstanceId) ?? 0) + (v.Size ?? 0),
                );
              }
            }
            vt = vr.NextToken;
          } while (vt);
        } catch {}

        // Elastic IPs não associados (cobram parados)
        try {
          const ad = await ec2.send(new ec2m.DescribeAddressesCommand({}));
          for (const a of ad.Addresses ?? []) {
            if (!a.AssociationId && !a.InstanceId) {
              inv.unused_eips.push({ ip: a.PublicIp, region });
            }
          }
        } catch {}

        // Snapshots EBS próprios (backup/custo) + quais são PÚBLICOS (vazamento)
        try {
          const publicIds = new Set();
          try {
            const pub = await ec2.send(
              new ec2m.DescribeSnapshotsCommand({
                OwnerIds: ['self'],
                RestorableByUserIds: ['all'],
                MaxResults: 1000,
              }),
            );
            for (const s of pub.Snapshots ?? []) publicIds.add(s.SnapshotId);
          } catch {}
          let st;
          let n = 0;
          do {
            const sr = await ec2.send(
              new ec2m.DescribeSnapshotsCommand({
                OwnerIds: ['self'],
                NextToken: st,
                MaxResults: 1000,
              }),
            );
            for (const s of sr.Snapshots ?? []) {
              if (n++ >= 1000) break;
              inv.snapshots.push({
                id: s.SnapshotId,
                kind: 'ebs',
                name: s.Description ?? null,
                sizeGB: s.VolumeSize ?? null,
                ageDays: ageDays(s.StartTime),
                public: publicIds.has(s.SnapshotId),
                region,
              });
            }
            st = sr.NextToken;
          } while (st && n < 1000);
        } catch {}

        // AMIs próprias (imagens) — Public é flag direta
        try {
          const im = await ec2.send(new ec2m.DescribeImagesCommand({ Owners: ['self'] }));
          for (const img of im.Images ?? []) {
            const sizeGB = (img.BlockDeviceMappings ?? []).reduce(
              (s, b) => s + (b.Ebs?.VolumeSize ?? 0),
              0,
            );
            inv.snapshots.push({
              id: img.ImageId,
              kind: 'ami',
              name: img.Name ?? null,
              sizeGB: sizeGB || null,
              ageDays: ageDays(img.CreationDate),
              public: Boolean(img.Public),
              region,
            });
          }
        } catch {}

        let token;
        do {
          const r = await ec2.send(
            new ec2m.DescribeInstancesCommand({ NextToken: token, MaxResults: 200 }),
          );
          for (const res of r.Reservations ?? []) {
            for (const i of res.Instances ?? []) {
              inv.instances.push({
                id: i.InstanceId,
                name: tagName(i.Tags),
                region,
                state: i.State?.Name ?? null,
                publicIp: i.PublicIpAddress ?? null,
                privateIp: i.PrivateIpAddress ?? null,
                type: i.InstanceType ?? null,
                az: i.Placement?.AvailabilityZone ?? null,
                os: i.PlatformDetails ?? (i.Platform === 'windows' ? 'Windows' : 'Linux'),
                diskGB: diskByInstance.get(i.InstanceId) ?? null,
                vpcId: i.VpcId ?? null,
                securityGroups: (i.SecurityGroups ?? []).map((g) => g.GroupId),
              });
            }
          }
          token = r.NextToken;
        } while (token);

        let t2;
        do {
          const r = await ec2.send(
            new ec2m.DescribeSecurityGroupsCommand({ NextToken: t2, MaxResults: 500 }),
          );
          for (const sg of r.SecurityGroups ?? []) {
            inv.security_groups.push({
              id: sg.GroupId,
              name: sg.GroupName ?? null,
              region,
              vpcId: sg.VpcId ?? null,
              openToWorld: sgOpenToWorld(sg),
            });
          }
          t2 = r.NextToken;
        } while (t2);

        const rv = await ec2.send(new ec2m.DescribeVpcsCommand({}));
        for (const v of rv.Vpcs ?? []) {
          inv.vpcs.push({
            id: v.VpcId,
            region,
            cidr: v.CidrBlock ?? null,
            isDefault: Boolean(v.IsDefault),
          });
        }
      } catch {
        // região sem opt-in / sem permissão — ignora
      }

      // KMS por região
      try {
        const kms = new kmsm.KMSClient({ region });
        const r = await kms.send(new kmsm.ListKeysCommand({ Limit: 200 }));
        for (const k of r.Keys ?? []) {
          try {
            const d = await kms.send(new kmsm.DescribeKeyCommand({ KeyId: k.KeyId }));
            if (d.KeyMetadata?.KeyManager === 'AWS') continue;
            inv.kms_keys.push({ id: k.KeyId, region, state: d.KeyMetadata?.KeyState ?? 'unknown' });
          } catch {}
        }
      } catch {}

      // CloudTrail por região (dedupe multi-region por ARN)
      try {
        const ct = new ctm.CloudTrailClient({ region });
        const r = await ct.send(new ctm.DescribeTrailsCommand({}));
        for (const t of r.trailList ?? []) {
          const arn = t.TrailARN ?? t.Name;
          if (seenTrails.has(arn)) continue;
          seenTrails.add(arn);
          let isLogging = false;
          try {
            const st = await ct.send(new ctm.GetTrailStatusCommand({ Name: arn }));
            isLogging = Boolean(st.IsLogging);
          } catch {}
          inv.trails.push({
            name: t.Name,
            region: t.HomeRegion ?? region,
            isLogging,
            multiRegion: Boolean(t.IsMultiRegionTrail),
          });
        }
      } catch {}

      // RDS: bancos de dados por região (público? criptografado?)
      try {
        const rds = new rdsm.RDSClient({ region });
        let marker;
        do {
          const r = await rds.send(
            new rdsm.DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 }),
          );
          for (const db of r.DBInstances ?? []) {
            inv.databases.push({
              id: db.DBInstanceIdentifier,
              engine: db.Engine ?? null,
              version: db.EngineVersion ?? null,
              class: db.DBInstanceClass ?? null,
              storageGB: db.AllocatedStorage ?? null,
              publicAccess: Boolean(db.PubliclyAccessible),
              encrypted: db.StorageEncrypted ?? null,
              multiAz: Boolean(db.MultiAZ),
              endpoint: db.Endpoint?.Address ?? null,
              region,
              az: db.AvailabilityZone ?? null,
              status: db.DBInstanceStatus ?? null,
            });
          }
          marker = r.Marker;
        } while (marker);

        // snapshots de RDS (backup/custo)
        let sm;
        let sn = 0;
        do {
          const sr = await rds.send(
            new rdsm.DescribeDBSnapshotsCommand({ Marker: sm, MaxRecords: 100 }),
          );
          for (const s of sr.DBSnapshots ?? []) {
            if (sn++ >= 500) break;
            inv.snapshots.push({
              id: s.DBSnapshotIdentifier,
              kind: 'rds',
              name: s.Engine ?? null,
              sizeGB: s.AllocatedStorage ?? null,
              ageDays: ageDays(s.SnapshotCreateTime),
              public: false, // público de snapshot RDS via attributes = fase posterior
              region,
            });
          }
          sm = sr.Marker;
        } while (sm && sn < 500);
      } catch {}

      // Lightsail: instâncias (VPS) por região — portas abertas ao mundo
      try {
        const ls = new lsm.LightsailClient({ region });
        let pageToken;
        do {
          const r = await ls.send(new lsm.GetInstancesCommand({ pageToken }));
          for (const li of r.instances ?? []) {
            const ports = [];
            for (const p of li.networking?.ports ?? []) {
              const world =
                (p.cidrs ?? []).includes('0.0.0.0/0') || (p.ipv6Cidrs ?? []).includes('::/0');
              if (!world) continue;
              const from = Number(p.fromPort);
              const to = Number(p.toPort ?? p.fromPort);
              if (!Number.isFinite(from) || to - from > 20) {
                ports.push('all');
              } else {
                for (let x = from; x <= to; x++) ports.push(x);
              }
            }
            const openPorts = ports.includes('all') ? ['all'] : [...new Set(ports)];
            inv.lightsail.push({
              name: li.name,
              region,
              az: li.location?.availabilityZone ?? null,
              state: li.state?.name ?? null,
              publicIp: li.publicIpAddress ?? null,
              privateIp: li.privateIpAddress ?? null,
              os: li.blueprintName ?? null,
              bundle: li.bundleId ?? null,
              vcpu: li.hardware?.cpuCount ?? null,
              ramGB: li.hardware?.ramSizeInGb ?? null,
              diskGB: (li.hardware?.disks ?? []).reduce((s, d) => s + (d.sizeInGb ?? 0), 0) || null,
              openPorts,
            });
          }
          pageToken = r.nextPageToken;
        } while (pageToken);
      } catch {}
    }),
  );

  return inv;
}
