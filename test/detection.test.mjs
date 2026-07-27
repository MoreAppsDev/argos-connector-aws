/**
 * Testa o núcleo de detecção com fixtures CloudTrail reais (sem AWS).
 * Rode com: node --test
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { detect, toIngestPayload } from '../src/detection.mjs';

const rootLogin = {
  eventID: 'a1-root',
  eventTime: '2026-06-15T12:00:00Z',
  eventName: 'ConsoleLogin',
  eventSource: 'signin.amazonaws.com',
  awsRegion: 'us-east-1',
  sourceIPAddress: '203.0.113.10',
  recipientAccountId: '123456789012',
  userIdentity: { type: 'Root', accountId: '123456789012' },
  responseElements: { ConsoleLogin: 'Success' },
  additionalEventData: { MFAUsed: 'No' },
};

const loginNoMfa = {
  eventID: 'b2-nomfa',
  eventTime: '2026-06-15T12:05:00Z',
  eventName: 'ConsoleLogin',
  recipientAccountId: '123456789012',
  userIdentity: { type: 'IAMUser', userName: 'joao' },
  responseElements: { ConsoleLogin: 'Success' },
  additionalEventData: { MFAUsed: 'No' },
};

const attachAdmin = {
  eventID: 'c3-admin',
  eventTime: '2026-06-15T12:10:00Z',
  eventName: 'AttachUserPolicy',
  userIdentity: { type: 'IAMUser', userName: 'maria' },
  requestParameters: {
    userName: 'novo-dev',
    policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
  },
};

const s3Public = {
  eventID: 'd4-s3',
  eventTime: '2026-06-15T12:15:00Z',
  eventName: 'PutBucketAcl',
  userIdentity: { type: 'IAMUser', userName: 'deploy-bot' },
  requestParameters: {
    bucketName: 'backups-prod',
    AccessControlPolicy: {
      AccessControlList: {
        Grant: [{ Grantee: { URI: 'http://acs.amazonaws.com/groups/global/AllUsers' } }],
      },
    },
  },
};

const benign = {
  eventID: 'e5-benign',
  eventTime: '2026-06-15T12:20:00Z',
  eventName: 'DescribeInstances',
  userIdentity: { type: 'IAMUser', userName: 'monitor' },
};

const loginWithMfa = {
  eventID: 'f6-mfa',
  eventTime: '2026-06-15T12:25:00Z',
  eventName: 'ConsoleLogin',
  userIdentity: { type: 'IAMUser', userName: 'segura' },
  responseElements: { ConsoleLogin: 'Success' },
  additionalEventData: { MFAUsed: 'Yes' },
};

test('root login → severidade 9', () => {
  const d = detect(rootLogin);
  assert.equal(d?.key, 'root_login');
  assert.equal(d.severity, 9);
  assert.equal(d.actor, 'root');
});

test('login sem MFA → console_login_no_mfa', () => {
  const d = detect(loginNoMfa);
  assert.equal(d?.key, 'console_login_no_mfa');
  assert.equal(d.actor, 'joao');
});

test('login COM MFA → ignorado', () => {
  assert.equal(detect(loginWithMfa), null);
});

test('attach AdministratorAccess → iam_attach_admin_policy sev 8', () => {
  const d = detect(attachAdmin);
  assert.equal(d?.key, 'iam_attach_admin_policy');
  assert.equal(d.severity, 8);
  assert.equal(d.target, 'novo-dev');
});

test('bucket público → s3_public_acl', () => {
  const d = detect(s3Public);
  assert.equal(d?.key, 's3_public_acl');
  assert.equal(d.target, 'backups-prod');
});

test('evento benigno → descartado (null)', () => {
  assert.equal(detect(benign), null);
});

const stopLogging = {
  eventID: 'g7-stoplog',
  eventTime: '2026-06-30T10:00:00Z',
  eventName: 'StopLogging',
  eventSource: 'cloudtrail.amazonaws.com',
  userIdentity: { type: 'IAMUser', userName: 'intruso' },
  requestParameters: { name: 'org-trail' },
};

const sgOpenSsh = {
  eventID: 'h8-sg',
  eventTime: '2026-06-30T10:05:00Z',
  eventName: 'AuthorizeSecurityGroupIngress',
  eventSource: 'ec2.amazonaws.com',
  userIdentity: { type: 'IAMUser', userName: 'devops' },
  requestParameters: {
    groupId: 'sg-0abc123',
    ipPermissions: {
      items: [
        { ipProtocol: 'tcp', fromPort: 22, toPort: 22, ipRanges: { items: [{ cidrIp: '0.0.0.0/0' }] } },
      ],
    },
  },
};

const sgOpenHttps = {
  eventID: 'h9-sg-ok',
  eventTime: '2026-06-30T10:06:00Z',
  eventName: 'AuthorizeSecurityGroupIngress',
  eventSource: 'ec2.amazonaws.com',
  userIdentity: { type: 'IAMUser', userName: 'devops' },
  requestParameters: {
    groupId: 'sg-web',
    ipPermissions: {
      items: [
        { ipProtocol: 'tcp', fromPort: 443, toPort: 443, ipRanges: { items: [{ cidrIp: '0.0.0.0/0' }] } },
      ],
    },
  },
};

const sgSshFromOffice = {
  eventID: 'h10-sg-office',
  eventTime: '2026-06-30T10:07:00Z',
  eventName: 'AuthorizeSecurityGroupIngress',
  eventSource: 'ec2.amazonaws.com',
  userIdentity: { type: 'IAMUser', userName: 'devops' },
  requestParameters: {
    groupId: 'sg-0abc123',
    ipPermissions: {
      items: [
        { ipProtocol: 'tcp', fromPort: 22, toPort: 22, ipRanges: { items: [{ cidrIp: '203.0.113.5/32' }] } },
      ],
    },
  },
};

const kmsDelete = {
  eventID: 'i11-kms',
  eventTime: '2026-06-30T10:10:00Z',
  eventName: 'ScheduleKeyDeletion',
  eventSource: 'kms.amazonaws.com',
  userIdentity: { type: 'IAMUser', userName: 'intruso' },
  requestParameters: { keyId: 'key-abc' },
};

const accessKeyForOther = {
  eventID: 'j12-key',
  eventTime: '2026-06-30T10:12:00Z',
  eventName: 'CreateAccessKey',
  eventSource: 'iam.amazonaws.com',
  userIdentity: { type: 'IAMUser', userName: 'intruso' },
  requestParameters: { userName: 'ceo' },
};

test('StopLogging → cloudtrail_tamper sev 9', () => {
  const d = detect(stopLogging);
  assert.equal(d?.key, 'cloudtrail_tamper');
  assert.equal(d.severity, 9);
  assert.equal(d.target, 'org-trail');
});

test('SSH aberto ao mundo → security_group_open_world sev 8', () => {
  const d = detect(sgOpenSsh);
  assert.equal(d?.key, 'security_group_open_world');
  assert.equal(d.severity, 8);
  assert.equal(d.target, 'sg-0abc123');
});

test('443 aberto ao mundo → ignorado (porta pública normal)', () => {
  assert.equal(detect(sgOpenHttps), null);
});

test('SSH liberado só pra um IP → ignorado (não é 0.0.0.0/0)', () => {
  assert.equal(detect(sgSshFromOffice), null);
});

test('ScheduleKeyDeletion → kms_key_destruction sev 9', () => {
  const d = detect(kmsDelete);
  assert.equal(d?.key, 'kms_key_destruction');
  assert.equal(d.severity, 9);
});

test('CreateAccessKey pra outro usuário → iam_access_key_created sev 7', () => {
  const d = detect(accessKeyForOther);
  assert.equal(d?.key, 'iam_access_key_created');
  assert.equal(d.severity, 7);
  assert.equal(d.target, 'ceo');
});

test('payload de ingestão mapeia eventID e raw', () => {
  const d = detect(rootLogin);
  const p = toIngestPayload(rootLogin, d);
  assert.equal(p.external_event_id, 'a1-root');
  assert.equal(p.event_time, '2026-06-15T12:00:00Z');
  assert.equal(p.severity, 9);
  assert.equal(p.raw.rule_key, 'root_login');
  assert.equal(p.raw.source_ip, '203.0.113.10');
  assert.equal(p.raw.cloudtrail.eventName, 'ConsoleLogin');
});

// ── Lote 3 (2026-07): evasão de defesa, exfil de snapshot, federação, destruição ──

test('DeleteDetector (GuardDuty) → aws_security_tool_disabled sev 9', () => {
  const d = detect({
    eventID: 'gd1',
    eventName: 'DeleteDetector',
    eventSource: 'guardduty.amazonaws.com',
    userIdentity: { type: 'IAMUser', userName: 'intruso' },
    requestParameters: { detectorId: 'det-123' },
  });
  assert.equal(d?.key, 'aws_security_tool_disabled');
  assert.equal(d.severity, 9);
});

test('UpdateDetector enable=false → aws_security_tool_disabled', () => {
  const d = detect({
    eventID: 'gd2',
    eventName: 'UpdateDetector',
    eventSource: 'guardduty.amazonaws.com',
    userIdentity: { type: 'IAMUser', userName: 'intruso' },
    requestParameters: { detectorId: 'det-123', enable: false },
  });
  assert.equal(d?.key, 'aws_security_tool_disabled');
});

test('UpdateDetector enable=true → ignorado (religar não é ameaça)', () => {
  assert.equal(
    detect({
      eventID: 'gd3',
      eventName: 'UpdateDetector',
      eventSource: 'guardduty.amazonaws.com',
      userIdentity: { type: 'IAMUser', userName: 'admin' },
      requestParameters: { detectorId: 'det-123', enable: true },
    }),
    null,
  );
});

test('ModifySnapshotAttribute pra conta externa → aws_snapshot_shared_external sev 8', () => {
  const d = detect({
    eventID: 'sn1',
    eventName: 'ModifySnapshotAttribute',
    eventSource: 'ec2.amazonaws.com',
    recipientAccountId: '123456789012',
    userIdentity: { type: 'IAMUser', userName: 'intruso', accountId: '123456789012' },
    requestParameters: {
      snapshotId: 'snap-abc',
      createVolumePermission: { add: { items: [{ userId: '999888777666' }] } },
    },
  });
  assert.equal(d?.key, 'aws_snapshot_shared_external');
  assert.equal(d.severity, 8);
  assert.equal(d.target, 'snap-abc');
});

test('ModifyImageAttribute tornando AMI pública → sev 9', () => {
  const d = detect({
    eventID: 'sn2',
    eventName: 'ModifyImageAttribute',
    eventSource: 'ec2.amazonaws.com',
    recipientAccountId: '123456789012',
    userIdentity: { type: 'IAMUser', accountId: '123456789012' },
    requestParameters: { imageId: 'ami-xyz', launchPermission: { add: { items: [{ group: 'all' }] } } },
  });
  assert.equal(d?.key, 'aws_snapshot_shared_external');
  assert.equal(d.severity, 9);
});

test('ModifySnapshotAttribute pra própria conta → ignorado', () => {
  assert.equal(
    detect({
      eventID: 'sn3',
      eventName: 'ModifySnapshotAttribute',
      eventSource: 'ec2.amazonaws.com',
      recipientAccountId: '123456789012',
      userIdentity: { type: 'IAMUser', accountId: '123456789012' },
      requestParameters: {
        snapshotId: 'snap-self',
        createVolumePermission: { add: { items: [{ userId: '123456789012' }] } },
      },
    }),
    null,
  );
});

test('CreateSAMLProvider → aws_saml_provider_change sev 9', () => {
  const d = detect({
    eventID: 'saml1',
    eventName: 'CreateSAMLProvider',
    eventSource: 'iam.amazonaws.com',
    userIdentity: { type: 'IAMUser', userName: 'intruso' },
    requestParameters: { name: 'evil-idp' },
  });
  assert.equal(d?.key, 'aws_saml_provider_change');
  assert.equal(d.severity, 9);
  assert.equal(d.target, 'evil-idp');
});

test('DeleteDBInstance sem snapshot final → aws_data_destruction sev 9', () => {
  const d = detect({
    eventID: 'dd1',
    eventName: 'DeleteDBInstance',
    eventSource: 'rds.amazonaws.com',
    userIdentity: { type: 'IAMUser', userName: 'intruso' },
    requestParameters: { dBInstanceIdentifier: 'prod-db', skipFinalSnapshot: true },
  });
  assert.equal(d?.key, 'aws_data_destruction');
  assert.equal(d.severity, 9);
  assert.equal(d.target, 'prod-db');
});

test('TerminateInstances de 6 instâncias → aws_data_destruction; 1 só → ignorado', () => {
  const many = detect({
    eventID: 'dd2',
    eventName: 'TerminateInstances',
    eventSource: 'ec2.amazonaws.com',
    userIdentity: { type: 'IAMUser', userName: 'intruso' },
    requestParameters: {
      instancesSet: { items: Array.from({ length: 6 }, (_, i) => ({ instanceId: `i-${i}` })) },
    },
  });
  assert.equal(many?.key, 'aws_data_destruction');
  const one = detect({
    eventID: 'dd3',
    eventName: 'TerminateInstances',
    eventSource: 'ec2.amazonaws.com',
    userIdentity: { type: 'IAMUser', userName: 'devops' },
    requestParameters: { instancesSet: { items: [{ instanceId: 'i-solo' }] } },
  });
  assert.equal(one, null);
});
