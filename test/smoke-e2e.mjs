/**
 * Smoke test E2E (sem AWS): fixture CloudTrail → detecção real → HMAC → POST
 * no endpoint de produção. Prova o pipeline inteiro do connector ao banco.
 *
 * Uso:
 *   ARGOS_INGEST_URL=... ARGOS_SOURCE_CONNECTION_ID=... ARGOS_HMAC_SECRET=... \
 *   node test/smoke-e2e.mjs
 */
import { createHmac } from 'node:crypto';

import { detect, toIngestPayload } from '../src/detection.mjs';

const URL = process.env.ARGOS_INGEST_URL;
const CONN = process.env.ARGOS_SOURCE_CONNECTION_ID;
const SECRET = process.env.ARGOS_HMAC_SECRET;

// Fixture: login root sem MFA (regra root_login, severidade 9).
const record = {
  eventID: `smoke-${process.env.SMOKE_ID ?? 'x'}`,
  eventTime: new Date(Date.now() - 60000).toISOString(),
  eventName: 'ConsoleLogin',
  eventSource: 'signin.amazonaws.com',
  awsRegion: 'us-east-1',
  sourceIPAddress: '203.0.113.77',
  recipientAccountId: '000000000000',
  userIdentity: { type: 'Root', accountId: '000000000000' },
  responseElements: { ConsoleLogin: 'Success' },
  additionalEventData: { MFAUsed: 'No' },
};

const detection = detect(record);
console.log('detecção:', detection?.key, 'sev', detection?.severity);

const payload = toIngestPayload(record, detection);
const body = JSON.stringify(payload);
const sig = `sha256=${createHmac('sha256', SECRET).update(body, 'utf-8').digest('hex')}`;

const res = await fetch(URL, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-argos-signature': sig,
    'x-argos-source-connection-id': CONN,
  },
  body,
});

console.log('HTTP', res.status);
console.log('resposta:', await res.text());
