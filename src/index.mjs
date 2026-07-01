/**
 * Argos V2 — AWS CloudTrail connector / Lambda handler.
 *
 * Fluxo: EventBridge entrega um registro CloudTrail → aplica as regras de
 * detecção (edge filter) → se casa, assina o payload com HMAC-SHA256 e faz
 * POST no endpoint de ingestão do Argos. Eventos que não casam são descartados
 * aqui mesmo (não trafegam, não custam).
 *
 * Node 20 (ESM). Sem dependências: usa `node:crypto` e `fetch` nativos.
 *
 * Variáveis de ambiente (injetadas pelo CloudFormation/SAM):
 *   ARGOS_INGEST_URL            ex: https://argos.moreapps.com.br/api/ingest/security-event
 *   ARGOS_SOURCE_CONNECTION_ID  UUID da source_connection criada no painel Argos
 *   ARGOS_HMAC_SECRET           secret HMAC exibido uma vez na criação da fonte
 */

import { createHmac } from 'node:crypto';

import { detect, toIngestPayload } from './detection.mjs';
import { runScan } from './scan.mjs';

const INGEST_URL = process.env.ARGOS_INGEST_URL;
const CONNECTION_ID = process.env.ARGOS_SOURCE_CONNECTION_ID;
const HMAC_SECRET = process.env.ARGOS_HMAC_SECRET;
// Endpoints derivados do host da ingestão (sem exigir novas env vars).
const HEARTBEAT_URL = INGEST_URL ? INGEST_URL.replace(/\/security-event\/?$/, '/heartbeat') : null;
const POSTURE_URL = INGEST_URL ? INGEST_URL.replace(/\/security-event\/?$/, '/posture') : null;

function sign(rawBody) {
  const hex = createHmac('sha256', HMAC_SECRET).update(rawBody, 'utf-8').digest('hex');
  return `sha256=${hex}`;
}

/** EventBridge pode entregar o registro em `detail`, ou o próprio evento já é o registro. */
function extractRecord(event) {
  if (event?.detail && typeof event.detail === 'object') return event.detail;
  return event;
}

/** Disparo agendado da varredura de postura (marcado via Input do EventBridge). */
function isScan(event) {
  return event?.argos === 'scan';
}

/** Disparo agendado (rate(...)) = pedido de heartbeat, não um evento CloudTrail. */
function isHeartbeat(event) {
  return event?.source === 'aws.events' || event?.['detail-type'] === 'Scheduled Event';
}

/** Varre a conta (read-only) e envia o snapshot de postura ao Argos. */
async function sendPostureScan() {
  if (!POSTURE_URL) return { posture: false, reason: 'sem URL' };
  const inventory = await runScan(process.env.AWS_REGION);
  const rawBody = JSON.stringify({ captured_at: new Date().toISOString(), inventory });
  const res = await fetch(POSTURE_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-argos-signature': sign(rawBody),
      'x-argos-source-connection-id': CONNECTION_ID,
    },
    body: rawBody,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    console.error(`[argos] postura falhou (${res.status}): ${body}`);
  }
  return { posture: true, status: res.status };
}

/** Pinga o Argos pra provar que o connector está vivo (liveness). Falha não retenta. */
async function sendHeartbeat() {
  if (!HEARTBEAT_URL) return { heartbeat: false, reason: 'sem URL' };
  const rawBody = JSON.stringify({ sent_at: new Date().toISOString() });
  const res = await fetch(HEARTBEAT_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-argos-signature': sign(rawBody),
      'x-argos-source-connection-id': CONNECTION_ID,
    },
    body: rawBody,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    console.error(`[argos] heartbeat falhou (${res.status}): ${body}`);
  }
  return { heartbeat: true, status: res.status };
}

export async function handler(event) {
  if (!INGEST_URL || !CONNECTION_ID || !HMAC_SECRET) {
    // Config faltando é erro de deploy — falha alto pra aparecer no CloudWatch.
    throw new Error(
      'Connector mal configurado: defina ARGOS_INGEST_URL, ARGOS_SOURCE_CONNECTION_ID e ARGOS_HMAC_SECRET.',
    );
  }

  // Disparo agendado de varredura de postura (marcado) → varre e envia.
  if (isScan(event)) {
    return sendPostureScan();
  }

  // Disparo agendado → heartbeat (não passa pela detecção).
  if (isHeartbeat(event)) {
    return sendHeartbeat();
  }

  const record = extractRecord(event);
  const detection = detect(record);

  // Não casou nenhuma regra → descarta no edge (sem log verboso).
  if (!detection) {
    return { skipped: true };
  }

  const payload = toIngestPayload(record, detection);
  const rawBody = JSON.stringify(payload);

  const res = await fetch(INGEST_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-argos-signature': sign(rawBody),
      'x-argos-source-connection-id': CONNECTION_ID,
    },
    body: rawBody,
  });

  // 2xx = aceito (202) ou idempotente. 4xx = problema permanente (não retentar).
  if (res.ok) {
    return { sent: true, rule: detection.key, status: res.status };
  }

  const body = await res.text().catch(() => '');

  if (res.status >= 400 && res.status < 500) {
    // Assinatura/conexão/payload inválidos — re-tentar não resolve. Loga e encerra.
    console.error(`[argos] ingestão rejeitada (${res.status}) regra=${detection.key}: ${body}`);
    return { rejected: true, status: res.status };
  }

  // 5xx → lança pra o retry assíncrono do Lambda reprocessar (idempotência protege duplicata).
  throw new Error(`[argos] ingestão falhou (${res.status}): ${body}`);
}
