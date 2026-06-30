# Argos V2 — Connector AWS CloudTrail

Lambda que captura eventos de segurança de uma conta AWS via **EventBridge**,
filtra no edge (só o que casa uma regra trafega — disciplina anti-custo) e envia
o evento **assinado com HMAC-SHA256** ao endpoint de ingestão do Argos.

```
CloudTrail → EventBridge → Lambda (este connector) → POST /api/ingest/security-event → security_events
```

## Regras detectadas (Fase 2)

| Regra | Gatilho | Severidade |
|---|---|---|
| `root_login` | `ConsoleLogin` com `userIdentity.type = Root` | 9 |
| `console_login_no_mfa` | `ConsoleLogin` de IAM user com `MFAUsed = No` | 7 |
| `iam_attach_admin_policy` | `Attach*Policy` com `AdministratorAccess`/`IAMFullAccess` | 8 |
| `s3_public_acl` | `PutBucketAcl`/`PutObjectAcl`/`PutBucketPolicy` com grant público | 8 |
| `iam_no_mfa` | `CreateUser` / `CreateLoginProfile` | 5 |

A lógica vive em [`src/detection.mjs`](src/detection.mjs) e é coberta por testes
(`node --test`). Eventos que não casam nenhuma regra são **descartados no edge**.

## Heartbeat (prova de vida)

Como os eventos de segurança são raros, "silêncio" é o estado normal — mas aí o
painel não sabe distinguir **vivo e quieto** de **offline**. Por isso o connector
**pinga o Argos a cada 15 min** (regra agendada `rate(15 minutes)` → o mesmo
Lambda detecta o disparo agendado e faz `POST /api/ingest/heartbeat`, assinado com
HMAC). O painel mostra "último sinal há N min" e marca a fonte como **parcial** se
perder uma batida e **offline** se silenciar de vez. Sem custo relevante (1 invoke
curtinho a cada 15 min). Connectors antigos (sem esta regra) continuam funcionando
— só não exibem o sinal de vida até o **redeploy**.

## Estrutura

```
src/
  index.mjs        # handler Lambda: HMAC + POST idempotente
  detection.mjs    # 5 regras + mapeamento CloudTrail → payload
test/
  detection.test.mjs
template.yaml      # SAM: Lambda + 2 EventBridge rules + heartbeat agendado
deploy.sh          # deploy 1-comando via CloudShell
scripts/package.mjs# zip pra upload manual no console (alternativa)
```

## Deploy (recomendado: AWS CloudShell)

> Use **us-east-1** — eventos de console sign-in são globais e emitidos lá.
> A conta precisa ter um **CloudTrail trail** ativo (multi-region) para os
> eventos de API fluírem ao EventBridge.

1. No painel Argos (`/admin/sources`) crie a fonte do tipo **AWS CloudTrail** e
   copie o **UUID da fonte** e o **secret HMAC** (exibido uma única vez).
2. Abra o **AWS CloudShell** (ícone `>_` no console, região us-east-1).
3. Traga este connector e rode o deploy:

```bash
git clone https://github.com/MoreAppsDev/argos-v2.git
cd argos-v2/connectors/aws-cloudtrail

export ARGOS_SOURCE_CONNECTION_ID="<uuid da fonte>"
export ARGOS_HMAC_SECRET="<secret HMAC>"
./deploy.sh
```

O `deploy.sh` empacota e publica via SAM (já instalado no CloudShell). Em ~1
minuto a stack `argos-cloudtrail-connector` está no ar.

## Teste rápido (smoke test)

Gere um evento que casa uma regra — ex.: faça **login no console com um usuário
IAM sem MFA**, ou rode:

```bash
aws iam create-user --user-name argos-smoke-test
aws iam create-login-profile --user-name argos-smoke-test --password 'Teste123!Argos'
```

Em segundos o evento aparece no dashboard do Argos. Limpe depois:

```bash
aws iam delete-login-profile --user-name argos-smoke-test
aws iam delete-user --user-name argos-smoke-test
```

## Desenvolvimento

```bash
node --test          # roda os testes de detecção (sem AWS)
node scripts/package.mjs   # gera dist/...zip pra upload manual
```

## Observabilidade e custo

- Log mínimo: só erros de ingestão e falhas 5xx (anti-custo de CloudWatch).
- Idempotência: `external_event_id = eventID` do CloudTrail — replays do retry
  do Lambda não duplicam evento (o endpoint devolve 202 idempotente).
- 4xx (assinatura/conexão inválida) **não** é re-tentado; 5xx é re-tentado pelo
  retry assíncrono nativo do Lambda.
