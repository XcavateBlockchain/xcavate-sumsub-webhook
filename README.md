# xcavate-sumsub-webhook

Webhook service that bridges Sumsub KYC results with the Xcavate blockchain.

When a Sumsub applicant is **reviewed and approved** (`reviewAnswer = GREEN`), the
webhook automatically:

1. **Assigns a blockchain role** via the `XcavateWhitelist` pallet based on the KYC level
2. **Transfers 10 native tokens** (12 decimals) to the user's address
3. **Transfers 10,000 tGBP tokens** (assetId=10, 6 decimals) — testnet only

When an applicant is **reviewed and rejected** (`reviewAnswer = RED`), the previously
assigned role is removed. All other Sumsub events are acknowledged and ignored.

---

## Quick Start

```bash
# Copy and edit environment variables
cp .env.example .env

# Install dependencies
npm install

# Build and run in Docker
docker compose up --build

# Health check
curl http://localhost:8005/health
```

The service listens on `POST /webhook/sumsub`. To receive real webhooks from
Sumsub it must be reachable over **HTTPS** at a public URL (Sumsub rejects plain
HTTP). Put it behind a reverse proxy / load balancer that terminates TLS, e.g.
`https://kyc.example.com/webhook/sumsub`.

---

## Connecting to Sumsub

This is the part you have to get right for the integration to work end-to-end.
Follow the steps in order.

### Prerequisites

- A Sumsub account with access to the **Dashboard** (Production and/or Sandbox).
- This service deployed and reachable at a public **HTTPS** URL.
- The faucet account mnemonic configured (`FAUCET_MNEMONIC`) with the **Admin**
  role on the `XcavateWhitelist` pallet, and a funded balance.

### Step 1 — Decide how the user's wallet address reaches the webhook

Sumsub has **no built-in "wallet address" field**. The service needs to know
which on-chain account to whitelist and fund, so you must supply it yourself.
The recommended way is to put the wallet address in Sumsub's **`externalUserId`**,
which is echoed back in every webhook.

You set `externalUserId` when you start a verification. With the WebSDK you do
this on your backend when generating the applicant access token:

```bash
# userId becomes the applicant's externalUserId
POST https://api.sumsub.com/resources/accessTokens
     ?userId=<USER_WALLET_ADDRESS>
     &levelName=basic-level
     &ttlInSecs=600
```

(or pass `externalUserId` when creating the applicant via
`POST /resources/applicants?levelName=...`).

The service resolves the destination account in this priority order:

1. A custom `fields[]` entry named `walletAddress` / `accountAddress` / `address` / `wallet`
2. A `walletAddress`-style key inside an `attributes` or `case` object
3. **`externalUserId`** ← recommended for native Sumsub webhooks

If none of these contain a valid SS58/hex address, the webhook is acknowledged
(HTTP 200) but **no on-chain action is taken** — check the logs for
`No wallet address found` or `not a valid SS58/hex account`.

### Step 2 — Create the verification levels

The role a user receives is decided by the Sumsub **level name**. Create your
levels (Dashboard → **Dev space → Levels**) so their names match the mapping
below — otherwise the user is still funded on approval but receives **no role**.

| Sumsub `levelName` | Role assigned        |
|--------------------|----------------------|
| `basic-level`      | RealEstateInvestor (1) |
| `premium-level`    | RealEstateDeveloper (2) |
| `corporate-level`  | RealEstateDeveloper (2) |

If you prefer different level names, edit `KYC_LEVEL_ROLE_MAP` in
[`src/index.ts`](src/index.ts) to match.

### Step 3 — Create the webhook in the dashboard

Go to **Dashboard → Dev space → Webhooks → Webhook manager → Create webhook**
and fill in the form:

| Field | What to enter |
|---|---|
| **Name** | Any label, e.g. `Xcavate faucet` |
| **Webhook receiver type** | `HTTP address` |
| **Target** (URL) | `https://YOUR_HOST/webhook/sumsub` — must be HTTPS (TLS 1.2+) |
| **Webhook types** | Select **`applicantReviewed`** (required). You may also add `applicantPending`, `applicantOnHold`, etc. — the service safely ignores them. |
| **Applicant types** | `Individual` (add `Company` if you onboard companies via `corporate-level`) |
| **Secret key** | Click generate (or paste your own) and **copy it** — you'll need it in Step 5 |
| **Signature algorithm** | `SHA256` (default). `SHA512` also works — the service auto-detects from the header. |
| **HTTP Headers** | _(optional)_ leave empty |
| **Resend failed webhooks** | Leave **enabled** so transient failures are retried |
| **Rollout percentage** | `100%` |

Click **Save**.

> ⚠️ Only the **`applicantReviewed`** event triggers role assignment and token
> transfers. If you forget to subscribe to it, nothing will happen on approval.

### Step 4 — Configure the signing secret

Sumsub signs every webhook with the secret key from Step 3 and sends:

- `X-Payload-Digest` — hex HMAC of the raw request body
- `X-Payload-Digest-Alg` — the algorithm, e.g. `HMAC_SHA256_HEX` (default)

Put the secret in the service environment so it verifies the signature on every
request and rejects forgeries:

```bash
SUMSUB_SECRET=<the secret key you copied in Step 3>
```

> 🔒 **Strongly recommended in production.** Without `SUMSUB_SECRET` the service
> logs a startup warning and accepts unsigned requests — anyone who learns the
> URL could forge an `applicantReviewed / GREEN` event and drain the faucet.
> When set, requests with a missing or invalid signature get `401`.

### Step 5 — Test it

1. In the Webhook manager, use **Test webhook** to send a sample event — it
   should return `200`. (Sumsub considers no response within 5s a timeout and
   retries up to 4 times.)
2. Run a real verification in **Sandbox** mode with `externalUserId` set to a
   test wallet, approve the applicant, and confirm in the logs that the role and
   transfers were submitted on-chain.
3. The `sandboxMode` flag in the payload tells you whether an event came from
   Sandbox or Production.

---

## Webhook Payload

Sumsub delivers review results at the **top level** of the body (there is no
`data` wrapper). An `applicantReviewed` event looks like:

```json
POST /webhook/sumsub
Content-Type: application/json
X-Payload-Digest: <hex hmac>
X-Payload-Digest-Alg: HMAC_SHA256_HEX

{
  "type": "applicantReviewed",
  "applicantId": "5cb56e8e0a975a35f333cb83",
  "inspectionId": "5cb56e8e0a975a35f333cb84",
  "correlationId": "req-…",
  "externalUserId": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
  "levelName": "basic-level",
  "reviewStatus": "completed",
  "reviewResult": {
    "reviewAnswer": "GREEN"
  },
  "sandboxMode": false,
  "createdAtMs": "2026-06-30 13:23:19.001"
}
```

Fields the service reads:

| Field | Used for |
|---|---|
| `type` | Only `applicantReviewed` triggers action; others are acknowledged and skipped |
| `reviewResult.reviewAnswer` | `GREEN` → approve (assign role + transfer), `RED` → remove role |
| `levelName` | Maps to the blockchain role (see table above) |
| `externalUserId` | Destination wallet address (see Step 1 for alternatives) |

> **Backward compatibility:** payloads that use the older custom shape
> (`{ "event": ..., "data": { "levelName": ..., "fields": [...] } }`) are still
> accepted. When no `reviewResult` is present, any non-empty `levelName` other
> than `none` is treated as approved.

---

## KYC Level → Role Mapping

| KYC Level | Role | Pallet Call |
|---|---|---|
| `basic-level` | RealEstateInvestor (1) | `xcavateWhitelist.assign_role` |
| `premium-level` | RealEstateDeveloper (2) | `xcavateWhitelist.assign_role` |
| `corporate-level` | RealEstateDeveloper (2) | `xcavateWhitelist.assign_role` |
| rejected (`RED`) | — | `xcavateWhitelist.remove_role` |

## Blockchain Call Reference

All calls use raw metadata lookups at runtime — no compile-time codegen needed.

| Action | Pallet | Call Index | Args |
|---|---|---|---|
| Assign role | 20 (XcavateWhitelist) | 2 | AccountId32, Role enum |
| Remove role | 20 (XcavateWhitelist) | 3 | AccountId32, Role enum |
| Native transfer | 4 (Balances) | 0 | MultiAddress, Balance (u128) |
| Asset transfer | 9 (Assets) | 8 | AssetId (u32), MultiAddress, Balance (u128) |

---

## Environment Variables

```bash
# Blockchain endpoint — at least one must be set.
# If both are set, the testnet endpoint takes precedence and tGBP is also sent.
TESTNET_WS_URL=wss://xcavate-solochain.api.onfinality.io/public-ws
MAINNET_WS_URL=wss://...

# Faucet account — must have the Admin role on XcavateWhitelist and be funded
FAUCET_MNEMONIC="word1 word2 ..."

# Sumsub webhook secret key (from the Webhook manager). When set, every request
# is signature-verified via the X-Payload-Digest header. Strongly recommended.
SUMSUB_SECRET=your-webhook-secret

# Server port (default 8005)
PORT=8005
```

---

## Deploy (GitHub Actions)

The included workflow ([`.github/workflows/deploy.yml`](.github/workflows/deploy.yml))
SSHes into your server, pulls `main`, writes `.env` from repository secrets, and
restarts the container. Add these **GitHub repository secrets**:
`SSH_HOST`, `SSH_USER`, `SSH_PORT`, `SSH_KEY`, `DEPLOY_DIR`, `TESTNET_WS_URL`,
`MAINNET_WS_URL`, `FAUCET_MNEMONIC`, and **`SUMSUB_SECRET`**.

> The current workflow writes `TESTNET_WS_URL`, `MAINNET_WS_URL`, `FAUCET_MNEMONIC`
> and `PORT` into `.env`. Add a `SUMSUB_SECRET=${{ secrets.SUMSUB_SECRET }}` line
> to the generated `.env` block so signature verification is enabled in production.

```yaml
name: Deploy

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy via SSH
        uses: appleboy/ssh-action@v1.0.3
        env:
          DEPLOY_DIR: ${{ secrets.DEPLOY_DIR }}
          REPO_URL: https://github.com/${{ github.repository }}.git
        with:
          host: ${{ secrets.SSH_HOST }}
          username: ${{ secrets.SSH_USER }}
          port: ${{ secrets.SSH_PORT }}
          key: ${{ secrets.SSH_KEY }}
          envs: DEPLOY_DIR,REPO_URL
          script: |
            set -e
            mkdir -p "$DEPLOY_DIR"
            cd "$DEPLOY_DIR"
            git fetch origin main
            git reset --hard origin/main
            git clean -fd
            docker compose down -v --remove-orphans
            docker compose pull
            docker compose up -d --remove-orphans
```

---

## Local Test

```bash
# Run locally (hot-reload)
npm run dev

# Send a test webhook in Sumsub's native shape.
# If SUMSUB_SECRET is set, compute and attach the X-Payload-Digest header:
BODY='{"type":"applicantReviewed","applicantId":"test","levelName":"basic-level","externalUserId":"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY","reviewStatus":"completed","reviewResult":{"reviewAnswer":"GREEN"}}'
SIG=$(node -e 'const c=require("crypto");process.stdout.write(c.createHmac("sha256",process.env.SUMSUB_SECRET).update(process.argv[1]).digest("hex"))' "$BODY")

curl -X POST http://localhost:8005/webhook/sumsub \
  -H "Content-Type: application/json" \
  -H "X-Payload-Digest: $SIG" \
  -H "X-Payload-Digest-Alg: HMAC_SHA256_HEX" \
  -d "$BODY"

# Without SUMSUB_SECRET set, you can omit the signature headers entirely.
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Webhook returns `401` | `SUMSUB_SECRET` doesn't match the Webhook manager's secret key, or the `X-Payload-Digest-Alg` isn't one of SHA1/SHA256/SHA512 hex |
| `200` but `No wallet address found` in logs | `externalUserId` wasn't set when the applicant was created (see Step 1) |
| `200` but `not a valid SS58/hex account` | `externalUserId` holds something that isn't an address |
| Approved user gets tokens but no role | The Sumsub `levelName` isn't in `KYC_LEVEL_ROLE_MAP` (see Step 2) |
| Nothing happens on approval | The webhook isn't subscribed to `applicantReviewed`, or the target URL isn't reachable over HTTPS |
| `No blockchain endpoint configured` | Neither `TESTNET_WS_URL` nor `MAINNET_WS_URL` is set |
