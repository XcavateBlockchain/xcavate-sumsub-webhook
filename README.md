# xcavate-sumsub-webhook

Webhook service that bridges Sumsub KYC results with the **realXmarket
`xcavate_whitelist` Solana program**.

When a Sumsub applicant is **reviewed and approved** (`reviewAnswer = GREEN`),
the service assigns the role that matches the KYC level — calling `assign_role`
if the user doesn't hold it yet, or `set_permission(Compliant)` if a previously
revoked assignment is still on chain. It then **airdrops 0.01 SOL + 10000 tGBP**
([`71G3dc4B…9HUb`](https://explorer.solana.com/address/71G3dc4B9p9QBosLx3XhWY3ULRPAxjopngsin66M9HUb?cluster=devnet))
to the user in a separate, best-effort transaction — even when the role was
already assigned and compliant (no on-chain change needed), a failed airdrop
never affects the role assignment.

When an applicant is **reviewed and rejected** (`reviewAnswer = RED`), the
matching assignment is revoked (`set_permission(Revoked)`), or removed outright
if you set `REJECTED_ROLE_ACTION=remove`.

All other Sumsub events are acknowledged and ignored.

| | |
|---|---|
| **Program** | [`7TrzjKpdrEhnfhxuw8tWdH1sjxadazscsG5HXCDPLmaY`](https://explorer.solana.com/address/7TrzjKpdrEhnfhxuw8tWdH1sjxadazscsG5HXCDPLmaY?cluster=devnet) |
| **Cluster** | Devnet (set `SOLANA_CLUSTER=mainnet-beta` for anything else) |
| **RPC** | Alchemy — `ALCHEMY_API_KEY` + `SOLANA_CLUSTER` (override with `SOLANA_RPC_URL`) |
| **Source** | [XcavateBlockchain/realxmarket-solana](https://github.com/XcavateBlockchain/realxmarket-solana) |
| **IDL** | [`src/idl/xcavate_whitelist.json`](src/idl/xcavate_whitelist.json) |

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

```json
{
  "status": "ok",
  "cluster": "devnet",
  "programId": "7TrzjKpdrEhnfhxuw8tWdH1sjxadazscsG5HXCDPLmaY",
  "admin": "D7LHTCvNtG37QsZSphsCTkJhLhg3SfpyjqMBwtfqbvaP",
  "adminIsRegistered": true
}
```

The service listens on `POST /webhook/sumsub`. To receive real webhooks from
Sumsub it must be reachable over **HTTPS** at a public URL (Sumsub rejects plain
HTTP). Put it behind a reverse proxy / load balancer that terminates TLS, e.g.
`https://kyc.example.com/webhook/sumsub`.

---

## The admin account

Every role change is signed by the account in `ADMIN_PRIVATE_KEY`. That account
must be a **registered whitelist admin** — the program checks that the
`["admin", <signer>]` PDA exists, and rejects the instruction otherwise.

```bash
# Generate a keypair (this prints the pubkey; the file holds the secret key)
solana-keygen new -o admin.json

# Fund it on devnet — it pays fees and ~0.0014 SOL of rent per role account
solana airdrop 2 $(solana-keygen pubkey admin.json) --url devnet
```

Then register it by calling `add_admin` **signed by the program's sudo
authority** (stored in the `["config"]` PDA — the service logs its address at
startup). That call lives in the program repo, not here.

Put the contents of `admin.json` — a JSON array of numbers — into
`ADMIN_PRIVATE_KEY`. A path to the file works too, which is convenient locally:

```bash
ADMIN_PRIVATE_KEY=[174,47,...]        # the raw secret key
ADMIN_PRIVATE_KEY=/etc/xcavate/admin.json   # or a path to it
```

### The tGBP airdrop balance

Approved users also receive an airdrop of **0.01 SOL + 10000 tGBP** (mint
[`71G3dc4B9p9QBosLx3XhWY3ULRPAxjopngsin66M9HUb`](https://explorer.solana.com/address/71G3dc4B9p9QBosLx3XhWY3ULRPAxjopngsin66M9HUb?cluster=devnet)),
paid from the admin account. The tGBP leaves the admin's **associated token
account** for that mint, so before the first approval send at least 10000 tGBP
to the admin's ATA on devnet (the service logs the exact address at startup).
The airdrop is best-effort: when the balance runs dry it is logged and skipped,
and the role assignment is still applied.

On startup the service checks all three requirements and logs a loud error if
the key isn't a registered admin, has a zero SOL balance, or the admin's tGBP
token account is missing/underfunded — that's much easier to spot at boot than
in a failed webhook an hour later.

> 🔑 The admin key can whitelist arbitrary wallets. Treat it as a production
> secret; never commit it.

---

## Connecting to Sumsub

This is the part you have to get right for the integration to work end-to-end.
Follow the steps in order.

### Prerequisites

- A Sumsub account with access to the **Dashboard** (Production and/or Sandbox).
- This service deployed and reachable at a public **HTTPS** URL.
- A funded, registered admin account (see above).

### Step 1 — Decide how the user's wallet address reaches the webhook

Sumsub has **no built-in "wallet address" field**. The service needs to know
which Solana account to whitelist, so you must supply it yourself. The
recommended way is to put the wallet address in Sumsub's **`externalUserId`**,
which is echoed back in every webhook.

You set `externalUserId` when you start a verification. With the WebSDK you do
this on your backend when generating the applicant access token:

```bash
# userId becomes the applicant's externalUserId
POST https://api.sumsub.com/resources/accessTokens
     ?userId=<USER_WALLET_ADDRESS>
     &levelName=csharp-verification-investor
     &ttlInSecs=600
```

(or pass `externalUserId` when creating the applicant via
`POST /resources/applicants?levelName=...`).

The service reads the destination account from **`externalUserId`** only.

If it is missing or does not contain a valid Solana public key, the webhook is
acknowledged (HTTP 200) but **no on-chain action is taken** — check the logs for
`No externalUserId in payload` or `not a valid Solana public key`.

### Step 2 — Create the verification levels

The role a user receives is decided by the Sumsub **level name**. Create your
levels (Dashboard → **Dev space → Levels**) so their names match the mapping
below — otherwise the review is acknowledged but **no role is assigned**.

| Sumsub `levelName` | Role assigned |
|---|---|
| `csharp-verification-investor` | `RealEstateInvestor` (1) |
| `csharp-verification-developer` | `RealEstateDeveloper` (2) |
| `csharp-verification-lawyer` | `Lawyer` (3) |
| `csharp-verification-letting-agent` | `LettingAgent` (4) |

If you prefer different level names, edit `KYC_LEVEL_ROLE_MAP` in
[`src/index.ts`](src/index.ts) to match.

### Step 3 — Create the webhook in the dashboard

Go to **Dashboard → Dev space → Webhooks → Webhook manager → Create webhook**
and fill in the form:

| Field | What to enter |
|---|---|
| **Name** | Any label, e.g. `Xcavate whitelist` |
| **Webhook receiver type** | `HTTP address` |
| **Target** (URL) | `https://YOUR_HOST/webhook/sumsub` — must be HTTPS (TLS 1.2+) |
| **Webhook types** | Select **`applicantReviewed`** (required). You may also add `applicantPending`, `applicantOnHold`, etc. — the service safely ignores them. |
| **Applicant types** | `Individual` (add `Company` if you onboard companies) |
| **Secret key** | Click generate (or paste your own) and **copy it** — you'll need it in Step 4 |
| **Signature algorithm** | `SHA256` (default). `SHA512` also works — the service auto-detects from the header. |
| **HTTP Headers** | _(optional)_ leave empty |
| **Resend failed webhooks** | Leave **enabled** so transient failures are retried |
| **Rollout percentage** | `100%` |

Click **Save**.

> ⚠️ Only the **`applicantReviewed`** event triggers a role change. If you forget
> to subscribe to it, nothing will happen on approval.

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
> URL could forge an `applicantReviewed / GREEN` event and whitelist a wallet of
> their choosing. When set, requests with a missing or invalid signature get `401`.

### Step 5 — Test it

1. In the Webhook manager, use **Test webhook** to send a sample event — it
   should return `200`. (Sumsub considers no response within 5s a timeout and
   retries up to 4 times.)
2. Run a real verification in **Sandbox** mode with `externalUserId` set to a
   test wallet, approve the applicant, and confirm in the logs that the role was
   assigned. Every successful call logs a `signature` you can open in the
   [explorer](https://explorer.solana.com/?cluster=devnet).
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
  "externalUserId": "3oX5ttHJvcqJDwbYh96tkShaa4bnWMM3JHc2N4kocSNY",
  "levelName": "csharp-verification-investor",
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
| `reviewResult.reviewAnswer` | `GREEN` → approve, `RED` → revoke |
| `levelName` | Maps to the role (see table above) |
| `externalUserId` | The user's Solana wallet address (see Step 1) |

> Only the native top-level Sumsub shape is accepted. An `applicantReviewed`
> event without a `reviewResult` is acknowledged and skipped.

---

## What happens on chain

Each `(user, role)` assignment is its own account at the PDA
`["role", user, role_index]`, owned by the whitelist program. The service reads
that account first and picks the instruction that actually applies, so redeliveries
and re-verifications are safe:

| Review | On-chain state | Instruction sent |
|---|---|---|
| `GREEN` | role not assigned | `assign_role(role)` — creates the account as `Compliant` |
| `GREEN` | assigned, `Revoked` | `set_permission(role, Compliant)` |
| `GREEN` | assigned, `Compliant` | *nothing on-chain* — already correct (the airdrop and the tgbp.io registration still run) |
| `RED` | assigned | `set_permission(role, Revoked)`, or `remove_role(role)` when `REJECTED_ROLE_ACTION=remove` |
| `RED` | not assigned | *nothing* |

Notes:

- `assign_role` uses Anchor's `init`, so it **fails if the role is already
  assigned** — hence the read-before-write above.
- `remove_role` refunds the account's rent to whoever paid it at assignment, so
  the service reads `rent_payer` off the account and passes it back.
- Role changes go out as a **single transaction**, which Solana executes
  atomically: all of it lands, or none of it does.
- The tGBP/SOL airdrop on approval is a **separate transaction**. It runs on
  every approval — including when the role was already assigned and compliant
  (where there is no role transaction to wait for) — and bundles the SOL
  transfer, an idempotent creation of the user's tGBP token account, and the
  tGBP transfer. If it fails (admin out of tGBP, RPC hiccup, …) it is logged
  and dropped — the role change is unaffected and Sumsub's 200 ack is sent.
  Note the consequence: a re-delivered or re-reviewed approval webhook
  airdrops again.
- **Off-chain customer registration (best-effort).** Once the on-chain half
  has confirmed, the service mints a Sumsub [Reusable KYC share
  token](https://docs.sumsub.com/docs/reusable-kyc-via-api) for the applicant
  (`POST /resources/accessTokens/shareToken`, `forClientId` = tgbp.io's
  Sumsub client) and registers the user as a customer on tgbp.io
  (`POST {TGBP_API_BASE_URL}/api/v1/customers`, `X-API-Key:
  <TGBP_API_KEY>`), passing the share token so tgbp.io can pull the KYC data.
  The Sumsub call is routed by the webhook payload's `sandboxMode` flag —
  sandbox applicants go to `api.sandbox.sumsub.com`, production ones to
  `api.sumsub.com` — so `SUMSUB_APP_TOKEN` must match the universe your KYC
  flow runs in.
  If it fails it is logged and dropped — the on-chain role is unaffected and
  the webhook still acks 200. The step is skipped entirely unless
  `TGBP_API_KEY`, `SUMSUB_APP_TOKEN` and `SUMSUB_RECIPIENT_CLIENT_ID` are all
  set (flagged at boot).
- The client is driven by [the IDL](src/idl/xcavate_whitelist.json): program id,
  discriminators, account ordering and signer/writable flags all come from that
  file. After a program upgrade, drop in the regenerated IDL.

### Roles

Indices are fixed by the program (`Role::seed_byte()`) and must not be reordered:

| Index | Role |
|---|---|
| 0 | `RegionalOperator` |
| 1 | `RealEstateInvestor` |
| 2 | `RealEstateDeveloper` |
| 3 | `Lawyer` |
| 4 | `LettingAgent` |
| 5 | `SpvConfirmation` |

---

## Environment Variables

```bash
# Alchemy API key — the RPC endpoint is built from it and SOLANA_CLUSTER,
# e.g. https://solana-devnet.g.alchemy.com/v2/<key>
ALCHEMY_API_KEY=your-alchemy-key

# Cluster to talk to: devnet (default) or mainnet-beta
SOLANA_CLUSTER=devnet

# Optional full RPC URL. Overrides ALCHEMY_API_KEY — set it only to bypass
# Alchemy (self-hosted node, another provider).
SOLANA_RPC_URL=

# Whitelist admin secret key as a JSON array of numbers (solana-keygen format),
# or a path to such a file. Must be a registered admin and hold SOL.
ADMIN_PRIVATE_KEY=[12,34,...]

# What to do when a user fails KYC and already holds the role:
#   revoke (default) — keep the role, set its permission to Revoked
#   remove           — close the role account entirely
REJECTED_ROLE_ACTION=revoke

# Optional SOL drip to newly approved users, in SOL. 0/unset disables it.
FAUCET_SOL_AMOUNT=0

# Sumsub webhook secret key. When set, every webhook is signature-verified.
SUMSUB_SECRET=your-webhook-secret

# tgbp.io customer registration — all three of the next variables must be
# set for the step to run; otherwise it is skipped and flagged at boot.
# tgbp.io API base URL (sandbox by default; https://api.tgbp.io for live)
TGBP_API_BASE_URL=https://sandbox.tgbp.io
# tgbp.io API key (sandbox keys are prefixed `tgbp_sandbox_`), sent as
# `X-API-Key` — the server-to-server auth per the API reference
TGBP_API_KEY=
# Sumsub client (app) token for this service's Sumsub account — mints the
# Reusable KYC share token
SUMSUB_APP_TOKEN=
# tgbp.io's Sumsub client ID — the `forClientId` (recipient) of the share token
SUMSUB_RECIPIENT_CLIENT_ID=
# Share-token TTL in seconds (default 1200)
SUMSUB_SHARE_TOKEN_TTL=1200

# Server port (default 8005)
PORT=8005
```

---

## Deploy (GitHub Actions)

The included workflow ([`.github/workflows/deploy.yml`](.github/workflows/deploy.yml))
SSHes into your server, pulls `main`, writes `.env` from repository secrets, and
restarts the container.

Add these **repository secrets**: `SSH_HOST`, `SSH_USER`, `SSH_PORT`, `SSH_KEY`,
`DEPLOY_DIR`, `ALCHEMY_API_KEY`, `ADMIN_PRIVATE_KEY`, `SUMSUB_SECRET`. Add
`SOLANA_RPC_URL` as a secret too only if you're bypassing Alchemy — when it's
set, it wins over `ALCHEMY_API_KEY`.

Add these for **tgbp.io customer registration**: secret `TGBP_API_KEY` and
secret `SUMSUB_APP_TOKEN`, plus repository variables
`SUMSUB_RECIPIENT_CLIENT_ID` (and optionally `TGBP_API_BASE_URL` and
`SUMSUB_SHARE_TOKEN_TTL`). Until all three of the key/token/client-id values
are set, approvals are handled on-chain only and the gap is logged at boot.

Optionally add these **repository variables**: `SOLANA_CLUSTER`,
`REJECTED_ROLE_ACTION`, `FAUCET_SOL_AMOUNT`. Leaving them unset keeps the
defaults (`devnet`, `revoke`, no drip).

---

## Local Test

```bash
# Run locally (hot-reload)
npm run dev

# Send a test webhook in Sumsub's native shape.
# If SUMSUB_SECRET is set, compute and attach the X-Payload-Digest header:
BODY='{"type":"applicantReviewed","applicantId":"test","levelName":"csharp-verification-investor","externalUserId":"3oX5ttHJvcqJDwbYh96tkShaa4bnWMM3JHc2N4kocSNY","reviewStatus":"completed","reviewResult":{"reviewAnswer":"GREEN"}}'
SIG=$(node -e 'const c=require("crypto");process.stdout.write(c.createHmac("sha256",process.env.SUMSUB_SECRET).update(process.argv[1]).digest("hex"))' "$BODY")

curl -X POST http://localhost:8005/webhook/sumsub \
  -H "Content-Type: application/json" \
  -H "X-Payload-Digest: $SIG" \
  -H "X-Payload-Digest-Alg: HMAC_SHA256_HEX" \
  -d "$BODY"

# Without SUMSUB_SECRET set, you can omit the signature headers entirely.
```

To inspect what's already on chain:

```bash
solana account <ROLE_ACCOUNT_PDA> --url devnet
solana program show 7TrzjKpdrEhnfhxuw8tWdH1sjxadazscsG5HXCDPLmaY --url devnet
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Webhook returns `401` | `SUMSUB_SECRET` doesn't match the Webhook manager's secret key, or the `X-Payload-Digest-Alg` isn't one of SHA1/SHA256/SHA512 hex |
| `200` but `No wallet address found` in logs | `externalUserId` wasn't set when the applicant was created (see Step 1) |
| `200` but `not a valid Solana public key` | `externalUserId` holds something that isn't a base58 Solana address (an address from another chain, an email, …) |
| Approved user gets no role | The Sumsub `levelName` isn't in `KYC_LEVEL_ROLE_MAP` (see Step 2) |
| `ADMIN_PRIVATE_KEY is NOT a registered whitelist admin` at startup | The key's address has no `["admin", …]` PDA — register it with `add_admin` from the sudo authority |
| `Admin tGBP token account does not exist` / `Admin tGBP balance is below the 10000 airdrop amount` at startup | Send ≥ 10000 tGBP to the admin's tGBP associated token account (address in the log) — until then every airdrop fails, role assignments are unaffected |
| `Airdrop failed` in the webhook logs while the role was assigned | Same cause as above — check the admin's tGBP balance and top up; the airdrop is best-effort by design |
| `AnchorError … ConstraintSeeds` / `AccountNotInitialized` | The admin isn't registered, or the RPC points at a cluster where the program isn't deployed (check `cluster` / `rpc` in `/health`) |
| `401`/`403` from the RPC, or `Could not reach the Solana RPC` at startup | `ALCHEMY_API_KEY` is wrong, or the Alchemy app doesn't have Solana on the configured `SOLANA_CLUSTER` enabled |
| `The RPC endpoint serves a different cluster than SOLANA_CLUSTER says` | `SOLANA_CLUSTER` and the actual endpoint disagree — most often a stale `SOLANA_RPC_URL` still set in `.env`, which overrides Alchemy |
| `Attempt to debit an account but found no record of a prior credit` | The admin account has no SOL |
| `PermissionAlreadySet` (6001) | The permission is already at the requested value — harmless, and normally avoided by the read-before-write |
| `WrongRentPayer` (6005) | `remove_role` was sent with a `rent_payer` other than the one stored on the role account |
| Nothing happens on approval | The webhook isn't subscribed to `applicantReviewed`, or the target URL isn't reachable over HTTPS |
