# xcavate-sumsub-webhook

Webhook service that bridges Sumsub KYC results with the Xcavate blockchain.

When a Sumsub case is verified, the webhook automatically:
1. **Assigns a blockchain role** via the `XcavateWhitelist` pallet based on KYC level
2. **Transfers 10 native tokens** (12 decimals) to the user's address
3. **Transfers 10,000 tGBP tokens** (assetId=10, 6 decimals) — testnet only

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

## Webhook Payload

```json
POST /webhook/sumsub
Content-Type: application/json

{
  "event": "applicant.created",
  "data": {
    "caseId": "case_abc123",
    "levelName": "basic-level",
    "fields": [
      { "name": "walletAddress", "value": "xcavate1..." }
    ]
  }
}
```

## KYC Level → Role Mapping

| KYC Level | Role | Pallet Call |
|---|---|---|
| `basic-level` | RealEstateInvestor (1) | `xcavateWhitelist.assign_role` |
| `premium-level` | RealEstateDeveloper (2) | `xcavateWhitelist.assign_role` |
| `corporate-level` | RealEstateDeveloper (2) | `xcavateWhitelist.assign_role` |
| `none` / rejected | — | `xcavateWhitelist.remove_role` |

## Blockchain Call Reference

All calls use raw metadata lookups at runtime — no compile-time codegen needed.

| Action | Pallet | Call Index | Args |
|---|---|---|---|
| Assign role | 20 (XcavateWhitelist) | 2 | AccountId32, Role enum |
| Remove role | 20 (XcavateWhitelist) | 3 | AccountId32, Role enum |
| Native transfer | 4 (Balances) | 0 | MultiAddress, Balance (u128) |
| Asset transfer | 9 (Assets) | 8 | AssetId (u32), MultiAddress, Balance (u128) |

## Environment Variables

```bash
# At least one must be set (both can be set; testnet takes precedence)
TESTNET_WS_URL=wss://xcavate-solochain.api.onfinality.io/public-ws
MAINNET_WS_URL=wss://...

# Faucet account — must have Admin role on XcavateWhitelist
FAUCET_MNEMONIC="word1 word2 ..."

# Optional: Sumsub webhook signature verification
SUMSUB_SECRET=your-webhook-secret
```

## Deploy (GitHub Actions)

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

## Local Test

```bash
# Run locally (hot-reload)
npm run dev

# Send a test webhook
curl -X POST http://localhost:8005/webhook/sumsub \
  -H "Content-Type: application/json" \
  -d '{
    "event": "applicant.created",
    "data": {
      "caseId": "test-case",
      "levelName": "basic-level",
      "fields": [{"name": "walletAddress", "value": "xcavate1..."}]
    }
  }'
```