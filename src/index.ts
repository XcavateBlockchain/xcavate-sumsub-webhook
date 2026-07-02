import express, { Request, Response } from "express";
import { ApiPromise, Keyring, WsProvider } from "@polkadot/api";
import { decodeAddress } from "@polkadot/util-crypto";
import crypto from "crypto";
import dotenv from "dotenv";
import pino from "pino";

dotenv.config();

// ── Logger ──────────────────────────────────────────────────────────────
const logger = pino({
  transport:
    process.env.NODE_ENV === "development"
      ? { target: "pino-pretty" }
      : undefined,
});

// ── Environment variables ───────────────────────────────────────────────
const TESTNET_WS_URL = process.env.TESTNET_WS_URL || "";
const MAINNET_WS_URL = process.env.MAINNET_WS_URL || "";
const FAUCET_MNEMONIC = process.env.FAUCET_MNEMONIC || "";
const SUMSUB_SECRET = process.env.SUMSUB_SECRET || "";
const PORT = parseInt(process.env.PORT || "8005", 10);

// ── Role mapping (from metadata type 71) ────────────────────────────────
// 0: RegionalOperator, 1: RealEstateInvestor, 2: RealEstateDeveloper,
// 3: Lawyer, 4: LettingAgent, 5: SpvConfirmation, 6-11: Module roles
const KYC_LEVEL_ROLE_MAP: Record<string, number> = {
  "csharp-verification-investor": 1,
  "csharp-verification-developer": 2,
  "csharp-verification-lawyer": 3,
  "csharp-verification-letting-agent": 4,
};

// ── Sumsub webhook payload type ─────────────────────────────────────────
//
// Sumsub sends review results at the TOP LEVEL of the body, e.g.:
//   {
//     "type": "applicantReviewed",
//     "applicantId": "...",
//     "externalUserId": "<wallet address>",
//     "levelName": "basic-level",
//     "reviewStatus": "completed",
//     "reviewResult": { "reviewAnswer": "GREEN" | "RED", ... }
//   }
// The legacy `event` / `data` wrapper below is kept only for backward
// compatibility with custom callers and the local test payload.
interface SumsubReviewResult {
  reviewAnswer?: string;
  reviewRejectType?: string;
  rejectLabels?: string[];
  moderationComment?: string;
  clientComment?: string;
}

interface SumsubPayload {
  // Native Sumsub fields (top level)
  type?: string;
  applicantId?: string;
  inspectionId?: string;
  correlationId?: string;
  externalUserId?: string;
  levelName?: string;
  reviewStatus?: string;
  reviewResult?: SumsubReviewResult;
  sandboxMode?: boolean;

  // Legacy / custom wrapper (backward compatibility)
  event?: string;
  data?: {
    caseId?: string;
    applicantId?: string;
    levelName?: string;
    reviewStatus?: string;
    status?: string;
    externalUserId?: string;
    fields?: Array<{ name: string; value: string }>;
    attributes?: Record<string, unknown>;
    case?: Record<string, unknown>;
  };
}

// ── Polkadot API singleton ──────────────────────────────────────────────
let apiRef: ApiPromise | null = null;
let detectedChain = "unknown";
let isTestnetFlag = false;

async function getApi(): Promise<ApiPromise> {
  if (apiRef && apiRef.isConnected) return apiRef;

  const wsUrl = TESTNET_WS_URL || MAINNET_WS_URL;
  if (!wsUrl) {
    throw new Error(
      "No blockchain endpoint configured. Set TESTNET_WS_URL or MAINNET_WS_URL in .env"
    );
  }

  const provider = new WsProvider(wsUrl);
  apiRef = await ApiPromise.create({ provider });
  await apiRef.isReady;

  // Detect chain to decide testnet vs mainnet behaviour
  try {
    const chain = await apiRef.rpc.system.chain();
    detectedChain = chain.toString();
    isTestnetFlag = detectedChain.toLowerCase().includes("test");
    logger.info({ chain: detectedChain, isTestnet: isTestnetFlag }, "Connected to blockchain");
  } catch {
    isTestnetFlag = !!TESTNET_WS_URL;
    detectedChain = TESTNET_WS_URL ? "testnet" : "mainnet";
    logger.info(
      { detectedChain, isTestnet: isTestnetFlag },
      "Connected (chain detection unavailable)",
    );
  }

  apiRef.on("disconnected", () => {
    apiRef = null;
    logger.warn("Disconnected from chain");
  });

  return apiRef;
}

// ── Keyring helper ──────────────────────────────────────────────────────
function getSigner() {
  if (!FAUCET_MNEMONIC) {
    throw new Error("FAUCET_MNEMONIC is not set in environment");
  }
  const keyring = new Keyring({ type: "sr25519" });
  return keyring.addFromUri(FAUCET_MNEMONIC);
}

// ── Account / encoding helpers ──────────────────────────────────────────

/** Convert SS58 / hex address → 32-byte AccountId32 bytes */
function toAccountIdBytes(address: string): Uint8Array {
  // decodeAddress accepts SS58 strings and hex (0x...) and returns raw 32 bytes
  return decodeAddress(address);
}

// ── Extrinsic construction & dispatch (runtime metadata resolved) ───────

function normalizeCallName(name: string): string {
  return name.replace(/[_\-\s]/g, "").toLowerCase();
}

function resolveTxMethod(
  api: ApiPromise,
  sectionCandidates: string[],
  methodCandidates: string[],
): {
  sectionName: string;
  methodName: string;
  method: (...args: unknown[]) => any;
} {
  const txRoot = api.tx as unknown as Record<string, Record<string, (...args: unknown[]) => any>>;
  const sectionSet = new Set(sectionCandidates.map(normalizeCallName));
  const methodSet = new Set(methodCandidates.map(normalizeCallName));

  for (const [sectionName, sectionMethods] of Object.entries(txRoot)) {
    if (!sectionSet.has(normalizeCallName(sectionName))) continue;
    for (const [methodName, method] of Object.entries(sectionMethods || {})) {
      if (methodSet.has(normalizeCallName(methodName))) {
        return { sectionName, methodName, method };
      }
    }
  }

  throw new Error(
    `Unable to resolve runtime call. sectionCandidates=${sectionCandidates.join("|")} methodCandidates=${methodCandidates.join("|")}`,
  );
}

async function buildTx(
  label: string,
  sectionCandidates: string[],
  methodCandidates: string[],
  args: unknown[],
): Promise<any> {
  const api = await getApi();
  const resolved = resolveTxMethod(api, sectionCandidates, methodCandidates);
  const tx = resolved.method(...args);

  logger.info(
    {
      label,
      section: resolved.sectionName,
      method: resolved.methodName,
    },
    "Resolved runtime call",
  );

  return tx;
}

async function buildBatchAllTx(calls: any[]): Promise<any> {
  return buildTx(
    "batch_all",
    ["utility"],
    ["batchAll", "batch_all"],
    [calls],
  );
}

async function submitExtrinsic(
  tx: any,
  label: string,
): Promise<string> {
  const api = await getApi();
  const signer = getSigner();

  return new Promise<string>(async (resolve, reject) => {
    let settled = false;
    let unsub: (() => void) | undefined;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      unsub?.();
      reject(err);
    };

    const pass = (hash: string) => {
      if (settled) return;
      settled = true;
      unsub?.();
      resolve(hash);
    };

    const timeoutId = setTimeout(() => {
      fail(new Error(`${label}: timeout waiting for finalization`));
    }, 120_000);

    try {
      unsub = await tx.signAndSend(signer, (result: any) => {
        const { status, dispatchError, txHash } = result;

        if (status?.isInBlock) {
          logger.info(
            { label, blockHash: status.asInBlock.toString() },
            "Extrinsic included in block",
          );
        }

        if (dispatchError) {
          let reason = dispatchError.toString();
          if (dispatchError.isModule) {
            const decoded = api.registry.findMetaError(dispatchError.asModule);
            reason = `${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`;
          }
          clearTimeout(timeoutId);
          return fail(new Error(`${label}: dispatch failed: ${reason}`));
        }

        if (status?.isFinalized) {
          const hash = txHash?.toString?.() || tx.hash?.toString?.() || "";
          logger.info(
            { label, hash, blockHash: status.asFinalized.toString() },
            "Extrinsic finalized",
          );
          clearTimeout(timeoutId);
          return pass(hash);
        }
      });
    } catch (err) {
      clearTimeout(timeoutId);
      fail(err instanceof Error ? err : new Error(String(err)));
    }
  });
}

// ── Role management (Pallet 20: XcavateWhitelist) ──────────────────────

/** assign_role(user, role) resolved from runtime metadata */
async function assignRole(account: string, roleId: number): Promise<string> {
  const tx = await buildTx(
    "assign_role",
    ["xcavateWhitelist", "XcavateWhitelist"],
    ["assignRole", "assign_role"],
    [account, roleId],
  );
  return submitExtrinsic(tx, "assign_role");
}

/** remove_role(user, role) resolved from runtime metadata */
async function removeRole(account: string, roleId: number): Promise<string> {
  const tx = await buildTx(
    "remove_role",
    ["xcavateWhitelist", "XcavateWhitelist"],
    ["removeRole", "remove_role"],
    [account, roleId],
  );
  return submitExtrinsic(tx, "remove_role");
}

/**
 * Pallet 20, Call 4: set_permission(user, role, permission)
 * permission: 0 = Revoked, 1 = Compliant
 */
async function setPermission(
  account: string,
  roleId: number,
  isCompliant: boolean,
): Promise<string> {
  const tx = await buildTx(
    "set_permission",
    ["xcavateWhitelist", "XcavateWhitelist"],
    ["setPermission", "set_permission"],
    [account, roleId, isCompliant ? 1 : 0],
  );
  return submitExtrinsic(tx, "set_permission");
}

// ── Token transfers ─────────────────────────────────────────────────────

/**
 * Native balance transfer resolved from runtime metadata.
 */
async function transferNativeBalance(
  to: string,
  amount: bigint,
): Promise<string> {
  const tx = await buildTx(
    "transfer_native",
    ["balances"],
    ["transferAllowDeath", "transfer_allow_death"],
    [to, amount.toString()],
  );
  return submitExtrinsic(tx, "transfer_native");
}

/**
 * Asset token transfer resolved from runtime metadata.
 */
async function transferAssetTokens(
  assetId: number,
  to: string,
  amount: bigint,
): Promise<string> {
  const tx = await buildTx(
    "transfer_asset",
    ["assets"],
    ["transfer"],
    [assetId, to, amount.toString()],
  );
  return submitExtrinsic(tx, "transfer_asset");
}

// ── Webhook processing ──────────────────────────────────────────────────

/** Keys we accept as the user's wallet address, in priority order. */
const WALLET_KEYS = ["walletAddress", "accountAddress", "address", "wallet"];

/**
 * Pull the user's wallet address out of whatever payload shape arrived.
 *
 * Recommended (native Sumsub): the address is stored in `externalUserId`,
 * which you set when the applicant is created. We also keep the legacy
 * fallbacks (custom `fields` array / `attributes` / `case` objects) so
 * existing custom callers keep working.
 */
function extractWalletAddress(body: SumsubPayload): string | null {
  // 1. Explicit wallet-named entry in a custom `fields` array (legacy)
  if (body.data?.fields) {
    for (const f of body.data.fields) {
      if (WALLET_KEYS.includes(f.name)) return f.value;
    }
  }

  // 2. Explicit wallet-named key in `attributes` / `case` objects (legacy)
  for (const container of [body.data?.attributes, body.data?.case]) {
    if (container) {
      for (const key of WALLET_KEYS) {
        if (container[key]) return String(container[key]);
      }
    }
  }

  // 3. externalUserId — the recommended place to stash the wallet address
  const ext = body.externalUserId ?? body.data?.externalUserId;
  if (ext) return String(ext);

  return null;
}

async function processSumsubWebhook(body: SumsubPayload): Promise<void> {
  // Normalise across native Sumsub and legacy custom shapes.
  const eventType = body.type || body.event || "";
  const levelName = body.levelName || body.data?.levelName || "";
  const reviewAnswer = body.reviewResult?.reviewAnswer;
  const caseId = body.applicantId || body.data?.applicantId || body.data?.caseId;

  logger.info(
    { eventType, caseId, levelName, reviewAnswer },
    "Processing Sumsub webhook",
  );

  // Sumsub emits many event types, but only the final review decides a
  // user's role and token allocation. Acknowledge everything else with 200
  // so Sumsub stops retrying. Payloads without a `type` (legacy/custom
  // callers and the local test) fall through to the heuristic below.
  if (body.type && body.type !== "applicantReviewed") {
    logger.info({ eventType }, "Non-decision event, acknowledging without action");
    return;
  }

  // Approval:
  //  - Native Sumsub: reviewResult.reviewAnswer === "GREEN" → approved, "RED" → rejected.
  //  - Legacy payloads (no reviewResult): treat any concrete level as approved.
  const isApproved =
    reviewAnswer !== undefined
      ? reviewAnswer === "GREEN"
      : levelName !== "none" && levelName !== "";

  const roleId = KYC_LEVEL_ROLE_MAP[levelName] ?? null;

  const accountAddress = extractWalletAddress(body);
  if (!accountAddress) {
    logger.warn(
      { caseId },
      "No wallet address found in payload, skipping",
    );
    return;
  }

  // Validate the address up front so we never half-apply on-chain actions
  // (e.g. assign a role but then fail every transfer) for a bad address.
  try {
    toAccountIdBytes(accountAddress);
  } catch {
    logger.warn(
      { caseId, accountAddress },
      "Wallet address is not a valid SS58/hex account, skipping",
    );
    return;
  }

  if (isApproved) {
    // ── Approved: assign role + transfer tokens ────────────────────
    const batchCalls: any[] = [];
    const nativeAmount = 10_000_000_000_000n; // 10 * 10^12
    const assetAmount = 10_000_000_000_000_000_000_000n; // 10000 * 10^18

    try {
      // 1. Assign blockchain role (if mapped)
      if (roleId !== null) {
        batchCalls.push(
          await buildTx(
            "assign_role",
            ["xcavateWhitelist", "XcavateWhitelist"],
            ["assignRole", "assign_role"],
            [accountAddress, roleId],
          ),
        );
      }

      // 2. Transfer 10 native tokens (decimals = 12 → 10 × 10¹²)
      batchCalls.push(
        await buildTx(
          "transfer_native",
          ["balances"],
          ["transferAllowDeath", "transfer_allow_death"],
          [accountAddress, nativeAmount.toString()],
        ),
      );

      // 3. Testnet only: 10 000 tGBP (assetId=10, decimals=18)
      if (isTestnetFlag) {
        batchCalls.push(
          await buildTx(
            "transfer_asset",
            ["assets"],
            ["transfer"],
            [10, accountAddress, assetAmount.toString()],
          ),
        );
      }

      const batchTx = await buildBatchAllTx(batchCalls);
      const hash = await submitExtrinsic(batchTx, "approved_batch_all");

      logger.info(
        {
          accountAddress,
          roleId,
          nativeAmount: nativeAmount.toString(),
          assetId: isTestnetFlag ? 10 : undefined,
          assetAmount: isTestnetFlag ? assetAmount.toString() : undefined,
          callCount: batchCalls.length,
          hash,
        },
        "Approved flow executed via Utility.batch_all",
      );
    } catch (err) {
      logger.error(
        { err, accountAddress, roleId, callCount: batchCalls.length },
        "Failed to execute approved batch_all extrinsic",
      );
    }
  } else {
    // ── Not approved: remove role ──────────────────────────────────
    if (roleId !== null) {
      try {
        const hash = await removeRole(accountAddress, roleId);
        logger.info(
          { accountAddress, roleId, hash },
          "Role removed",
        );
      } catch (err) {
        logger.error(
          { err, accountAddress, roleId },
          "Failed to remove role (may already be unassigned)",
        );
      }
    }
  }
}

// ── Express app ─────────────────────────────────────────────────────────

const app = express();

app.use(
  express.json({
    // Keep the raw bytes so we can verify Sumsub's HMAC signature, which is
    // computed over the exact request body.
    verify: (req: Request, _res, buf) => {
      (req as any).rawBody = buf;
    },
  }),
);

// ── Sumsub signature verification ──────────────────────────────────────
// Sumsub signs each webhook with your secret key and sends:
//   x-payload-digest:     hex HMAC of the raw body
//   x-payload-digest-alg: the algorithm, e.g. HMAC_SHA256_HEX (default)
const SIG_ALG_MAP: Record<string, string> = {
  HMAC_SHA1_HEX: "sha1",
  HMAC_SHA256_HEX: "sha256",
  HMAC_SHA512_HEX: "sha512",
};

function verifySumsubSignature(req: Request): boolean {
  const digest = req.headers["x-payload-digest"];
  if (typeof digest !== "string") return false;

  const algHeader = String(
    req.headers["x-payload-digest-alg"] || "HMAC_SHA256_HEX",
  ).toUpperCase();
  const alg = SIG_ALG_MAP[algHeader];
  if (!alg) {
    logger.warn({ algHeader }, "Unsupported Sumsub signature algorithm");
    return false;
  }

  const rawBody: Buffer = (req as any).rawBody ?? Buffer.alloc(0);
  const computed = crypto
    .createHmac(alg, SUMSUB_SECRET)
    .update(rawBody)
    .digest("hex");

  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(digest, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── Sumsub webhook endpoint ────────────────────────────────────────────
app.post("/webhook/sumsub", async (req: Request, res: Response) => {
  try {
    // Verify the HMAC signature when a secret is configured. Without this an
    // attacker who learns the URL could forge an "approved" event and drain
    // the faucet, so it is strongly recommended in production.
    if (SUMSUB_SECRET) {
      if (!verifySumsubSignature(req)) {
        logger.warn("Invalid or missing Sumsub webhook signature");
        return res.status(401).json({ error: "Invalid signature" });
      }
    }

    const body = req.body as SumsubPayload;
    await processSumsubWebhook(body);
    res.status(200).json({ status: "ok" });
  } catch (err) {
    logger.error(err, "Error processing webhook");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Health check ───────────────────────────────────────────────────────
app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    chain: detectedChain,
    isTestnet: isTestnetFlag,
    hasEndpoint: !!(TESTNET_WS_URL || MAINNET_WS_URL),
  });
});

// ── Start server ──────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  logger.info(`Sumsub webhook server listening on port ${PORT}`);
  if (!SUMSUB_SECRET) {
    logger.warn(
      "SUMSUB_SECRET is not set — webhook signatures are NOT verified. " +
        "Set it in production so forged requests cannot drain the faucet.",
    );
  }
});

async function gracefulShutdown() {
  logger.info("Shutting down…");
  server.close(async () => {
    if (apiRef) {
      await apiRef.disconnect();
    }
    process.exit(0);
  });
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

// ── Exports (for testing / composition) ─────────────────────────────────
export {
  app,
  processSumsubWebhook,
  assignRole,
  removeRole,
  setPermission,
  transferNativeBalance,
  transferAssetTokens,
};
