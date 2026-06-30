import express, { Request, Response } from "express";
import { ApiPromise, Keyring, WsProvider } from "@polkadot/api";
import { decodeAddress } from "@polkadot/util-crypto";
import { hexToU8a } from "@polkadot/util";
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
const PORT = parseInt(process.env.PORT || "8005", 10);

// ── Role mapping (from metadata type 71) ────────────────────────────────
// 0: RegionalOperator, 1: RealEstateInvestor, 2: RealEstateDeveloper,
// 3: Lawyer, 4: LettingAgent, 5: SpvConfirmation, 6-11: Module roles
const KYC_LEVEL_ROLE_MAP: Record<string, number> = {
  "basic-level": 1, // RealEstateInvestor
  "premium-level": 2, // RealEstateDeveloper
  "corporate-level": 2, // RealEstateDeveloper
};

// ── Sumsub webhook payload type ─────────────────────────────────────────
interface SumsubPayload {
  event: string;
  data: {
    caseId: string;
    applicantId?: string;
    levelName?: string;
    reviewStatus?: string;
    status?: string;
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
  if (address.startsWith("0x")) {
    return hexToU8a(address);
  }
  return decodeAddress(address);
}

/** MultiAddress::Id = variant index 0 (1 byte) + AccountId32 (32 bytes) */
function toMultiAddressId(address: string): Uint8Array {
  const addr = toAccountIdBytes(address);
  const result = new Uint8Array(33);
  result[0] = 0; // MultiAddress::Id
  result.set(addr, 1);
  return result;
}

// ── SS58 compact encoding (used for AssetId and Balance) ────────────────
// The two least-significant bits of the first byte encode the size:
//   0b00 → 1 byte (value < 64)
//   0b01 → 2 bytes (value < 16 384)
//   0b10 → 4 bytes (value < 2^30)
//   0b11 → 8 bytes (value < 2^62)

function encodeCompact(value: bigint): Uint8Array {
  if (value < 64n) {
    return new Uint8Array([Number(value)]);
  }
  if (value < 16_384n) {
    const v = Number(value * 4n) | 0b01;
    const b = new Uint8Array(2);
    b[0] = v & 0xff;
    b[1] = (v >> 8) & 0xff;
    return b;
  }
  if (value < 4_294_967_296n) {
    const v = Number(value * 4n) | 0b10;
    const b = new Uint8Array(4);
    b[0] = v & 0xff;
    b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff;
    b[3] = (v >> 24) & 0xff;
    return b;
  }
  const v = value * 4n;
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    b[i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  b[0] |= 0b11;
  return b;
}

function encodeCompactU32(value: number): Uint8Array {
  return encodeCompact(BigInt(value));
}

// ── Extrinsic construction & dispatch ───────────────────────────────────
//
// Pallet indices from metadata v15:
//   Pallet 4  = Balances:   call[0] = transfer_allow_death
//   Pallet 9  = Assets:     call[8] = transfer
//   Pallet 20 = XcavateWhitelist:
//                 call[2] = assign_role (AccountId32, Role)
//                 call[3] = remove_role (AccountId32, Role)
//                 call[4] = set_permission (AccountId32, Role, AccessPermission)
//
// We build raw call bytes [pallet_idx, call_idx, …arg_bytes] and feed
// them to `registry.createType("Call", bytes)` which decodes them
// against the live metadata — no compile-time codegen needed.

/**
 * Build raw call bytes for a signed extrinsic.
 * Returns a Buffer with: [palletIdx(1), callIdx(1), ...argBytes...]
 */
function buildCallBytes(
  palletIdx: number,
  callIdx: number,
  ...argBytes: Uint8Array[]
): Uint8Array {
  const total = 2 + argBytes.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  out[0] = palletIdx;
  out[1] = callIdx;
  let off = 2;
  for (const b of argBytes) {
    out.set(b, off);
    off += b.length;
  }
  return out;
}

/**
 * Submit a signed extrinsic constructed from raw call bytes and
 * wait for finalisation.  Returns the extrinsic hash.
 */
async function submitExtrinsic(
  callBytes: Uint8Array,
  label: string,
): Promise<string> {
  const api = await getApi();
  const signer = getSigner();

  // Decode the raw bytes against the live metadata so polkadot-js knows
  // the call's section, method, and argument types.
  const callObj = api.registry.createType("Call", callBytes);

  // Wrap in an extrinsic and sign
  const extrinsic = api.createType("Extrinsic", callObj, {
    version: api.extrinsicVersion,
  });
  const { genesisHash, runtimeVersion } = api;
  const nonce = await api.rpc.system.accountNextIndex(signer.address);
  const blockHash = await api.rpc.chain.getBlockHash();
  const signed = extrinsic.sign(signer, { genesisHash, runtimeVersion, nonce, blockHash });

  logger.info(
    {
      pallet: callObj.section,
      method: callObj.method,
      hash: signed.hash.toString(),
    },
    `${label}: signed, submitting`,
  );

  // Submit and wait for finalisation (with a 2-minute safety timeout)
  const hash = await api.rpc.author.submitExtrinsic(signed);
  await waitForFinalization(signed);

  return hash.toString();
}

// ── Role management (Pallet 20: XcavateWhitelist) ──────────────────────

/** Pallet 20, Call 2: assign_role(user, role) */
async function assignRole(account: string, roleId: number): Promise<string> {
  const args = buildCallBytes(
    20, 2,
    toAccountIdBytes(account),
    new Uint8Array([roleId]),
  );
  return submitExtrinsic(args, "assign_role");
}

/** Pallet 20, Call 3: remove_role(user, role) */
async function removeRole(account: string, roleId: number): Promise<string> {
  const args = buildCallBytes(
    20, 3,
    toAccountIdBytes(account),
    new Uint8Array([roleId]),
  );
  return submitExtrinsic(args, "remove_role");
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
  const args = buildCallBytes(
    20, 4,
    toAccountIdBytes(account),
    new Uint8Array([roleId]),
    new Uint8Array([isCompliant ? 1 : 0]),
  );
  return submitExtrinsic(args, "set_permission");
}

// ── Token transfers ─────────────────────────────────────────────────────

/**
 * Native balance transfer — Pallet 4, Call 0: transfer_allow_death
 * Args: MultiAddress::Id (1+32), Balance (compact u128)
 */
async function transferNativeBalance(
  to: string,
  amount: bigint,
): Promise<string> {
  const args = buildCallBytes(
    4, 0,
    toMultiAddressId(to),
    encodeCompact(amount),
  );
  return submitExtrinsic(args, "transfer_native");
}

/**
 * Asset token transfer — Pallet 9, Call 8: assets.transfer
 * Args: AssetId (compact u32), MultiAddress::Id (1+32), Balance (compact u128)
 */
async function transferAssetTokens(
  assetId: number,
  to: string,
  amount: bigint,
): Promise<string> {
  const args = buildCallBytes(
    9, 8,
    encodeCompactU32(assetId),
    toMultiAddressId(to),
    encodeCompact(amount),
  );
  return submitExtrinsic(args, "transfer_asset");
}

// ── Finalisation wait helper ────────────────────────────────────────────
function waitForFinalization(extrinsic: any): Promise<void> {
  return new Promise<void>((resolve) => {
    const unsub = extrinsic?.on("status", async (status: any) => {
      if (status.isInBlock) {
        logger.info(
          { blockHash: status.asInBlock.toString() },
          "Extrinsic included in block",
        );
      }
      if (status.isFinalized) {
        logger.info(
          { blockHash: status.asFinalized.toString() },
          "Extrinsic finalized",
        );
        unsub?.();
        resolve();
      }
    });

    // Safety timeout — 2 minutes
    setTimeout(() => {
      resolve();
    }, 120_000);
  });
}

// ── Webhook processing ──────────────────────────────────────────────────

async function processSumsubWebhook(body: SumsubPayload): Promise<void> {
  const { event, data } = body;
  logger.info(
    { event, caseId: data.caseId, levelName: data.levelName },
    "Processing Sumsub webhook",
  );

  const levelName = data.levelName || "";
  const isApproved = levelName !== "none" && levelName !== "";
  const roleId = KYC_LEVEL_ROLE_MAP[levelName] ?? null;

  // ── Extract wallet address from various Sumsub payload shapes ──────
  let accountAddress: string | null = null;

  // Case A: fields array [{ name, value }]
  if (data.fields) {
    for (const f of data.fields) {
      if (
        f.name === "walletAddress" ||
        f.name === "accountAddress" ||
        f.name === "address" ||
        f.name === "wallet"
      ) {
        accountAddress = f.value;
        break;
      }
    }
  }

  // Case B: top-level attributes object
  if (!accountAddress && (data as any).attributes) {
    const attrs: Record<string, unknown> = (data as any).attributes;
    for (const key of [
      "walletAddress",
      "accountAddress",
      "address",
      "wallet",
    ]) {
      if (attrs[key]) {
        accountAddress = String(attrs[key]);
        break;
      }
    }
  }

  // Case C: nested case object
  if (!accountAddress && (data as any).case) {
    const casedata: Record<string, unknown> = (data as any).case;
    for (const key of [
      "walletAddress",
      "accountAddress",
      "address",
      "wallet",
    ]) {
      if (casedata[key]) {
        accountAddress = String(casedata[key]);
        break;
      }
    }
  }

  if (!accountAddress) {
    logger.warn(
      { caseId: data.caseId },
      "No wallet address found in payload, skipping",
    );
    return;
  }

  if (isApproved) {
    // ── Approved: assign role + transfer tokens ────────────────────

    // 1. Assign blockchain role
    if (roleId !== null) {
      try {
        const hash = await assignRole(accountAddress, roleId);
        logger.info(
          { accountAddress, roleId, hash },
          "Role assigned",
        );
      } catch (err) {
        logger.error(
          { err, accountAddress, roleId },
          "Failed to assign role (may already be assigned)",
        );
      }
    }

    // 2. Transfer 10 native tokens (decimals = 12 → 10 × 10¹²)
    try {
      const nativeAmount = 10_000_000_000_000n; // 10 * 10^12
      const hash = await transferNativeBalance(
        accountAddress,
        nativeAmount,
      );
      logger.info(
        {
          accountAddress,
          amount: nativeAmount.toString(),
          hash,
        },
        "Native balance transferred",
      );
    } catch (err) {
      logger.error(
        { err, accountAddress },
        "Failed to transfer native balance",
      );
    }

    // 3. Testnet only: 10 000 tGBP (assetId=10, decimals=6 → 10⁴ × 10⁶)
    if (isTestnetFlag) {
      try {
        const assetAmount = 10_000_000_000n; // 10000 * 10^6
        const hash = await transferAssetTokens(
          10,
          accountAddress,
          assetAmount,
        );
        logger.info(
          {
            accountAddress,
            assetId: 10,
            amount: assetAmount.toString(),
            hash,
          },
          "tGBP asset tokens transferred (testnet)",
        );
      } catch (err) {
        logger.error(
          { err, accountAddress },
          "Failed to transfer asset tokens",
        );
      }
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
    verify: (req: Request, _res, buf) => {
      (req as any).rawBody = buf.toString();
    },
  }),
);

// ── Sumsub webhook endpoint ────────────────────────────────────────────
app.post("/webhook/sumsub", async (req: Request, res: Response) => {
  try {
    const body = req.body as SumsubPayload;

    // Optional HMAC signature verification (Sumsub sends signature in
    // X-Sumsub-Signature header).  Uncomment below and set SUMSUB_SECRET.
    /*
    if (process.env.SUMSUB_SECRET && req.headers["x-sumsub-signature"]) {
      const crypto = require("crypto");
      const hmac = crypto
        .createHmac("sha256", process.env.SUMSUB_SECRET)
        .update((req as any).rawBody)
        .digest("hex");
      if (hmac !== (req.headers["x-sumsub-signature"] as string)) {
        logger.warn("Invalid Sumsub webhook signature");
        return res.status(401).json({ error: "Invalid signature" });
      }
    }
    */

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