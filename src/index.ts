import express, { Request, Response } from "express";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import crypto from "crypto";
import fs from "fs";
import dotenv from "dotenv";
import pino from "pino";

import rawIdl from "./idl/xcavate_whitelist.json";

dotenv.config();

// ── Logger ──────────────────────────────────────────────────────────────
const logger = pino({
  transport:
    process.env.NODE_ENV === "development"
      ? { target: "pino-pretty" }
      : undefined,
});

// ── Environment variables ───────────────────────────────────────────────
const SOLANA_RPC_URL =
  process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
const ADMIN_PRIVATE_KEY = process.env.ADMIN_PRIVATE_KEY || "";
const SUMSUB_SECRET = process.env.SUMSUB_SECRET || "";
const PORT = parseInt(process.env.PORT || "8005", 10);

/**
 * What to do when a user fails KYC and already holds the role.
 *  - "revoke" (default): keep the role account, flip its permission to
 *    Revoked. This mirrors the program's compliance model — `AccessPermission`
 *    is exactly the "admin set this after off-chain KYC/AML" flag.
 *  - "remove": close the role account entirely, freeing the assignment (rent
 *    goes back to whoever paid it). Use this if a failed review should undo
 *    the role rather than mark it non-compliant.
 */
const REJECTED_ROLE_ACTION =
  process.env.REJECTED_ROLE_ACTION === "remove" ? "remove" : "revoke";

/**
 * Optional SOL drip to newly approved users, in SOL (e.g. "0.05").
 * 0 / unset disables the transfer — on Solana the admin pays the role
 * account's rent, so a user needs no funds to be whitelisted.
 */
const FAUCET_SOL_AMOUNT = parseFloat(process.env.FAUCET_SOL_AMOUNT || "0");
const FAUCET_SOL_LAMPORTS = Number.isFinite(FAUCET_SOL_AMOUNT)
  ? Math.round(FAUCET_SOL_AMOUNT * LAMPORTS_PER_SOL)
  : 0;

// ── IDL ─────────────────────────────────────────────────────────────────
// The client is driven by the program IDL: program id, instruction
// discriminators, account ordering and the signer/writable flags all come
// from `src/idl/xcavate_whitelist.json`. Drop in a fresh IDL after a program
// upgrade and the instructions rebuild themselves.

interface IdlAccountSpec {
  name: string;
  writable?: boolean;
  signer?: boolean;
  address?: string;
}

interface IdlInstructionSpec {
  name: string;
  discriminator: number[];
  accounts: IdlAccountSpec[];
}

interface WhitelistIdl {
  address: string;
  instructions: IdlInstructionSpec[];
  accounts: Array<{ name: string; discriminator: number[] }>;
  errors: Array<{ code: number; name: string; msg: string }>;
}

const IDL = rawIdl as unknown as WhitelistIdl;

const PROGRAM_ID = new PublicKey(IDL.address);

/** PDA seeds, from the program's `constants.rs`. */
const CONFIG_SEED = Buffer.from("config");
const ADMIN_SEED = Buffer.from("admin");
const ROLE_SEED = Buffer.from("role");

/**
 * `Role` variant indices. These double as `Role::seed_byte()` in the role
 * PDA seeds, and the program pins them explicitly — do not reorder.
 */
enum Role {
  RegionalOperator = 0,
  RealEstateInvestor = 1,
  RealEstateDeveloper = 2,
  Lawyer = 3,
  LettingAgent = 4,
  SpvConfirmation = 5,
}

/** `AccessPermission` variant indices. Compliant is 0, Revoked is 1. */
enum AccessPermission {
  Compliant = 0,
  Revoked = 1,
}

const ROLE_NAMES: Record<Role, string> = {
  [Role.RegionalOperator]: "RegionalOperator",
  [Role.RealEstateInvestor]: "RealEstateInvestor",
  [Role.RealEstateDeveloper]: "RealEstateDeveloper",
  [Role.Lawyer]: "Lawyer",
  [Role.LettingAgent]: "LettingAgent",
  [Role.SpvConfirmation]: "SpvConfirmation",
};

// ── KYC level → role mapping ────────────────────────────────────────────
const KYC_LEVEL_ROLE_MAP: Record<string, Role | undefined> = {
  "csharp-verification-investor": Role.RealEstateInvestor,
  "csharp-verification-developer": Role.RealEstateDeveloper,
  "csharp-verification-lawyer": Role.Lawyer,
  "csharp-verification-letting-agent": Role.LettingAgent,
};

// ── Sumsub webhook payload type ─────────────────────────────────────────
//
// Sumsub sends review results at the TOP LEVEL of the body, e.g.:
//   {
//     "type": "applicantReviewed",
//     "applicantId": "...",
//     "externalUserId": "<wallet address>",
//     "levelName": "csharp-verification-investor",
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

// ── Solana connection & admin signer ────────────────────────────────────

const connection = new Connection(SOLANA_RPC_URL, "confirmed");

/** Genesis hashes, used to report which cluster we actually ended up on. */
const CLUSTER_BY_GENESIS_HASH: Record<string, string> = {
  "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d": "mainnet-beta",
  EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG: "devnet",
  "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": "testnet",
};

let detectedCluster = "unknown";
let adminIsRegistered: boolean | null = null;

let adminKeypair: Keypair | null = null;

/**
 * Load the whitelist admin signer.
 *
 * `ADMIN_PRIVATE_KEY` is the raw secret key as a JSON array of numbers — the
 * same format `solana-keygen` writes. A filesystem path to such a file is
 * also accepted, which is handy for local development.
 */
function loadAdminKeypair(): Keypair {
  const raw = ADMIN_PRIVATE_KEY.trim();
  if (!raw) {
    throw new Error("ADMIN_PRIVATE_KEY is not set in environment");
  }

  const json = raw.startsWith("[") ? raw : fs.readFileSync(raw, "utf8");

  let bytes: unknown;
  try {
    bytes = JSON.parse(json);
  } catch {
    throw new Error(
      "ADMIN_PRIVATE_KEY must be a JSON array of numbers (the secret key), " +
        "or a path to a keypair JSON file",
    );
  }

  if (!Array.isArray(bytes) || bytes.some((b) => typeof b !== "number")) {
    throw new Error("ADMIN_PRIVATE_KEY must be a JSON array of numbers");
  }

  const secret = Uint8Array.from(bytes as number[]);
  if (secret.length === 64) return Keypair.fromSecretKey(secret);
  if (secret.length === 32) return Keypair.fromSeed(secret);

  throw new Error(
    `ADMIN_PRIVATE_KEY has ${secret.length} bytes, expected 64 (secret key) or 32 (seed)`,
  );
}

function getAdmin(): Keypair {
  if (!adminKeypair) adminKeypair = loadAdminKeypair();
  return adminKeypair;
}

// ── PDA helpers ─────────────────────────────────────────────────────────

/** `["config"]` — the singleton program config. */
function configPda(): PublicKey {
  return PublicKey.findProgramAddressSync([CONFIG_SEED], PROGRAM_ID)[0];
}

/** `["admin", admin]` — proves an address is a registered whitelist admin. */
function adminPda(admin: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [ADMIN_SEED, admin.toBuffer()],
    PROGRAM_ID,
  )[0];
}

/** `["role", user, role.seed_byte()]` — one (user, role) assignment. */
function roleAccountPda(user: PublicKey, role: Role): PublicKey {
  return PublicKey.findProgramAddressSync(
    [ROLE_SEED, user.toBuffer(), Buffer.from([role])],
    PROGRAM_ID,
  )[0];
}

// ── Account decoding ────────────────────────────────────────────────────

interface RoleAccountData {
  user: PublicKey;
  role: Role;
  permission: AccessPermission;
  rentPayer: PublicKey;
  bump: number;
}

function accountDiscriminator(name: string): Buffer {
  const spec = IDL.accounts.find((a) => a.name === name);
  if (!spec) throw new Error(`Account ${name} not found in IDL`);
  return Buffer.from(spec.discriminator);
}

const ROLE_ACCOUNT_DISCRIMINATOR = accountDiscriminator("RoleAccount");

/**
 * Borsh layout of `RoleAccount`: 8 discriminator + 32 user + 1 role +
 * 1 permission + 32 rent_payer + 1 bump = 75 bytes.
 */
function decodeRoleAccount(data: Buffer): RoleAccountData {
  if (!data.subarray(0, 8).equals(ROLE_ACCOUNT_DISCRIMINATOR)) {
    throw new Error("Account is not a RoleAccount (discriminator mismatch)");
  }
  return {
    user: new PublicKey(data.subarray(8, 40)),
    role: data[40] as Role,
    permission: data[41] as AccessPermission,
    rentPayer: new PublicKey(data.subarray(42, 74)),
    bump: data[74],
  };
}

/** Read a (user, role) assignment, or null when the role isn't assigned. */
async function fetchRoleAccount(
  user: PublicKey,
  role: Role,
): Promise<RoleAccountData | null> {
  const info = await connection.getAccountInfo(roleAccountPda(user, role));
  if (!info) return null;
  return decodeRoleAccount(info.data);
}

// ── Instruction building ────────────────────────────────────────────────

/**
 * Build an instruction from the IDL: discriminator + account metas in the
 * declared order. Accounts with a fixed `address` in the IDL (the system
 * program) are filled in automatically; everything else comes from
 * `accounts`, keyed by the IDL's snake_case account name.
 */
function buildInstruction(
  name: string,
  accounts: Record<string, PublicKey>,
  args: Buffer = Buffer.alloc(0),
): TransactionInstruction {
  const spec = IDL.instructions.find((i) => i.name === name);
  if (!spec) throw new Error(`Instruction ${name} not found in IDL`);

  const keys = spec.accounts.map((account) => {
    const pubkey =
      accounts[account.name] ??
      (account.address ? new PublicKey(account.address) : undefined);
    if (!pubkey) {
      throw new Error(`Missing account "${account.name}" for ${name}`);
    }
    return {
      pubkey,
      isSigner: !!account.signer,
      isWritable: !!account.writable,
    };
  });

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys,
    data: Buffer.concat([Buffer.from(spec.discriminator), args]),
  });
}

/** assign_role(role) — creates the role account, admin pays its rent. */
function assignRoleIx(user: PublicKey, role: Role): TransactionInstruction {
  const admin = getAdmin().publicKey;
  return buildInstruction(
    "assign_role",
    {
      admin_signer: admin,
      admin: adminPda(admin),
      user,
      role_account: roleAccountPda(user, role),
    },
    Buffer.from([role]),
  );
}

/**
 * remove_role(role) — closes the role account. The rent refund is pinned to
 * whoever paid at assignment, so it has to be read off the account first.
 */
function removeRoleIx(
  user: PublicKey,
  role: Role,
  rentPayer: PublicKey,
): TransactionInstruction {
  const admin = getAdmin().publicKey;
  return buildInstruction(
    "remove_role",
    {
      admin_signer: admin,
      admin: adminPda(admin),
      user,
      rent_payer: rentPayer,
      role_account: roleAccountPda(user, role),
    },
    Buffer.from([role]),
  );
}

/** set_permission(role, permission) — flip a user's compliance status. */
function setPermissionIx(
  user: PublicKey,
  role: Role,
  permission: AccessPermission,
): TransactionInstruction {
  const admin = getAdmin().publicKey;
  return buildInstruction(
    "set_permission",
    {
      admin_signer: admin,
      admin: adminPda(admin),
      user,
      role_account: roleAccountPda(user, role),
    },
    Buffer.from([role, permission]),
  );
}

// ── Transaction dispatch ────────────────────────────────────────────────

/** Turn an on-chain failure into something readable in the logs. */
function describeError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const match = message.match(/custom program error: (0x[0-9a-fA-F]+)/);
  if (match) {
    const code = parseInt(match[1], 16);
    const known = IDL.errors.find((e) => e.code === code);
    if (known) return `${message} (${known.name}: ${known.msg})`;
  }
  return message;
}

/**
 * Program logs carry the useful half of an Anchor failure (the error name and
 * the source line), but web3.js only fetches them on demand.
 */
async function collectLogs(err: unknown): Promise<string[] | null> {
  const candidate = err as {
    logs?: string[];
    getLogs?: (c: Connection) => Promise<string[] | null>;
  };
  if (candidate?.logs?.length) return candidate.logs;
  if (typeof candidate?.getLogs !== "function") return null;
  try {
    return await candidate.getLogs(connection);
  } catch {
    return null;
  }
}

/**
 * Send one transaction holding every instruction. Solana executes a
 * transaction atomically, so either all of the instructions land or none
 * of them do.
 */
async function submitTransaction(
  instructions: TransactionInstruction[],
  label: string,
): Promise<string> {
  const admin = getAdmin();
  const tx = new Transaction().add(...instructions);
  tx.feePayer = admin.publicKey;

  try {
    const signature = await sendAndConfirmTransaction(connection, tx, [admin], {
      commitment: "confirmed",
      maxRetries: 3,
    });
    logger.info(
      { label, signature, instructionCount: instructions.length },
      "Transaction confirmed",
    );
    return signature;
  } catch (err) {
    const logs = await collectLogs(err);
    throw new Error(
      `${label}: ${describeError(err)}${logs?.length ? `\n${logs.join("\n")}` : ""}`,
    );
  }
}

// ── Role management ─────────────────────────────────────────────────────

/** Assign a role to a user (starts Compliant). */
async function assignRole(user: PublicKey, role: Role): Promise<string> {
  return submitTransaction([assignRoleIx(user, role)], "assign_role");
}

/** Remove a role from a user, refunding rent to the original payer. */
async function removeRole(user: PublicKey, role: Role): Promise<string> {
  const existing = await fetchRoleAccount(user, role);
  if (!existing) throw new Error("Role is not assigned");
  return submitTransaction(
    [removeRoleIx(user, role, existing.rentPayer)],
    "remove_role",
  );
}

/** Set a user's compliance status for a role. */
async function setPermission(
  user: PublicKey,
  role: Role,
  permission: AccessPermission,
): Promise<string> {
  return submitTransaction(
    [setPermissionIx(user, role, permission)],
    "set_permission",
  );
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
  // user's role. Acknowledge everything else with 200 so Sumsub stops
  // retrying. Payloads without a `type` (legacy/custom callers and the local
  // test) fall through to the heuristic below.
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

  const role = KYC_LEVEL_ROLE_MAP[levelName];
  const roleName = role !== undefined ? ROLE_NAMES[role] : null;

  const accountAddress = extractWalletAddress(body);
  if (!accountAddress) {
    logger.warn({ caseId }, "No wallet address found in payload, skipping");
    return;
  }

  // Validate the address up front so we never send a transaction that can
  // only fail, and so a typo'd address is visible in the logs.
  let user: PublicKey;
  try {
    user = new PublicKey(accountAddress);
  } catch {
    logger.warn(
      { caseId, accountAddress },
      "Wallet address is not a valid Solana public key, skipping",
    );
    return;
  }

  try {
    if (isApproved) {
      await handleApproved(user, role, roleName);
    } else {
      await handleRejected(user, role, roleName);
    }
  } catch (err) {
    logger.error(
      { err: describeError(err), user: user.toBase58(), role: roleName },
      "Failed to apply KYC result on-chain",
    );
  }
}

/**
 * Approved: make sure the user holds the mapped role and is marked
 * Compliant, then (optionally) drip some SOL. Both instructions ride in one
 * transaction so they land together or not at all.
 */
async function handleApproved(
  user: PublicKey,
  role: Role | undefined,
  roleName: string | null,
): Promise<void> {
  const instructions: TransactionInstruction[] = [];

  if (role === undefined) {
    logger.warn(
      { user: user.toBase58() },
      "KYC level is not in KYC_LEVEL_ROLE_MAP, no role assigned",
    );
  } else {
    const existing = await fetchRoleAccount(user, role);

    if (!existing) {
      // Not assigned yet — assign_role creates the account as Compliant.
      instructions.push(assignRoleIx(user, role));
    } else if (existing.permission === AccessPermission.Revoked) {
      // Previously revoked (a failed review, or a manual revocation) — the
      // role account already exists, so re-assigning would fail. Flip the
      // compliance flag back instead.
      instructions.push(setPermissionIx(user, role, AccessPermission.Compliant));
    } else {
      logger.info(
        { user: user.toBase58(), role: roleName },
        "Role already assigned and compliant, nothing to do",
      );
    }
  }

  if (FAUCET_SOL_LAMPORTS > 0) {
    instructions.push(
      SystemProgram.transfer({
        fromPubkey: getAdmin().publicKey,
        toPubkey: user,
        lamports: FAUCET_SOL_LAMPORTS,
      }),
    );
  }

  if (instructions.length === 0) return;

  const signature = await submitTransaction(instructions, "approved");
  logger.info(
    {
      user: user.toBase58(),
      role: roleName,
      lamports: FAUCET_SOL_LAMPORTS || undefined,
      signature,
    },
    "Approved flow executed",
  );
}

/**
 * Rejected: revoke the user's compliance for the mapped role, or remove the
 * role outright when REJECTED_ROLE_ACTION=remove.
 */
async function handleRejected(
  user: PublicKey,
  role: Role | undefined,
  roleName: string | null,
): Promise<void> {
  if (role === undefined) {
    logger.warn(
      { user: user.toBase58() },
      "KYC level is not in KYC_LEVEL_ROLE_MAP, nothing to revoke",
    );
    return;
  }

  const existing = await fetchRoleAccount(user, role);
  if (!existing) {
    logger.info(
      { user: user.toBase58(), role: roleName },
      "Role is not assigned, nothing to revoke",
    );
    return;
  }

  if (REJECTED_ROLE_ACTION === "remove") {
    const signature = await submitTransaction(
      [removeRoleIx(user, role, existing.rentPayer)],
      "remove_role",
    );
    logger.info(
      { user: user.toBase58(), role: roleName, signature },
      "Role removed",
    );
    return;
  }

  if (existing.permission === AccessPermission.Revoked) {
    logger.info(
      { user: user.toBase58(), role: roleName },
      "Role is already revoked, nothing to do",
    );
    return;
  }

  const signature = await submitTransaction(
    [setPermissionIx(user, role, AccessPermission.Revoked)],
    "set_permission",
  );
  logger.info(
    { user: user.toBase58(), role: roleName, signature },
    "Role permission set to Revoked",
  );
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
    // attacker who learns the URL could forge an "approved" event and get
    // themselves whitelisted, so it is strongly recommended in production.
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
  let admin: string | null = null;
  try {
    admin = getAdmin().publicKey.toBase58();
  } catch {
    admin = null;
  }

  res.status(200).json({
    status: "ok",
    cluster: detectedCluster,
    programId: PROGRAM_ID.toBase58(),
    admin,
    adminIsRegistered,
  });
});

// ── Startup preflight ──────────────────────────────────────────────────
//
// Everything here is diagnostics: which cluster the RPC actually points at,
// whether the configured key is a registered whitelist admin, and whether it
// can pay for account rent. Getting any of these wrong makes every
// assign_role fail, and the failure is much easier to read at boot than
// buried in a webhook error.
async function preflight(): Promise<void> {
  try {
    const genesisHash = await connection.getGenesisHash();
    detectedCluster = CLUSTER_BY_GENESIS_HASH[genesisHash] || genesisHash;
  } catch (err) {
    logger.warn({ err: describeError(err) }, "Could not reach the Solana RPC");
  }

  let admin: Keypair;
  try {
    admin = getAdmin();
  } catch (err) {
    logger.error(
      { err: describeError(err) },
      "Admin keypair is unavailable — no on-chain action can be taken",
    );
    return;
  }

  logger.info(
    {
      cluster: detectedCluster,
      programId: PROGRAM_ID.toBase58(),
      config: configPda().toBase58(),
      admin: admin.publicKey.toBase58(),
      rejectedRoleAction: REJECTED_ROLE_ACTION,
      faucetLamports: FAUCET_SOL_LAMPORTS,
    },
    "Solana client ready",
  );

  try {
    const [adminAccount, balance] = await Promise.all([
      connection.getAccountInfo(adminPda(admin.publicKey)),
      connection.getBalance(admin.publicKey),
    ]);

    adminIsRegistered = adminAccount !== null;
    if (!adminIsRegistered) {
      logger.error(
        { admin: admin.publicKey.toBase58(), adminPda: adminPda(admin.publicKey).toBase58() },
        "ADMIN_PRIVATE_KEY is NOT a registered whitelist admin — every " +
          "assign_role will fail. Register it with add_admin, signed by the " +
          "sudo authority in the program config.",
      );
    }

    if (balance === 0) {
      logger.error(
        { admin: admin.publicKey.toBase58() },
        "Admin account has a zero SOL balance — it pays fees and role account rent",
      );
    } else {
      logger.info(
        { admin: admin.publicKey.toBase58(), sol: balance / LAMPORTS_PER_SOL },
        "Admin balance",
      );
    }
  } catch (err) {
    logger.warn({ err: describeError(err) }, "Admin preflight check failed");
  }
}

// ── Start server ──────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  logger.info(`Sumsub webhook server listening on port ${PORT}`);
  if (!SUMSUB_SECRET) {
    logger.warn(
      "SUMSUB_SECRET is not set — webhook signatures are NOT verified. " +
        "Set it in production so forged requests cannot whitelist arbitrary wallets.",
    );
  }
  void preflight();
});

async function gracefulShutdown() {
  logger.info("Shutting down…");
  server.close(() => {
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
  buildInstruction,
  assignRoleIx,
  removeRoleIx,
  setPermissionIx,
  fetchRoleAccount,
  roleAccountPda,
  adminPda,
  configPda,
  Role,
  AccessPermission,
  PROGRAM_ID,
  KYC_LEVEL_ROLE_MAP,
};
