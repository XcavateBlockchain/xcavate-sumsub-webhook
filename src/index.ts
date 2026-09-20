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
import {
  createAssociatedTokenAccountIdempotentInstructionWithDerivation,
  createTransferInstruction,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
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

/**
 * RPC endpoint resolution, in order:
 *
 *  1. `SOLANA_RPC_URL` — an explicit endpoint always wins, so a self-hosted
 *     or third-party node can be pointed at without touching anything else.
 *  2. `ALCHEMY_API_KEY` — the normal setup. The endpoint is built for
 *     `SOLANA_CLUSTER` (devnet unless set).
 *  3. The public `api.<cluster>.solana.com` endpoint, as a last resort. It is
 *     rate limited hard enough that it will drop webhook traffic in
 *     production — the boot log says so when we land here.
 *
 * Note the truthiness checks: the deploy workflow writes every variable into
 * `.env`, so an unset GitHub secret arrives as an empty string, not as undefined.
 */
const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY || "";
const SOLANA_CLUSTER = process.env.SOLANA_CLUSTER || "devnet";

/** Alchemy's network slug per Solana cluster. Alchemy has no testnet node. */
const ALCHEMY_NETWORK_BY_CLUSTER: Record<string, string> = {
  devnet: "solana-devnet",
  mainnet: "solana-mainnet",
  "mainnet-beta": "solana-mainnet",
};

function resolveRpcUrl(): { url: string; source: string } {
  if (process.env.SOLANA_RPC_URL) {
    return { url: process.env.SOLANA_RPC_URL, source: "SOLANA_RPC_URL" };
  }

  const publicUrl = `https://api.${SOLANA_CLUSTER}.solana.com`;

  if (ALCHEMY_API_KEY) {
    const network = ALCHEMY_NETWORK_BY_CLUSTER[SOLANA_CLUSTER];
    if (network) {
      return {
        url: `https://${network}.g.alchemy.com/v2/${ALCHEMY_API_KEY}`,
        source: "Alchemy",
      };
    }
    logger.error(
      { cluster: SOLANA_CLUSTER, supported: Object.keys(ALCHEMY_NETWORK_BY_CLUSTER) },
      "Alchemy has no endpoint for this SOLANA_CLUSTER — falling back to the " +
        "public RPC. Set SOLANA_RPC_URL explicitly to use another provider.",
    );
  }

  return { url: publicUrl, source: "public RPC (rate limited)" };
}

const { url: SOLANA_RPC_URL, source: SOLANA_RPC_SOURCE } = resolveRpcUrl();

/** Host only — the Alchemy API key lives in the URL path and must not be logged. */
const SOLANA_RPC_HOST = (() => {
  try {
    return new URL(SOLANA_RPC_URL).host;
  } catch {
    return "invalid-url";
  }
})();

/** Strip the Alchemy key out of anything headed for a log or an HTTP response. */
function redactSecrets(text: string): string {
  return ALCHEMY_API_KEY ? text.split(ALCHEMY_API_KEY).join("***") : text;
}

const ADMIN_PRIVATE_KEY = process.env.ADMIN_PRIVATE_KEY || "";
const SUMSUB_SECRET = process.env.SUMSUB_SECRET || "";
const PORT = parseInt(process.env.PORT || "8005", 10);

// ── tgbp.io customer registration & Sumsub share tokens ────────────────
//
// When an applicant is approved, after the on-chain role + airdrop have
// confirmed, the webhook also registers them as a customer on tgbp.io.
// tgbp.io pulls the KYC data through Sumsub Reusable KYC: this service
// mints a share token for the applicant (our Sumsub client is the donor,
// tgbp.io's Sumsub client is the recipient, named by
// SUMSUB_RECIPIENT_CLIENT_ID) and hands the token to the registration call.
// All three knobs must be set for the feature to run; otherwise approvals
// are handled on-chain only and the gap is logged at boot.
const TGBP_API_BASE_URL = (
  process.env.TGBP_API_BASE_URL || "https://sandbox.tgbp.io"
).replace(/\/+$/, "");
const TGBP_API_KEY = process.env.TGBP_API_KEY || "";
const SUMSUB_APP_TOKEN = process.env.SUMSUB_APP_TOKEN || "";
const SUMSUB_APP_TOKEN_SECRET = process.env.SUMSUB_APP_TOKEN_SECRET || "";
const SUMSUB_RECIPIENT_CLIENT_ID =
  process.env.SUMSUB_RECIPIENT_CLIENT_ID || "";
const SUMSUB_SHARE_TOKEN_TTL_SECS =
  parseInt(process.env.SUMSUB_SHARE_TOKEN_TTL || "1200", 10) || 1200;

/**
 * Feature switch — derived so a half-configured env can't produce a
 * confusing 401/403 loop. SUMSUB_APP_TOKEN_SECRET is the secret key Sumsub
 * shows alongside the app token when it is created; every Sumsub API request
 * is signed with it, so the token alone is not enough to call the API.
 */
const TGBP_REGISTRATION_ENABLED =
  TGBP_API_KEY !== "" &&
  SUMSUB_APP_TOKEN !== "" &&
  SUMSUB_APP_TOKEN_SECRET !== "" &&
  SUMSUB_RECIPIENT_CLIENT_ID !== "";

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

/**
 * Airdrop for newly approved users, paid from the admin account: 0.01 SOL
 * plus 10000 tGBP (the devnet tGBP SPL token below). It rides in its own
 * transaction — Solana executes transactions atomically, so bundling it with
 * the role instruction would let a failed transfer (e.g. the admin's tGBP
 * balance running out) roll the role assignment back, which must not happen.
 * A failed airdrop is logged and dropped; the role change has confirmed by
 * then.
 */
const AIRDROP_SOL_LAMPORTS = Math.round(0.01 * LAMPORTS_PER_SOL);
const AIRDROP_TGBP_AMOUNT = 10_000;
const TGBP_MINT = new PublicKey(
  "71G3dc4B9p9QBosLx3XhWY3ULRPAxjopngsin66M9HUb",
);

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
//     "applicantId": "5cb56e8e0a975a35f333cb83",
//     "inspectionId": "5cb56e8e0a975a35f333cb84",
//     "applicantType": "individual",
//     "correlationId": "req-a260b669-4f14-4bb5-a4c5-ac0218acb9a4",
//     "externalUserId": "<wallet address>",
//     "levelName": "csharp-verification-investor",
//     "type": "applicantReviewed",
//     "sandboxMode": false,
//     "reviewResult": { "reviewAnswer": "GREEN" | "RED", ... },
//     "reviewStatus": "completed",
//     "createdAtMs": "2020-02-21 13:23:19.321",
//     "clientId": "coolClientId"
//   }
// This is the only shape the service accepts.
interface SumsubReviewResult {
  reviewAnswer?: string;
  reviewRejectType?: string;
  rejectLabels?: string[];
  moderationComment?: string;
  clientComment?: string;
}

interface SumsubPayload {
  type?: string;
  applicantId?: string;
  inspectionId?: string;
  applicantType?: string;
  correlationId?: string;
  externalUserId?: string;
  levelName?: string;
  reviewStatus?: string;
  reviewResult?: SumsubReviewResult;
  sandboxMode?: boolean;
  createdAtMs?: string;
  clientId?: string;
}

// ── Solana connection & admin signer ────────────────────────────────────

const connection = new Connection(SOLANA_RPC_URL, "confirmed");

/** Genesis hashes, used to report which cluster we actually ended up on. */
const CLUSTER_BY_GENESIS_HASH: Record<string, string> = {
  "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d": "mainnet-beta",
  "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG": "devnet",
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

/**
 * Idempotently create `owner`'s associated token account for `mint` — a
 * no-op when the account already exists. Without it a first-time user's
 * tGBP transfer has no destination account to land in. The admin pays the
 * rent and signs the transaction.
 */
function createAtaIx(mint: PublicKey, owner: PublicKey): TransactionInstruction {
  return createAssociatedTokenAccountIdempotentInstructionWithDerivation(
    getAdmin().publicKey,
    owner,
    mint,
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
  // Redacted: transport errors quote the endpoint they failed on, which
  // carries the Alchemy API key.
  let message = redactSecrets(err instanceof Error ? err.message : String(err));
  // Node's fetch (undici) wraps network-level failures (DNS, TCP, TLS) in a
  // bare `fetch failed`; the real reason — ENOTFOUND, ECONNRESET, a timeout —
  // only lives in `cause`, so append it or the log is a dead end.
  const cause = (err as { cause?: unknown } | null)?.cause;
  if (cause instanceof Error && cause.message) {
    const code = (cause as { code?: string }).code;
    message += redactSecrets(` (cause: ${code ? `${code} — ` : ""}${cause.message})`);
  }
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

// ── Token airdrop ───────────────────────────────────────────────────────

/** tGBP mint decimals — fetched lazily, cached for the process lifetime. */
let tgbpDecimals: number | null = null;

async function fetchTgbpDecimals(): Promise<number> {
  if (tgbpDecimals === null) {
    const { value } = await connection.getTokenSupply(TGBP_MINT);
    tgbpDecimals = value.decimals;
  }
  return tgbpDecimals;
}

/**
 * Airdrop 0.01 SOL + 10000 tGBP to `user`, one atomic transaction: SOL
 * transfer, idempotent creation of the user's token account, and the tGBP
 * transfer out of the admin's own associated token account, which must hold
 * at least `AIRDROP_TGBP_AMOUNT` tGBP.
 */
async function airdropTokens(user: PublicKey): Promise<string> {
  const admin = getAdmin().publicKey;
  const decimals = await fetchTgbpDecimals();
  const amount = BigInt(AIRDROP_TGBP_AMOUNT) * 10n ** BigInt(decimals);

  return submitTransaction(
    [
      SystemProgram.transfer({
        fromPubkey: admin,
        toPubkey: user,
        lamports: AIRDROP_SOL_LAMPORTS,
      }),
      createAtaIx(TGBP_MINT, user),
      createTransferInstruction(
        getAssociatedTokenAddressSync(TGBP_MINT, admin),
        getAssociatedTokenAddressSync(TGBP_MINT, user),
        admin,
        amount,
      ),
    ],
    "airdrop",
  );
}

// ── tgbp.io customer registration ───────────────────────────────────────

// Sumsub runs a single API host (api.sumsub.com) for both production and
// sandbox. The two environments are separated by the app token itself:
// a token created in the sandbox dashboard only resolves sandbox
// applicants, and vice versa. There is no `api.sandbox.sumsub.com`
// host — it does not exist in DNS.
const SUMSUB_API_BASE = "https://api.sumsub.com";

/**
 * tgbp.io customer-registration endpoint.
 *
 * Confirmed against the tgbp.io API reference (local HTML copy): the body is
 * a `CustomerCreateRequest` where `type: "individual"` is the required
 * discriminator and the individual variant needs an `email` plus either a
 * `name` or both `first_name` and `last_name`. The Sumsub field is the
 * snake_case `sumsub_share_token` (tgbp.io ingests the KYC data from Sumsub
 * itself once it has the token); there is no wallet field in the create
 * body. Auth is the `x-api-key` header for server-to-server calls.
 */
const TGBP_CUSTOMERS_PATH = "/api/v1/customers";

/**
 * Make a signed request against the Sumsub Resource API.
 *
 * Sumsub does not accept the raw app token in the `Authorization` header —
 * that is exactly what produces the `403 "Unauthorized (cfb)"` response.
 * Every request must carry three headers instead:
 *
 * - `X-App-Token` — the app token itself
 * - `X-App-Access-Ts` — unix timestamp in seconds (UTC), must be within a
 *   minute of Sumsub's server time
 * - `X-App-Access-Sig` — HMAC-SHA256, lowercase hex, keyed with the app
 *   token's SECRET KEY (SUMSUB_APP_TOKEN_SECRET) over the concatenation
 *   `timestamp + METHOD (uppercase) + /path(+query) + body`. `body` is the
 *   exact byte sequence sent — the empty string for GET.
 *
 * Docs: https://docs.sumsub.com/sumsub/reference/authentication
 *
 * The signed message is built from the same `body` string that is sent, so
 * signature and wire bytes match by construction.
 */
// Return type is inferred (global fetch Response): an explicit `Response`
// annotation would resolve to the Express type imported at the top of this
// file.
async function sumsubFetch(
  method: "GET" | "POST",
  path: string,
  bodyObj?: unknown,
) {
  const body = bodyObj === undefined ? "" : JSON.stringify(bodyObj);
  const ts = Math.floor(Date.now() / 1000);
  const sig = crypto
    .createHmac("sha256", SUMSUB_APP_TOKEN_SECRET)
    .update(`${ts}${method}${path}${body}`)
    .digest("hex");

  const headers: Record<string, string> = {
    "X-App-Token": SUMSUB_APP_TOKEN,
    "X-App-Access-Ts": String(ts),
    "X-App-Access-Sig": sig,
  };
  if (body) headers["content-type"] = "application/json";

  return fetch(`${SUMSUB_API_BASE}${path}`, {
    method,
    headers,
    body: body || undefined,
    signal: AbortSignal.timeout(30_000),
  });
}

/**
 * Mint a Reusable KYC share token for `applicantId`.
 *
 * Sumsub endpoint: `POST /resources/accessTokens/shareToken`, authenticated
 * with the signed header scheme (see `sumsubFetch`). `forClientId` names
 * tgbp.io's Sumsub client as the recipient; with that token tgbp.io can
 * ingest the applicant's KYC data on its side. Sandbox and production share
 * the same host — the app token itself selects the universe.
 *
 * Permission: the app token's role must include the "Share applicants data"
 * dashboard permission (Reusable Identity group). Without it Sumsub answers
 * 403 "User not authorized" — a permission error, not a signing failure
 * (a bad signature or unknown token is a 401, and Reusable-KYC domain
 * errors carry an `errorCode`, which this response does not). Token
 * permissions are fixed at creation and cannot be edited afterwards, so the
 * remedy is a freshly generated token — the 403 branch below says so in the
 * log.
 * Docs: https://docs.sumsub.com/reference/generate-share-token
 */
async function fetchSumsubShareToken(applicantId: string): Promise<string> {
  const res = await sumsubFetch("POST", "/resources/accessTokens/shareToken", {
    applicantId,
    forClientId: SUMSUB_RECIPIENT_CLIENT_ID,
    ttlInSecs: SUMSUB_SHARE_TOKEN_TTL_SECS,
  });

  const text = await res.text();
  if (!res.ok) {
    if (res.status === 403) {
      throw new Error(
        `Sumsub share token request failed (403 "User not authorized"): ` +
          `the SUMSUB_APP_TOKEN role does not have the "Share applicants data" ` +
          `permission (Reusable Identity group), which this endpoint requires. ` +
          `App token permissions are fixed at creation and cannot be changed ` +
          `afterwards — generate a NEW app token in the Sumsub Dashboard ` +
          `(Dev space → App Tokens → Generate app token, in the same mode your ` +
          `KYC flow runs in) with "Share applicants data" checked, then update ` +
          `the SUMSUB_APP_TOKEN and SUMSUB_APP_TOKEN_SECRET secrets and redeploy. ` +
          `Sumsub response: ${text.slice(0, 300)}`,
      );
    }
    throw new Error(
      `Sumsub share token request failed (${res.status}): ${text.slice(0, 20000)}`,
    );
  }

  const { token } = JSON.parse(text) as { token?: string };
  if (!token) {
    throw new Error("Sumsub share token response has no `token` field");
  }
  return token;
}

/** KYC applicant details we need for the tgbp.io customer body. */
interface ApplicantDetails {
  email?: string;
  firstName?: string;
  lastName?: string;
  dob?: string;
  phone?: string;
  /** Primary identity document, mapped onto the tgbp.io document fields. */
  idDoc?: {
    type?: string;
    number?: string;
    issuingCountryAlpha2?: string;
    validUntil?: string;
  };
  /** How many ID documents the applicant has on record (0 = nothing to share). */
  idDocCount: number;
}

/**
 * Sumsub document types → tgbp.io `document_type` enum
 * (`passport`, `driving_license`, `national_id`, `other`).
 */
const TGBP_DOC_TYPE_BY_SUMSUB: Record<string, string> = {
  PASSPORT: "passport",
  DRIVERS: "driving_license",
  ID_CARD: "national_id",
};

/**
 * Sumsub reports countries as ISO 3166-1 alpha-3; tgbp.io wants alpha-2.
 * Covers the common issuing countries — an unmapped code omits the optional
 * field rather than risking a 400 by sending a wrong-format value.
 */
const ALPHA3_TO_ALPHA2: Record<string, string> = {
  GBR: "GB", USA: "US", IRL: "IE", FRA: "FR", DEU: "DE", ESP: "ES",
  ITA: "IT", PRT: "PT", NLD: "NL", BEL: "BE", LUX: "LU", CHE: "CH",
  AUT: "AT", POL: "PL", CZE: "CZ", SVK: "SK", HUN: "HU", ROU: "RO",
  BGR: "BG", GRC: "GR", HRV: "HR", SVN: "SI", EST: "EE", LVA: "LV",
  LTU: "LT", FIN: "FI", SWE: "SE", NOR: "NO", DNK: "DK", ISL: "IS",
  MLT: "MT", CYP: "CY", UKR: "UA", TUR: "TR", ARE: "AE", SAU: "SA",
  QAT: "QA", ISR: "IL", IND: "IN", PAK: "PK", CHN: "CN", HKG: "HK",
  SGP: "SG", JPN: "JP", KOR: "KR", TWN: "TW", THA: "TH", MYS: "MY",
  IDN: "ID", PHL: "PH", VNM: "VN", AUS: "AU", NZL: "NZ", CAN: "CA",
  MEX: "MX", BRA: "BR", ARG: "AR", COL: "CO", PER: "PE", CHL: "CL",
  ZAF: "ZA", NGA: "NG", KEN: "KE", GHA: "GH", EGY: "EG", MAR: "MA",
  JEY: "JE", GGY: "GG", IMN: "IM", GIB: "GI", MCO: "MC", LIE: "LI",
  ALB: "AL", SRB: "RS", MNE: "ME", BIH: "BA", MKD: "MK", GEO: "GE",
  ARM: "AM", AZE: "AZ", KAZ: "KZ", UZB: "UZ", LKA: "LK", BGD: "BD",
  PAN: "PA", CRI: "CR", DOM: "DO", CYM: "KY", VGB: "VG", BMU: "BM",
};

function toAlpha2(country: string | undefined): string | undefined {
  if (!country) return undefined;
  if (/^[A-Z]{2}$/.test(country)) return country;
  return ALPHA3_TO_ALPHA2[country.toUpperCase()];
}

/**
 * Fetch the applicant's contact and document details from the Sumsub Resource
 * API. The `applicantReviewed` webhook payload doesn't carry them, and the
 * tgbp.io create body needs an email (plus a name) on top of the share token.
 * Endpoint: `GET /resources/applicants/{id}/one`, authenticated with the
 * signed header scheme (see `sumsubFetch`). In the response the email sits
 * at the root level while the names are nested under `fixedInfo` (`info`
 * as fallback). The verified document list lives at `info.idDocs` — per the
 * tgbp.io API reference, document metadata (type, number, expiry, …) is NOT
 * imported by the share token and "should still be sent as normal fields",
 * so it is extracted here too; the document IMAGES cross via the token.
 */
async function fetchSumsubApplicantDetails(
  applicantId: string,
): Promise<ApplicantDetails> {
  const path = `/resources/applicants/${applicantId}/one`;
  const res = await sumsubFetch("GET", path);

  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `Sumsub applicant details request failed (${res.status} on ${path}): ${text.slice(0, 300)}`,
    );
  }

  interface SumsubIdDoc {
    idDocType?: unknown;
    number?: unknown;
    country?: unknown;
    validUntil?: unknown;
  }
  const data = JSON.parse(text) as {
    email?: unknown;
    phone?: unknown;
    fixedInfo?: {
      firstName?: unknown;
      lastName?: unknown;
      dob?: unknown;
      phone?: unknown;
      idDocs?: unknown;
    };
    info?: {
      firstName?: unknown;
      lastName?: unknown;
      dob?: unknown;
      phone?: unknown;
      idDocs?: unknown;
    };
  };
  const pick = (...values: unknown[]): string | undefined => {
    for (const value of values) {
      if (typeof value === "string" && value.trim()) return value.trim();
    }
    return undefined;
  };

  // `info` holds the verified results (from the documents), `fixedInfo` the
  // applicant-supplied input — prefer verified data for dob and documents.
  const idDocs = (
    Array.isArray(data.info?.idDocs) && data.info.idDocs.length > 0
      ? data.info.idDocs
      : Array.isArray(data.fixedInfo?.idDocs)
        ? data.fixedInfo.idDocs
        : []
  ) as SumsubIdDoc[];
  // The customer record takes one document — prefer the passport.
  const primary =
    idDocs.find((d) => d.idDocType === "PASSPORT") ?? idDocs[0];

  return {
    email: pick(data.email),
    firstName: pick(data.fixedInfo?.firstName, data.info?.firstName),
    lastName: pick(data.fixedInfo?.lastName, data.info?.lastName),
    dob: pick(data.info?.dob, data.fixedInfo?.dob),
    phone: pick(data.phone, data.info?.phone, data.fixedInfo?.phone),
    idDoc: primary
      ? {
          type: TGBP_DOC_TYPE_BY_SUMSUB[pick(primary.idDocType) ?? ""] ?? "other",
          number: pick(primary.number),
          issuingCountryAlpha2: toAlpha2(pick(primary.country)),
          validUntil: pick(primary.validUntil),
        }
      : undefined,
    idDocCount: idDocs.length,
  };
}

/**
 * Register the KYC'd applicant as a customer on tgbp.io. The body follows
 * the `CustomerCreateRequest` from the tgbp.io API reference: `type`
 * discriminates the variant, individuals need an `email` plus either a
 * `name` or both `first_name` and `last_name`, and the snake_case
 * `sumsub_share_token` lets tgbp.io pull the KYC data from Sumsub itself.
 * There is no wallet field.
 *
 * `metadata.sumsub_applicant_id` records OUR (donor-side) Sumsub applicant
 * id on the customer: the onramp webview resolves a user to their tgbp.io
 * customer by exactly this field, and the share-token import is not
 * guaranteed to write the donor applicant id itself (the applicant created
 * in tgbp.io's own Sumsub account gets a different id). If the API rejects
 * the `metadata` field with a 400, the create is retried without it — the
 * registration must not fail over a field the API reference does not list.
 *
 * Success is a 201 with the customer in a `data` envelope
 * (`{ "data": { "id": "customer_…", "status": "pending", … } }`). The share
 * token import is fire-and-forget on tgbp.io's side: the imported result is
 * recorded as evidence and the customer stays `pending` until a check runs
 * in tgbp.io's own Sumsub account (a shared rejection marks the customer
 * `rejected` on sight).
 */
async function postTgbpCustomer(body: Record<string, unknown>) {
  const res = await fetch(`${TGBP_API_BASE_URL}${TGBP_CUSTOMERS_PATH}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": TGBP_API_KEY,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  return { res, text: await res.text() };
}

async function registerTgbpCustomer(
  details: ApplicantDetails & { email: string },
  shareToken: string,
  applicantId: string,
): Promise<void> {
  const body: Record<string, unknown> = {
    type: "individual",
    email: details.email,
    sumsub_share_token: shareToken,
    metadata: { sumsub_applicant_id: applicantId },
  };
  if (details.firstName && details.lastName) {
    body.first_name = details.firstName;
    body.last_name = details.lastName;
  } else {
    const single = details.firstName ?? details.lastName;
    if (single) body.name = single;
  }
  // The share token imports the document IMAGES and check results; the
  // customer record's own metadata fields are NOT imported (same rule as
  // the questionnaire fields the API reference calls out), so mirror them
  // here — the recurring-mint dossier gate requires e.g.
  // `document_expiration_date` on the customer row.
  if (details.dob) body.date_of_birth = details.dob;
  if (details.phone) body.phone = details.phone;
  if (details.idDoc) {
    if (details.idDoc.type) body.document_type = details.idDoc.type;
    if (details.idDoc.number) body.document_number = details.idDoc.number;
    if (details.idDoc.issuingCountryAlpha2) {
      body.document_issuing_country = details.idDoc.issuingCountryAlpha2;
    }
    if (details.idDoc.validUntil) {
      body.document_expiration_date = details.idDoc.validUntil;
    }
  }

  let { res, text } = await postTgbpCustomer(body);
  // The API reference does not list `metadata` on the create body: if the
  // server validates strictly and rejects it, register without it rather
  // than not at all. The onramp's Sumsub-id lookup then has to rely on
  // whatever the share-token import recorded — which is exactly the case
  // that made registrations unfindable, so say so loudly.
  if (res.status === 400 && text.includes("metadata")) {
    logger.warn(
      { applicantId },
      "tgbp.io rejected the customer `metadata` field (400) — retrying the " +
        "registration without it. The onramp may not be able to resolve " +
        "this customer by Sumsub applicant id.",
    );
    delete body.metadata;
    ({ res, text } = await postTgbpCustomer(body));
  }

  if (!res.ok) {
    // 400s carry the reason in the body — a machine-readable code like
    // `sumsub_sharing_not_enabled`, and/or `details.field_errors` naming the
    // offending fields.
    let fieldErrors = "";
    try {
      const parsed = JSON.parse(text) as {
        details?: { field_errors?: unknown };
      };
      if (parsed.details?.field_errors) {
        fieldErrors = ` — field_errors: ${JSON.stringify(parsed.details.field_errors)}`;
      }
    } catch {
      // Non-JSON error body — the raw slice below is all we have.
    }
 
    if (res.status === 400 && text.includes("sumsub_sharing_not_enabled")) {
      throw new Error(
        "tgbp.io customer registration failed (400 sumsub_sharing_not_enabled): " +
          "the client account behind TGBP_API_KEY has not enabled Sumsub " +
          "applicant sharing. Run scripts/enable-sumsub-sharing.sh once with " +
          "the same API key (it PATCHes /api/v1/clients/me with " +
          '{"sumsub_sharing_enabled": true}).',
      );
    }
    if (res.status === 401) {
      throw new Error(
        "tgbp.io customer registration failed (401): TGBP_API_KEY is missing, " +
          "wrong, or expired (sandbox keys are prefixed tgbp_sandbox_). " +
          `Response: ${text.slice(0, 300)}`,
      );
    }
    if (res.status === 429) {
      const retryAfter = res.headers.get("x-rate-limit-retry-after");
      throw new Error(
        "tgbp.io customer registration failed (429 rate limited)" +
          (retryAfter ? ` — retry after ${retryAfter}s` : "") +
          ". The next applicant event for this user retries the registration.",
      );
    }
    throw new Error(
      `tgbp.io customer registration failed (${res.status}): ${text.slice(0, 20000)}${fieldErrors}`,
    );
  }

  let customerId: string | null = null;
  let customerStatus: string | null = null;
  try {
    const parsed = JSON.parse(text) as {
      data?: { id?: unknown; status?: unknown };
      id?: unknown;
      status?: unknown;
    };
    const customer = parsed.data ?? parsed;
    if (typeof customer.id === "string") customerId = customer.id;
    if (typeof customer.status === "string") customerStatus = customer.status;
  } catch {
    // Non-JSON success body — the 2xx status is all we need.
  }
  logger.info(
    {
      customerId,
      customerStatus,
      applicantId,
      withMetadata: body.metadata !== undefined,
      idDocs: details.idDocCount,
      docType: details.idDoc?.type,
    },
    "Customer registered on tgbp.io",
  );
}

/**
 * Best-effort: fetch the applicant's details, mint the share token, then
 * register the customer. Run only after the on-chain role change has
 * confirmed, and never allowed to fail the webhook — a failed registration
 * is logged, and the customer can be created in the tgbp.io portal manually.
 * The sandbox/production universe is selected by SUMSUB_APP_TOKEN itself —
 * both point at the same Sumsub host.
 */
async function registerTgbpCustomerBestEffort(
  user: PublicKey,
  applicantId: string | undefined,
  _levelName: string,
): Promise<void> {
  if (!TGBP_REGISTRATION_ENABLED) {
    logger.debug(
      { wallet: user.toBase58() },
      "tgbp.io registration skipped — TGBP_API_KEY, SUMSUB_APP_TOKEN, " +
        "SUMSUB_APP_TOKEN_SECRET or SUMSUB_RECIPIENT_CLIENT_ID is not set",
    );
    return;
  }

  if (!applicantId) {
    logger.warn(
      { wallet: user.toBase58() },
      "tgbp.io registration skipped — no applicantId in webhook payload",
    );
    return;
  }

  try {
    const details = await fetchSumsubApplicantDetails(applicantId);
    const email = details.email;
    if (!email) {
      logger.warn(
        { wallet: user.toBase58(), applicantId },
        "tgbp.io registration skipped — the Sumsub applicant has no email address",
      );
      return;
    }
    // tgbp.io requires a `name` or a `first_name`/`last_name` pair — without
    // any name on the Sumsub record the create call can only fail with a 400.
    if (!details.firstName && !details.lastName) {
      logger.warn(
        { wallet: user.toBase58(), applicantId },
        "tgbp.io registration skipped — the Sumsub applicant has no name on record",
      );
      return;
    }
    // Not fatal — registration still proceeds — but the most common reason
    // tgbp.io "receives no documents": the donor applicant has none. Typical
    // in sandbox, where applicants get approved without real uploads.
    if (details.idDocCount === 0) {
      logger.warn(
        { wallet: user.toBase58(), applicantId },
        "The Sumsub applicant has NO ID documents on record — the share " +
          "token can only import profile data, no document images. Check " +
          "that the verification level collects documents and that the " +
          "applicant was approved with real uploads.",
      );
    }
    const shareToken = await fetchSumsubShareToken(applicantId);
    await registerTgbpCustomer({ ...details, email }, shareToken, applicantId);
  } catch (err) {
    logger.error(
      {
        err: describeError(err),
        wallet: user.toBase58(),
        applicantId,
      },
      "tgbp.io customer registration failed — the on-chain role is unaffected",
    );
  }
}

// ── Webhook processing ──────────────────────────────────────────────────

/**
 * Process one verified Sumsub event. Returns true when the event was fully
 * handled (including "acknowledged, nothing to do") and false when the
 * on-chain application of the result failed — Sumsub's redelivery of the
 * same event then gets to run it again. Never throws: failures are logged
 * here.
 */
async function processSumsubWebhook(body: SumsubPayload): Promise<boolean> {
  const eventType = body.type ?? "";
  const levelName = body.levelName ?? "";
  const reviewAnswer = body.reviewResult?.reviewAnswer;
  const caseId = body.applicantId;

  logger.info(
    { eventType, caseId, levelName, reviewAnswer },
    "Processing Sumsub webhook",
  );

  // Sumsub emits many event types, but only the final review decides a
  // user's role. Acknowledge everything else with 200 so Sumsub stops
  // retrying.
  if (eventType !== "applicantReviewed") {
    logger.info({ eventType }, "Non-decision event, acknowledging without action");
    return true;
  }

  // reviewResult.reviewAnswer === "GREEN" → approved, anything else → rejected.
  if (reviewAnswer === undefined) {
    logger.warn({ caseId }, "applicantReviewed without reviewResult, skipping");
    return true;
  }
  const isApproved = reviewAnswer === "GREEN";

  const role = KYC_LEVEL_ROLE_MAP[levelName];
  const roleName = role !== undefined ? ROLE_NAMES[role] : null;

  // The wallet address is carried in `externalUserId`, which you set when the
  // applicant is created and Sumsub echoes back on every event.
  const accountAddress = body.externalUserId;
  if (!accountAddress) {
    logger.warn({ caseId }, "No externalUserId in payload, skipping");
    return true;
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
    return true;
  }

  try {
    if (isApproved) {
      await handleApproved(user, role, roleName);
      // Off-chain, best-effort: only once the on-chain half has confirmed.
      // The Sumsub host is shared between sandbox and production — the
      // SUMSUB_APP_TOKEN itself selects the universe.
      await registerTgbpCustomerBestEffort(
        user,
        body.applicantId,
        levelName,
      );
    } else {
      await handleRejected(user, role, roleName);
    }
    return true;
  } catch (err) {
    logger.error(
      { err: describeError(err), user: user.toBase58(), role: roleName },
      "Failed to apply KYC result on-chain",
    );
    return false;
  }
}

/**
 * Approved: make sure the user holds the mapped role and is marked
 * Compliant — optionally with an extra SOL drip riding in the same
 * transaction so they land together or not at all. Then airdrop 0.01 SOL +
 * 10000 tGBP in a separate best-effort transaction (see `airdropTokens`).
 * The airdrop runs even when there was nothing to change on-chain (the role
 * was already assigned and compliant), so a repeated approval webhook still
 * pays out; the tgbp.io customer registration that follows in
 * processSumsubWebhook runs as well.
 */
async function handleApproved(
  user: PublicKey,
  role: Role | undefined,
  roleName: string | null,
): Promise<void> {
  const instructions: TransactionInstruction[] = [];
  let alreadyCompliant = false;

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
      alreadyCompliant = true;
      logger.info(
        { user: user.toBase58(), role: roleName },
        "Role already assigned and compliant — no on-chain change needed; " +
          "airdrop and tgbp.io registration still run",
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

  // Nothing to do on-chain and the role is not already compliant (i.e. the
  // KYC level has no mapped role and there is no faucet transfer) — preserve
  // the old no-op behavior. The tgbp.io registration still runs afterwards
  // in processSumsubWebhook.
  if (instructions.length === 0 && !alreadyCompliant) return;

  const signature =
    instructions.length === 0
      ? undefined
      : await submitTransaction(instructions, "approved");

  // Best-effort airdrop in its own transaction. It runs even when there was
  // no on-chain change (the role was already compliant); a failure is
  // logged and dropped — it cannot roll the assignment back or surface as a
  // webhook error.
  try {
    const airdropSignature = await airdropTokens(user);
    logger.info(
      {
        user: user.toBase58(),
        role: roleName,
        lamports: FAUCET_SOL_LAMPORTS || undefined,
        signature,
        airdropSignature,
      },
      signature
        ? "Approved flow executed"
        : "Role already compliant — airdrop executed anyway",
    );
  } catch (err) {
    logger.error(
      {
        err: describeError(err),
        user: user.toBase58(),
        role: roleName,
        signature,
      },
      signature
        ? "Airdrop failed — the role assignment already confirmed and is unaffected"
        : "Airdrop failed — role was already assigned and compliant",
    );
  }
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
app.post("/webhook/sumsub", (req: Request, res: Response) => {
  // Verify the HMAC signature when a secret is configured. Without this an
  // attacker who learns the URL could forge an "approved" event and get
  // themselves whitelisted, so it is strongly recommended in production.
  if (SUMSUB_SECRET) {
    if (!verifySumsubSignature(req)) {
      logger.warn("Invalid or missing Sumsub webhook signature");
      return res.status(401).json({ error: "Invalid signature" });
    }
  }

  // Acknowledge immediately and process in the background: the full pipeline
  // takes far longer than Sumsub's ~5s timeout, so answering only after
  // processing makes Sumsub retry deliveries that actually succeeded.
  // Duplicate deliveries are allowed: every redelivery runs the full
  // pipeline again — the on-chain role change is idempotent by
  // read-before-write, but the airdrop pays out and the tgbp.io
  // registration runs once per delivery.
  void processSumsubWebhook((req.body ?? {}) as SumsubPayload).catch((err) =>
    logger.error(err, "Error processing webhook"),
  );
  res.status(200).json({ status: "ok" });
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
    rpc: { host: SOLANA_RPC_HOST, source: SOLANA_RPC_SOURCE },
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

    // A cluster mismatch means every instruction is aimed at the wrong chain.
    // Only meaningful when SOLANA_CLUSTER is what built the endpoint, or when
    // it was set explicitly next to a hand-written SOLANA_RPC_URL.
    const expected =
      SOLANA_CLUSTER === "mainnet" ? "mainnet-beta" : SOLANA_CLUSTER;
    const clusterIsDeclared =
      SOLANA_RPC_SOURCE !== "SOLANA_RPC_URL" || !!process.env.SOLANA_CLUSTER;
    if (clusterIsDeclared && detectedCluster !== expected) {
      logger.warn(
        { expected, detected: detectedCluster, rpcHost: SOLANA_RPC_HOST },
        "The RPC endpoint serves a different cluster than SOLANA_CLUSTER says",
      );
    }
  } catch (err) {
    logger.warn(
      { err: describeError(err), rpcHost: SOLANA_RPC_HOST },
      "Could not reach the Solana RPC",
    );
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
      rpcHost: SOLANA_RPC_HOST,
      rpcSource: SOLANA_RPC_SOURCE,
      programId: PROGRAM_ID.toBase58(),
      config: configPda().toBase58(),
      admin: admin.publicKey.toBase58(),
      rejectedRoleAction: REJECTED_ROLE_ACTION,
      faucetLamports: FAUCET_SOL_LAMPORTS,
      airdrop: {
        sol: AIRDROP_SOL_LAMPORTS / LAMPORTS_PER_SOL,
        tgbp: AIRDROP_TGBP_AMOUNT,
        mint: TGBP_MINT.toBase58(),
      },
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

  // Airdrop funding: the tGBP mint must exist on this cluster and the
  // admin's associated token account must hold at least one airdrop's worth.
  // A short balance only breaks the best-effort airdrop — role assignments
  // are unaffected — but the failure is easier to read at boot than at the
  // first approval.
  try {
    const { value } = await connection.getTokenSupply(TGBP_MINT);
    tgbpDecimals = value.decimals;

    const adminAta = getAssociatedTokenAddressSync(TGBP_MINT, admin.publicKey);
    const ataInfo = await connection.getAccountInfo(adminAta);

    if (!ataInfo) {
      logger.error(
        { adminAta: adminAta.toBase58(), mint: TGBP_MINT.toBase58() },
        `Admin tGBP token account does not exist — every airdrop will fail ` +
          `(role assignments are unaffected). Send at least ${AIRDROP_TGBP_AMOUNT} ` +
          `tGBP to ${adminAta.toBase58()}.`,
      );
      return;
    }

    const { value: balance } = await connection.getTokenAccountBalance(adminAta);
    const available = Number(balance.uiAmountString ?? "0");

    if (available < AIRDROP_TGBP_AMOUNT) {
      logger.error(
        { adminAta: adminAta.toBase58(), available, required: AIRDROP_TGBP_AMOUNT },
        `Admin tGBP balance is below the ${AIRDROP_TGBP_AMOUNT} airdrop amount — ` +
          "every airdrop will fail (role assignments are unaffected).",
      );
    } else {
      logger.info(
        { adminAta: adminAta.toBase58(), tgbp: available, decimals: tgbpDecimals },
        "Admin tGBP balance",
      );
    }
  } catch (err) {
    logger.warn(
      { err: describeError(err), mint: TGBP_MINT.toBase58() },
      "tGBP airdrop preflight check failed",
    );
  }
}

// ── Start server ──────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  logger.info(`Sumsub webhook server listening on port ${PORT}`);
  if (!ALCHEMY_API_KEY && !process.env.SOLANA_RPC_URL) {
    logger.warn(
      "Neither ALCHEMY_API_KEY nor SOLANA_RPC_URL is set — falling back to " +
        `${SOLANA_RPC_HOST}, whose rate limits will drop transactions under load.`,
    );
  }
  if (!SUMSUB_SECRET) {
    logger.warn(
      "SUMSUB_SECRET is not set — webhook signatures are NOT verified. " +
        "Set it in production so forged requests cannot whitelist arbitrary wallets.",
    );
  }
  if (!TGBP_REGISTRATION_ENABLED) {
    logger.warn(
      { baseUrl: TGBP_API_BASE_URL },
      "tgbp.io customer registration is DISABLED — set TGBP_API_KEY, " +
        "SUMSUB_APP_TOKEN, SUMSUB_APP_TOKEN_SECRET and " +
        "SUMSUB_RECIPIENT_CLIENT_ID to enable it. " +
        "Approved users will still get their on-chain role and airdrop.",
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
  airdropTokens,
  buildInstruction,
  assignRoleIx,
  removeRoleIx,
  setPermissionIx,
  fetchRoleAccount,
  roleAccountPda,
  adminPda,
  configPda,
  fetchSumsubApplicantDetails,
  fetchSumsubShareToken,
  registerTgbpCustomer,
  registerTgbpCustomerBestEffort,
  Role,
  AccessPermission,
  PROGRAM_ID,
  KYC_LEVEL_ROLE_MAP,
};
