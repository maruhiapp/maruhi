// The persistence layer of invite non-secret pinning (CRYPTO_SPEC
// §6.3 out-of-band anchor (a) and its inviter-side counterpart =
// the issue-time pin).
//
// - **Acceptor-side anchor**: the genesis the invite link's
//   fragment carries (= projectId, which the filename doubles as),
//   the inviter's verified head (hash + seq), the inviter's user_id
//   + key FP. Pinned at accept time; the sync-time mechanical
//   collation (context.ts) checks "head containment + inviter FP
//   membership match" (§6.3 (a) / §6.5).
// - **Issuer-side pin**: what `invite create` records — invite id →
//   (link_pub, role, expiry, destination login). At member add
//   time it collates against the list response (a server
//   declaration) to mechanically detect row substitution and role
//   misdeclaration (the defense symmetric to the acceptor-side
//   anchor). member add from a different device has no pin and
//   degrades to the ceremony's display check only (SHOULD).
//
// The contents are only public keys, hashes, sequence numbers,
// user_id, FP, role, and login — no plaintext values, key material,
// or link-key seeds (compatible with the diskless invariant).
// Storage is the same family as the floor (<config
// dir>/invites/<projectId>.json). Writes are temp + rename
// read-merge-write (same discipline as the floor).
//
// fail-open: a missing file is "no pin", corruption is "no pin + a
// distinguishable warning" (the caller emits it). An attacker who
// can erase local state is outside the pins' remit (reduces to
// §14.3-3's non-guarantee — the same boundary as the floor).

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { isEnvironmentId } from "@maruhi/core";
import { MAX_SCOPE_ENVIRONMENTS, type ScopeKind } from "@maruhi/crypto";
import { Context, Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import { GITHUB_LOGIN } from "./invite-link.ts";

/** The acceptor-side invite-link anchor (§6.3 (a)). */
export interface InviteAnchor {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly inviterUserId: string;
  /** The user key FP (16-byte hex, 32 chars — §3). */
  readonly inviterKeyFingerprintHex: string;
  /** The inviter's sig public key (the link's `is=`). Collated against the on-chain key in addition to the FP at first sync. */
  readonly inviterSigPubHex: string;
  /** My view's head seq at the time the first mechanical collation succeeded (not yet collated = null). */
  readonly verifiedAtSeq: number | null;
}

/** The issuer-side pin (invite id → the content settled at issue time. IV revision — link public key + destination login). */
export interface IssuedInvitePin {
  /** The link public key (hex 64). Collated against the row's link_pub of the server declaration (SHOULD). */
  readonly linkPubHex: string;
  readonly role: "reader" | "member" | "admin";
  /**
   * The scope to be granted (2026-09-15 ES K4 — extra collation
   * material of the same standing as role. The source of truth is
   * the issue signature). Pins issued before K4 lack it (both
   * missing = skip the collation).
   */
  readonly scopeKind?: ScopeKind;
  readonly scopeEnvironmentIds?: readonly string[];
  readonly expiresAtMs: number;
  /**
   * The destination's GitHub login (`invite create --github` —
   * the backing source's check target. Kept only at hand: never
   * written to the server, audit, or chain). Unspecified = null.
   */
  readonly expectedGithubLogin: string | null;
}

/** The pin file for one project (invites/<projectId>.json). */
export interface InvitePins {
  readonly v: 1;
  readonly anchor: InviteAnchor | null;
  /** The key is the invite id. */
  readonly issued: Readonly<Record<string, IssuedInvitePin>>;
}

/** The load result (fail-open — the caller emits a state-specific warning). */
export interface PinsLoadResult {
  readonly pins: InvitePins | null;
  readonly state: "loaded" | "missing" | "corrupt";
}

/** Load / merge boundary for the invite pin files. */
export interface PinStoreShape {
  readonly load: (projectId: string) => Effect.Effect<PinsLoadResult, CliError>;
  /** Saves the anchor (read-merge-write. Existing issued pins are kept). */
  readonly saveAnchor: (projectId: string, anchor: InviteAnchor) => Effect.Effect<void, CliError>;
  /** Appends an issued pin (read-merge-write + sweeping rows long past their expiry). */
  readonly saveIssuedPin: (
    projectId: string,
    inviteId: string,
    pin: IssuedInvitePin,
  ) => Effect.Effect<void, CliError>;
}

export class PinStore extends Context.Service<PinStore, PinStoreShape>()("cli/PinStore") {}

/** The pins directory (a location of the same family as the config: <config.json's parent>/invites). */
export function pinsDirOf(configPath: string): string {
  return join(dirname(configPath), "invites");
}

/**
 * The issued pin's retention window: rows past this much time
 * after expiry are swept. An accepted invite's add_member is
 * possible even after expiry (the expiry binds only acceptance —
 * AUTH_SPEC §15-1), so it is not deleted at the expiry itself. A
 * member add past the window degrades to pinless (display check
 * only).
 */
const ISSUED_PIN_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_32 = /^[0-9a-f]{32}$/;
const ROLES = ["reader", "member", "admin"] as const;
// The invite id is server-issued (ULID) but does not depend on
// the format (the same posture as AUTH_SPEC §11-1's ID-format
// independence). Banning a leading `_` structurally excludes
// `__proto__` (floor.ts's record-key discipline). The reading side
// uses floorRecordGet
const INVITE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/** Returns a record's string field after pattern validation (mismatch = null). */
function patternField(
  record: Record<string, unknown>,
  key: string,
  pattern: RegExp,
): string | null {
  const value = record[key];
  return typeof value === "string" && pattern.test(value) ? value : null;
}

/** A record's positive-integer field (mismatch = null). */
function positiveIntField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return isPositiveInteger(value) ? value : null;
}

/**
 * An optional string field: missing / null = null, pattern match
 * = the value, otherwise = "invalid" (distinguishes missing from
 * malformed — a pin of the old format is missing, tampering /
 * corruption is malformed).
 */
function optionalPatternField(
  record: Record<string, unknown>,
  key: string,
  pattern: RegExp,
): string | null | "invalid" {
  const raw = record[key];
  if (raw === undefined || raw === null) {
    return null;
  }
  return patternField(record, key, pattern) ?? "invalid";
}

/** An optional positive-integer field (missing / null = null, malformed = "invalid"). */
function optionalPositiveIntField(
  record: Record<string, unknown>,
  key: string,
): number | null | "invalid" {
  const raw = record[key];
  if (raw === undefined || raw === null) {
    return null;
  }
  return positiveIntField(record, key) ?? "invalid";
}

function decodeAnchor(value: unknown): InviteAnchor | null {
  if (!isRecord(value)) {
    return null;
  }
  const headSeq = positiveIntField(value, "headSeq");
  const headHashHex = patternField(value, "headHashHex", HEX_64);
  const inviterUserId = patternField(value, "inviterUserId", /^.{1,1024}$/s);
  const inviterKeyFingerprintHex = patternField(value, "inviterKeyFingerprintHex", HEX_32);
  const verifiedAtSeq = optionalPositiveIntField(value, "verifiedAtSeq");
  const inviterSigPubHex = patternField(value, "inviterSigPubHex", HEX_64);
  if (
    headSeq === null ||
    headHashHex === null ||
    inviterUserId === null ||
    inviterKeyFingerprintHex === null ||
    verifiedAtSeq === "invalid" ||
    inviterSigPubHex === null
  ) {
    return null;
  }
  return {
    headSeq,
    headHashHex,
    inviterUserId,
    inviterKeyFingerprintHex,
    inviterSigPubHex,
    verifiedAtSeq,
  };
}

function decodeIssuedPin(value: unknown): IssuedInvitePin | null {
  if (!isRecord(value)) {
    return null;
  }
  const linkPubHex = patternField(value, "linkPubHex", HEX_64);
  const role = ROLES.find((known) => known === value["role"]) ?? null;
  const expiresAtMs = positiveIntField(value, "expiresAtMs");
  const expectedGithubLogin = optionalPatternField(value, "expectedGithubLogin", GITHUB_LOGIN);
  const scope = optionalScopeFields(value);
  if (
    linkPubHex === null ||
    role === null ||
    expiresAtMs === null ||
    expectedGithubLogin === "invalid" ||
    scope === "invalid"
  ) {
    return null;
  }
  return { linkPubHex, role, ...scope, expiresAtMs, expectedGithubLogin };
}

/**
 * The optional scope pair (both missing = an old pin → empty;
 * only one present or a structural-rule violation = "invalid").
 * The structural rules are CRYPTO_SPEC §6.2's (kind's closed set,
 * all ⇒ empty, at most 256, no duplicates, id format).
 */
function optionalScopeFields(
  record: Record<string, unknown>,
):
  | { readonly scopeKind: ScopeKind; readonly scopeEnvironmentIds: readonly string[] }
  | "invalid"
  | {} {
  const kind = record["scopeKind"];
  const ids = record["scopeEnvironmentIds"];
  if (kind === undefined && ids === undefined) {
    return {};
  }
  if (
    (kind !== "all" && kind !== "listed") ||
    !isScopeIdList(ids) ||
    (kind === "all" && ids.length > 0)
  ) {
    return "invalid";
  }
  return { scopeKind: kind, scopeEnvironmentIds: [...ids] };
}

/** The structural rules of an environment-id list (§12-1 format, at most 256, no duplicates). */
function isScopeIdList(ids: unknown): ids is readonly string[] {
  return (
    Array.isArray(ids) &&
    ids.length <= MAX_SCOPE_ENVIRONMENTS &&
    ids.every((id) => isEnvironmentId(id)) &&
    new Set(ids).size === ids.length
  );
}

/** Strict decoding. A schema mismatch treats the whole as corrupt (no partial reads — same as the floor). */
/** Decoding the whole issued record (one malformed entry rejects the whole). */
function decodeIssuedRecord(value: unknown): Record<string, IssuedInvitePin> | null {
  if (!isRecord(value)) {
    return null;
  }
  const issued: Record<string, IssuedInvitePin> = {};
  for (const [inviteId, raw] of Object.entries(value)) {
    if (!INVITE_ID.test(inviteId)) {
      return null;
    }
    const pin = decodeIssuedPin(raw);
    if (pin === null) {
      return null;
    }
    issued[inviteId] = pin;
  }
  return issued;
}

function decodeInvitePins(json: string): InvitePins | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== 1) {
    return null;
  }
  const anchor = value["anchor"] === null ? null : decodeAnchor(value["anchor"]);
  if (value["anchor"] !== null && anchor === null) {
    return null;
  }
  const issued = decodeIssuedRecord(value["issued"]);
  if (issued === null) {
    return null;
  }
  return { v: 1, anchor, issued };
}

/** Reads an issued pin (own-property — floor.ts's discipline). */
export function issuedPinOf(
  pins: InvitePins | null,
  inviteId: string,
): IssuedInvitePin | undefined {
  return pins === null ? undefined : floorRecordGet(pins.issued, inviteId);
}

/** File-backed pin store at `dir` (used by both production and tests). */
export function makeFilePinStore(dir: string): PinStoreShape {
  const pathOf = (projectId: string) => join(dir, `${projectId}.json`);

  const loadRaw = async (projectId: string): Promise<PinsLoadResult> => {
    let json: string;
    try {
      json = await readFile(pathOf(projectId), "utf8");
    } catch (error) {
      // Only missing (ENOENT) **alone** folds into "none". EACCES
      // / EISDIR etc. are a "could not read the existing pins"
      // failure — folding them into "none" makes merge rebuild the
      // existing file from empty and silently lose the verified
      // anchor and the issued pins (same discipline as config.ts's
      // reading)
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { pins: null, state: "missing" };
      }
      throw error;
    }
    const pins = decodeInvitePins(json);
    return pins === null ? { pins: null, state: "corrupt" } : { pins, state: "loaded" };
  };

  const write = async (projectId: string, pins: InvitePins): Promise<void> => {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const path = pathOf(projectId);
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, `${JSON.stringify(pins, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  };

  const merge = (
    projectId: string,
    apply: (pins: InvitePins) => InvitePins,
  ): Effect.Effect<void, CliError> =>
    Effect.tryPromise({
      try: async () => {
        const loaded = await loadRaw(projectId);
        if (loaded.state === "corrupt") {
          // Writing onto a corrupt file is refused (same
          // discipline as the floor's "a write failure is never
          // fail-open"). Rebuilding from empty would let the
          // verified anchor be silently lost via one corruption +
          // the next write and become indistinguishable from
          // "there never was an anchor" (§6.3 (a)'s detection
          // itself depends on the anchor)
          throw new Error("corrupt");
        }
        const base: InvitePins = loaded.pins ?? { v: 1, anchor: null, issued: {} };
        await write(projectId, apply(base));
      },
      catch: () =>
        cliError(
          `Cannot write the invite-pin file (corrupt or an I/O failure): ${pathOf(projectId)} — inspect it, and if the modification was unintended, delete it and re-run`,
        ),
    });

  return {
    load: (projectId) =>
      Effect.tryPromise({
        try: () => loadRaw(projectId),
        catch: () => cliError(`Cannot read the invite-pin file: ${pathOf(projectId)}`),
      }),
    saveAnchor: (projectId, anchor) => merge(projectId, (pins) => ({ ...pins, anchor })),
    saveIssuedPin: (projectId, inviteId, pin) => {
      // Writing an out-of-format id makes the next load wholly corrupt (strict decoding), so refuse beforehand
      if (!INVITE_ID.test(inviteId)) {
        return Effect.fail(
          cliError(
            "Cannot save the issuance pin because the invite id in the server response is not in the expected form",
          ),
        );
      }
      return merge(projectId, (pins) => {
        const now = Date.now();
        const kept = Object.entries(pins.issued).filter(
          ([, existing]) => existing.expiresAtMs + ISSUED_PIN_RETENTION_MS > now,
        );
        return { ...pins, issued: { ...Object.fromEntries(kept), [inviteId]: pin } };
      });
    },
  };
}
