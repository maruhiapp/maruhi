// The OS keychain boundary (Effect service) and the shape of stored records.
//
// The only secrets the CLI may persist are the maruhi API token and the
// master private key, and both pass through this boundary (the OS keychain)
// (the CLAUDE.md diskless invariant). No plaintext-file fallback is
// implemented — in environments without a keychain, nothing is stored and a
// typed error guides the user.
//
// The production implementation is Bun.secrets (live.ts; macOS Keychain /
// Linux libsecret / Windows Credential Manager). Tests are in-memory
// (test/support).
//
// Secret fields of a stored record are wrapped in `Redacted` (the type stops
// leakage into logs and errors). **But `JSON.stringify` stores the
// placeholder** — `Redacted`'s `toJSON()` returns "<redacted>", so
// stringifying a record as-is writes the placeholder to the keychain without
// a type error (a token fails next auth, a master key becomes undecryptable).
// Always persist via this file's {@link serializeStoredToken} /
// {@link serializeStoredMasterKey}, unwrapping explicitly just before
// serialization.

import { Context, type Effect, Redacted } from "effect";

import { escapeText } from "./display.ts";
import type { CliError } from "./errors.ts";

/**
 * Where the records live: the OS keychain, or the memory of a running
 * `maruhi agent` (KL2 — agent.ts). The distinction exists so success text
 * can name the store; the semantics (get / set / remove) are the same.
 */
export type KeychainKind = "os-keychain" | "agent";

/** OS keychain boundary. Names are scoped by {@link tokenEntryName} / {@link masterKeyEntryName}. */
export interface KeychainShape {
  readonly kind: KeychainKind;
  readonly get: (name: string) => Effect.Effect<string | null, CliError>;
  readonly set: (name: string, value: string) => Effect.Effect<void, CliError>;
  readonly remove: (name: string) => Effect.Effect<void, CliError>;
}

export class Keychain extends Context.Service<Keychain, KeychainShape>()("cli/Keychain") {}

/** Keychain service name shared by every maruhi entry. */
export const KEYCHAIN_SERVICE = "maruhi";

/**
 * Name for the store (for success text). Saying "stored in the OS keychain"
 * inside an agent session would point at a place that does not exist in an
 * environment without a keychain.
 */
export function describeStore(kind: KeychainKind): string {
  return kind === "agent" ? "the maruhi agent's memory (this session only)" : "the OS keychain";
}

/** Keychain entry name for the maruhi API token of one server. */
export function tokenEntryName(origin: string): string {
  return `token::${origin}`;
}

/** Keychain entry name for the master keypair of one (server, user). */
export function masterKeyEntryName(origin: string, userId: string): string {
  return `master::${origin}::${userId}`;
}

/** Whether an entry name is a master-key entry (the agent's `--key-ttl` applies to these only). */
export function isMasterKeyEntryName(name: string): boolean {
  return name.startsWith("master::");
}

/** The maruhi API token record stored in the keychain (AUTH_SPEC §4-5). */
export interface StoredToken {
  readonly token: Redacted.Redacted<string>;
  readonly userId: string;
  readonly tokenId: string;
  /**
   * Expiry fixed at issuance (AUTH_SPEC §6 — W3a). Non-sensitive metadata
   * used for the early expiry warning (W3a ruling CL — a local check with no
   * traffic). Absent from records written by logins before W3a (missing =
   * behaves as before with no warning; added on re-login).
   */
  readonly expiresAtMs?: number;
}

/**
 * The master keypair record stored in the keychain (CRYPTO_SPEC §3).
 *
 * Only the secret halves (`encSkHex` / `sigSkSeedHex`) are wrapped. The
 * public keys and the suite are non-sensitive — used widely in signing
 * contexts, FP computation, and invite-acceptance payloads — so they stay
 * raw.
 */
export interface StoredMasterKey {
  readonly suite: string;
  readonly encPubHex: string;
  readonly encSkHex: Redacted.Redacted<string>;
  readonly sigPubHex: string;
  readonly sigSkSeedHex: Redacted.Redacted<string>;
  /**
   * `"reserve"` = the client created this key as the reserve key (CRYPTO_SPEC §8 — DK K16).
   * Carried inside the sealed ledger blob only; a keychain never holds such a record.
   */
  readonly kind?: "reserve";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

// The very output of `Redacted.toString()` / `toJSON()` (including labelled forms).
const REDACTED_PLACEHOLDER = /^<redacted(?::[^>]*)?>$/;

/**
 * The public version, for checking whether the redaction placeholder itself
 * arrived outside stored records (e.g. environment variables). Whatever the
 * value's origin, a slipped-in placeholder looks the same, so the check is
 * shared.
 */
export const REDACTED_PLACEHOLDER_TEXT: RegExp = REDACTED_PLACEHOLDER;

function isRedactedPlaceholder(value: string): boolean {
  return REDACTED_PLACEHOLDER.test(value);
}

/**
 * Whether a stored record has the redaction placeholder written into it
 * (detection at the read boundary).
 *
 * As the note at the top says, forgetting to unwrap during serialization
 * stores "<redacted>". This is the only path **the type cannot stop**, so the
 * reader checks too.
 *
 * The point is returning the detection **in a form the caller can
 * distinguish**: merged into a generic "the record is corrupt", neither the
 * cause (a maruhi bug) nor the per-record-kind recovery steps survive.
 * Recoverability depends on **which build wrote it**: a record written by an
 * old build and read by the fixed version is repaired by overwriting; if the
 * bug remains in the current version, rewriting stores the same placeholder
 * again. Both are possible, so the wording shows both.
 *
 * A raw value never takes this form (tokens have the `maruhi_pat_` /
 * `maruhi_inv_` prefixes, key material is hex), so no false positives.
 */
export function hasRedactedPlaceholder(json: string): boolean {
  try {
    const value: unknown = JSON.parse(json);
    if (!isRecord(value)) {
      return false;
    }
    return ["token", "encSkHex", "sigSkSeedHex"].some((name) => {
      const field = value[name];
      return typeof field === "string" && isRedactedPlaceholder(field);
    });
  } catch {
    return false;
  }
}

/**
 * Explanation of how the placeholder got in (the caller appends the
 * recovery steps per record kind).
 *
 * The broken artifact is an argument because **a different thing** is broken
 * depending on the path: sometimes a keychain record, sometimes the recovery
 * blob registered on the server. Using the former's wording for the latter
 * would point at a keychain record that does not exist and mislead the
 * investigation.
 */
export function placeholderCause(artifact: string): string {
  return `${artifact} contains the redaction placeholder (<redacted>). This is a maruhi bug (the record was written without unwrapping the secret)`;
}

/**
 * Name for the token record (sentence-initial; varies by store — never
 * names a place that does not exist). The fix (`maruhi login` overwrites it)
 * does not depend on the store.
 */
export function tokenRecordNoun(kind: KeychainKind): string {
  return kind === "agent"
    ? "The token record held by this agent session"
    : "The keychain token record";
}

/** Name for a record that stored the placeholder (varies by store — never names a place that does not exist). */
function storedRecordPlaceholderCause(kind: KeychainKind): string {
  return placeholderCause(
    kind === "agent" ? "The record held by this agent session" : "The keychain record",
  );
}

/**
 * Wording when the placeholder was stored in a token record.
 *
 * Split because the recovery means **differ by record kind**. Since
 * `maruhi login` overwrites a token unconditionally, a record written by an
 * old build is fixed by re-login (asserting it cannot be fixed would shut the
 * user out of the only single-command recovery). But if the bug remains in
 * the current version, rewriting stores the same placeholder again — so the
 * text also says a recurrence is itself evidence.
 */
export function redactedPlaceholderTokenMessage(kind: KeychainKind): string {
  return `${storedRecordPlaceholderCause(kind)}. If an older maruhi wrote the record, \`maruhi login\` overwrites it correctly. If it recurs after re-login, the bug is in the current version — report it`;
}

/**
 * Wording when MARUHI_TOKEN holds the placeholder itself.
 *
 * Here the cause is not a maruhi bug but **a paste mistake**: the redacted
 * display from output was taken for a token and put into the environment
 * variable. The fix differs too (not re-login or key deletion — put the real
 * token back), so the wording is separate.
 */
export const redactedPlaceholderEnvTokenMessage =
  "MARUHI_TOKEN is the redaction placeholder (<redacted>) itself. maruhi's redacted display was pasted as if it were a token; it cannot authenticate. Set the raw token issued by `maruhi login`" as const;

/**
 * Display of an entry name (escaped, plus a note that it is escaped).
 *
 * Dropping the note would make **the displayed name not exist** for a user_id
 * containing anything outside printable ASCII, so the only recovery step
 * (deleting it by hand) could not be carried out. With more places showing
 * the name, the note is confined here together with it.
 */
function quotedEntryName(entryName: string): string {
  return `"${escapeText(entryName)}" (characters outside printable ASCII in the name are displayed escaped as \\u{hex} — at least 4 digits, more for supplementary planes — and backslashes / quotes as \\\\ / \\"; the actual entry name is the unescaped form)`;
}

/**
 * The shared "delete it by hand, then proceed as follows" part (the exit is
 * the same for placeholder and corruption alike).
 *
 * The point is **having the user copy the value before deleting**: corruption
 * judgment is imperfect. parseStoredMasterKey does not inspect inside the
 * hex, so a well-formed future-format record can fail at decodeHex and look
 * "corrupt" (the key material itself may be fine). Whichever side of the
 * classification the record truly belongs to, the only way to stay safe is to
 * keep deletion reversible — aligned with the foreign-format wording
 * ({@link foreignMasterKeyMessage}).
 *
 * The point is showing **both** post-deletion paths: which applies depends on
 * the user's situation. With a recovery code, `key recover` restores the
 * original key and keeps existing values decryptable; without one,
 * `key generate` is the only option (then existing values cannot be decrypted
 * and self-addressed wraps must be redistributed). Guiding only to
 * `key recover` would send users without a code to instructions they cannot
 * execute.
 */
function manualDeletionGuidance(entryName: string, kind: KeychainKind): string {
  // An agent session's record exists only in this process's memory. "Delete
  // it from the OS keychain by hand" would be unexecutable guidance (nothing
  // to delete, and generate / recover stay blocked until the session ends).
  // The exit is recreating the session, but it **cannot be made reversible**
  // (there is no way to copy the value out of memory), so it is guarded by
  // order and conditions: (1) first, without leaving, update maruhi and
  // re-run (a well-formed future-format record looks corrupt to an older
  // version — parseStoredMasterKey does not inspect inside the hex); (2)
  // leave only when a recovery code exists (a record whose issuance has not
  // completed right after `key generate` has this memory as its only copy —
  // the server has none)
  if (kind === "agent") {
    return `Because of overwrite protection, this device's key cannot be repaired by \`maruhi key generate\` / \`maruhi device add\` / \`maruhi key recover\` while this record exists. It lives only in this agent session's memory and cannot be copied out, so first update maruhi to the latest version and re-run inside this session (a record written by a newer maruhi looks corrupt to an older one; leaving the session discards it). Only if that does not fix it: exit the session (the record is discarded with it) and start a new one with \`maruhi agent -- <shell>\` — do this only if you still have another device of yours or your recovery code, because \`maruhi device add\` (approved from that device) or \`maruhi key recover\` is then the only way to give this machine a key again (a new device key; you keep the ability to decrypt existing values). Without either, this record may be the last copy of the key: \`maruhi key generate --new-identity\` after exiting creates a new identity, but existing project values become undecryptable — ask an administrator to re-invite you (re-run \`maruhi member add\`). `;
  }
  // entryName contains user_id (a free-form string distributed by the
  // server). It is sanitized before reaching the terminal, but **escaped, not
  // flattened**: the name is the very target of the "please delete it"
  // guidance, and flattening it to replacement characters would name an entry
  // that does not exist and make the only recovery step unexecutable.
  //
  // The escaped string is not the original text, though (the notation changes
  // for a user_id containing anything outside printable ASCII). **The text
  // explicitly notes that it is escaped** — otherwise the user searches for
  // the name as displayed and cannot find it.
  return `Because of overwrite protection, this device's key cannot be repaired by \`maruhi key generate\` / \`maruhi device add\` / \`maruhi key recover\`. **Copy down the value first**, then delete the entry ${quotedEntryName(entryName)} of service "${KEYCHAIN_SERVICE}" from the OS keychain by hand (with the copy you can put it back; the copy is the device's private key itself, so destroy it once it is no longer needed — the key is usable again — and avoid forms that linger in terminal scrollback). After deletion, give this machine a key again: \`maruhi device add\` (approved from another device of yours) or, if no device is left, \`maruhi key recover\` with your recovery code — either way a new device key, and you keep the ability to decrypt existing values. Without either, \`maruhi key generate --new-identity\` creates a new identity, but existing project values become undecryptable — ask an administrator to re-invite you (re-run \`maruhi member add\`). `;
}

/** Whether the current format's fields are all present (the contents of the values are not questioned). */
function hasCurrentMasterKeyShape(value: Record<string, unknown>): boolean {
  return ["suite", "encPubHex", "encSkHex", "sigPubHex", "sigSkSeedHex"].every(
    (field) => typeof value[field] === "string",
  );
}

/**
 * Classification of an unreadable record.
 *
 * This is **the decision of whether deletion may be recommended**, and
 * getting it wrong loses the key permanently: a record written in a different
 * shape by a future maruhi does not pass the current
 * {@link parseStoredMasterKey} (a changed shape fails the required-field
 * check), but that is not corruption — it is **a key that is correct for that
 * version**. Guiding to "please delete it" without the distinction leaves a
 * user with no recovery code unable to restore anything.
 *
 * The judgment **leans toward not recommending deletion**: only "not even
 * JSON", "not even a JSON object", or "claims the current suite yet cannot be
 * read" count as corrupt; everything else (a different suite, no suite,
 * nested, etc.) is treated as possibly another format. Where a future shape
 * puts the suite is unknowable from this implementation, so no bet is placed
 * on a specific field name. Conversely, that the record is an object is the
 * minimal format-independent premise, so up to that much may be declared
 * corrupt (without that declaration, the guidance to update leads to a dead
 * end that never gets fixed).
 */
export function classifyUnreadableMasterKey(json: string): "corrupt" | "foreign" {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    // Not even JSON = a shape no version of maruhi writes. Safe to delete
    return "corrupt";
  }
  // A JSON scalar (null, number, string, boolean) = a shape no version of
  // maruhi writes as a key record. Leaning toward "maybe another format" here
  // would mean telling a record that should be deletable to "keep it and
  // update", which updates never fix — permanently blocking generate /
  // recover / show alike (no way out). Arrays stay on the object side = the
  // keep side — a future version could plausibly use one as a container
  // holding multiple keys
  if (!isRecord(value)) {
    return "corrupt";
  }
  // Unreadable despite having **all** fields of the current shape = the
  // contents are broken (parseStoredMasterKey fails only when a value is
  // empty or the wrong type).
  //
  // `suite === SUITE_ID` must not be the basis here: SUITE_ID is **the
  // identifier of the crypto suite**, not the version of the stored format. A
  // future version that changed only the record's shape while keeping the
  // suite would land in "corrupt" under this check and get deletion
  // recommended — the very permanent key loss the classification exists to
  // prevent
  if (hasCurrentMasterKeyShape(value)) {
    return "corrupt";
  }
  // Anything else (a different suite, no suite, nested, etc.) is **possibly
  // another format**. Do not bet on a single field name to judge "safe to
  // delete" — a mistake is permanent key loss, and the cost of getting it
  // wrong is not balanced on the two sides
  return "foreign";
}

/**
 * Wording for a record this version cannot read (a future version may have
 * written it).
 *
 * **The default is to not recommend deletion**. Deleting it loses a key that
 * would have worked after upgrading to that version.
 *
 * But ending at "please keep it" strands a user whose record is actually
 * corrupt (object-shaped but missing its suite, etc.): blocked from all of
 * `key generate` / `key recover` / `key show` in a state updates never fix.
 * So an escape remains, but it is **not conditioned on having a recovery
 * code**: if a newer version wrote this record, the server's recovery blob is
 * very likely in the same format, and `key recover` fails for the same reason
 * (noticed after deleting = permanent loss). Safety comes not from a
 * condition but from **reversibility** — copy the value before deleting, and
 * it can be put back.
 */
export function foreignMasterKeyMessage(
  suite: string | null,
  entryName: string,
  kind: KeychainKind,
): string {
  const named = suite === null ? "" : ` (${escapeText(suite)})`;
  // An agent session's record can neither be deleted by hand nor copied out
  // (it lives only in memory). Reaching this branch means a newer maruhi
  // (`bunx maruhi@latest` or a differently pinned binary) wrote a record into
  // this session and the older one read it. Leaving can lose **the last
  // readable copy** (if issuance has not completed right after `key generate`
  // the server does not have it either, and even if it does, the blob may be
  // in the same new format and unrestorable). With no reversibility
  // available, what can be guarded is order (update without leaving) and
  // conditions (leave only when a code exists)
  if (kind === "agent") {
    return `The device-key record held by this agent session cannot be read by this version${named}. It may have been written by a newer maruhi — update maruhi to the latest version and re-run inside this session (leaving it discards the record, and nothing can copy it out of agent memory). Only if updating does not fix it, and only if you still have another device of yours or your recovery code: exit the session (the record is discarded with it), start a new one with \`maruhi agent -- <shell>\`, and run \`maruhi device add\` (approved from that device) or \`maruhi key recover\`. Without either, do not exit — the registered blob may be in the same new format, and this record may be the last readable copy of the key. Also report this as a maruhi bug`;
  }
  return `The keychain device-key record cannot be read by this version${named}. It may have been written by a newer maruhi — keep this record (deleting it makes the key unrecoverable). Update maruhi to the latest version and re-run. Only if updating does not fix it: **Copy down the value first**, then delete the entry ${quotedEntryName(entryName)} of service "${KEYCHAIN_SERVICE}" from the OS keychain so you can try \`maruhi device add\` / \`maruhi key recover\` (with the copy you can put it back; the copy is the device's private key itself, so destroy it once it is no longer needed — the key is usable again — and avoid forms that linger in terminal scrollback. Never delete without the copy — even with a recovery code, the registered blob may be in the same new format and unrestorable). Also report this as a maruhi bug`;
}

/** Name for the record (varies by store — never names a place that does not exist). */
function masterRecordNoun(kind: KeychainKind): string {
  return kind === "agent"
    ? "the device-key record held by this agent session"
    : "the keychain device-key record";
}

/** Extracts only the declared suite from a record (null if unreadable). */
export function declaredSuiteOf(json: string): string | null {
  try {
    const value: unknown = JSON.parse(json);
    return isRecord(value) && nonEmptyString(value["suite"]) ? value["suite"] : null;
  } catch {
    return null;
  }
}

/**
 * Wording when a master-key record is corrupt and unreadable (damage other
 * than the placeholder).
 *
 * As with the placeholder, the point is **not leaving a dead end**: the
 * overwrite-protection guard looks only at the record's existence, so while
 * an unreadable record remains, all of `key generate` / `key recover` /
 * `key show` are refused and nothing can be done from the CLI. The cause
 * differs but the exit (deleting by hand) is the same, so it shows the entry
 * name to delete and the steps available afterward.
 */
export function corruptMasterKeyMessage(entryName: string, kind: KeychainKind): string {
  return `Cannot read ${masterRecordNoun(kind)} (the record is corrupt). ${manualDeletionGuidance(entryName, kind)}`;
}

/**
 * Wording when the placeholder was stored in a master-key record.
 *
 * This one cannot be fixed by commands alone: the overwrite-protection guard
 * (once a {@link masterKeyEntryName} entry exists, `key generate` /
 * `key recover` are refused — losing the key means losing the ability to
 * decrypt) blocks them. There is no path other than deleting the entry from
 * the OS keychain by hand, so the entry name to delete is included.
 *
 * The point is showing **both** post-deletion paths: which applies depends on
 * the user's situation. With a recovery code, `key recover` restores the
 * original key and keeps existing values decryptable; without one,
 * `key generate` is the only option (then existing values cannot be decrypted
 * and self-addressed wraps must be redistributed). Guiding only to
 * `key recover` sends users without a code to "please re-register from
 * another device" — instructions they cannot execute.
 */
export function redactedPlaceholderMasterKeyMessage(entryName: string, kind: KeychainKind): string {
  // entryName contains user_id (a free-form string distributed by the
  // server). It is sanitized before reaching the terminal, but **escaped, not
  // flattened**: the name is the very target of the "please delete it"
  // guidance, and flattening it to replacement characters would name an entry
  // that does not exist and make the only recovery step unexecutable.
  //
  // The escaped string is not the original text, though (the notation changes
  // for a user_id containing control characters, `\`, or `"`). **The text
  // explicitly notes that it is escaped** — otherwise the user searches for
  // the name as displayed and cannot find it.
  return `${storedRecordPlaceholderCause(kind)}. ${manualDeletionGuidance(entryName, kind)}Also report this as a maruhi bug`;
}

/** Parses a stored token record; null when the shape is corrupt. */
export function parseStoredToken(json: string): StoredToken | null {
  try {
    const value: unknown = JSON.parse(json);
    if (
      isRecord(value) &&
      nonEmptyString(value["token"]) &&
      !isRedactedPlaceholder(value["token"]) &&
      nonEmptyString(value["userId"]) &&
      nonEmptyString(value["tokenId"])
    ) {
      // expiresAtMs is optional for backward compatibility (W3a ruling CL):
      // missing or non-numeric values fold into "unknown" (the warning simply
      // does not appear; the record is not treated as corrupt)
      const expiresAtMs = value["expiresAtMs"];
      return {
        token: Redacted.make(value["token"], { label: "maruhi-token" }),
        userId: value["userId"],
        tokenId: value["tokenId"],
        ...(typeof expiresAtMs === "number" && Number.isFinite(expiresAtMs) ? { expiresAtMs } : {}),
      };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Serializes a token record for the keychain, unwrapping the token.
 *
 * Why unwrap: what is written to the keychain must be the raw value. Passing
 * a {@link StoredToken} straight to `JSON.stringify` triggers
 * `Redacted.toJSON()` and "<redacted>" gets stored, unnoticed until the next
 * login (the type checks pass). All store paths are concentrated in this one
 * function so the unwrapping spots stay countable.
 */
export function serializeStoredToken(record: StoredToken): string {
  return JSON.stringify({
    token: Redacted.value(record.token),
    userId: record.userId,
    tokenId: record.tokenId,
    ...(record.expiresAtMs === undefined ? {} : { expiresAtMs: record.expiresAtMs }),
  });
}

/** Parses a stored master-key record; null when the shape is corrupt. */
export function parseStoredMasterKey(json: string): StoredMasterKey | null {
  try {
    const value: unknown = JSON.parse(json);
    if (
      isRecord(value) &&
      nonEmptyString(value["suite"]) &&
      nonEmptyString(value["encPubHex"]) &&
      nonEmptyString(value["encSkHex"]) &&
      !isRedactedPlaceholder(value["encSkHex"]) &&
      nonEmptyString(value["sigPubHex"]) &&
      nonEmptyString(value["sigSkSeedHex"]) &&
      !isRedactedPlaceholder(value["sigSkSeedHex"]) &&
      // The marker (DK K16) is absent or "reserve" only; unknown values are
      // treated as a corrupt record
      (value["kind"] === undefined || value["kind"] === "reserve")
    ) {
      return {
        suite: value["suite"],
        encPubHex: value["encPubHex"],
        encSkHex: Redacted.make(value["encSkHex"], { label: "master-enc-sk" }),
        sigPubHex: value["sigPubHex"],
        sigSkSeedHex: Redacted.make(value["sigSkSeedHex"], { label: "master-sig-seed" }),
        ...(value["kind"] === "reserve" ? { kind: "reserve" as const } : {}),
      };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Serializes a master-key record, unwrapping the private halves.
 *
 * Why unwrap: same as {@link serializeStoredToken} — what is written to the
 * keychain and the recovery blob must be the raw value. Passing a
 * {@link StoredMasterKey} straight to `JSON.stringify` turns the secret
 * halves into "<redacted>" and **stores a record whose key cannot be
 * restored** (the type checks pass, unnoticed until decryption is needed).
 * Every store and wrap path is concentrated in this one function.
 */
export function serializeStoredMasterKey(record: StoredMasterKey): string {
  return JSON.stringify({
    suite: record.suite,
    encPubHex: record.encPubHex,
    encSkHex: Redacted.value(record.encSkHex),
    sigPubHex: record.sigPubHex,
    sigSkSeedHex: Redacted.value(record.sigSkSeedHex),
    ...(record.kind === undefined ? {} : { kind: record.kind }),
  });
}
