import { decodeUserId, type UserId } from "@maruhi/core";
import { Context, type Effect, Redacted } from "effect";

import { escapeText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { isRecord } from "./json-record.ts";

export type KeychainKind = "os-keychain" | "agent";

export interface KeychainShape {
  readonly kind: KeychainKind;
  readonly get: (name: string) => Effect.Effect<string | null, CliError>;
  readonly set: (name: string, value: string) => Effect.Effect<void, CliError>;
  readonly remove: (name: string) => Effect.Effect<void, CliError>;
}

export class Keychain extends Context.Service<Keychain, KeychainShape>()("cli/Keychain") {}

export const KEYCHAIN_SERVICE = "maruhi";

export function describeStore(kind: KeychainKind): string {
  return kind === "agent" ? "the maruhi agent's memory (this session only)" : "the OS keychain";
}

export function tokenEntryName(origin: string): string {
  return `token::${origin}`;
}

export function isTokenEntryName(name: string): boolean {
  return name.startsWith("token::");
}

export function masterKeyEntryName(origin: string, userId: UserId): string {
  return `master::${origin}::${userId}`;
}

export function isMasterKeyEntryName(name: string): boolean {
  return name.startsWith("master::");
}

export interface StoredToken {
  readonly token: Redacted.Redacted<string>;
  readonly userId: UserId;
  readonly tokenId: string;
  readonly expiresAtMs: number;
}

export interface StoredMasterKey {
  readonly suite: string;
  readonly encPubHex: string;
  readonly encSkHex: Redacted.Redacted<string>;
  readonly sigPubHex: string;
  readonly sigSkSeedHex: Redacted.Redacted<string>;
  readonly kind?: "reserve";
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

const REDACTED_PLACEHOLDER = /^<redacted(?::[^>]*)?>$/;

export const REDACTED_PLACEHOLDER_TEXT: RegExp = REDACTED_PLACEHOLDER;

function isRedactedPlaceholder(value: string): boolean {
  return REDACTED_PLACEHOLDER.test(value);
}

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

export function placeholderCause(artifact: string): string {
  return `${artifact} contains the redaction placeholder (<redacted>). This is a maruhi bug (the record was written without unwrapping the secret)`;
}

export function tokenRecordNoun(kind: KeychainKind): string {
  return kind === "agent"
    ? "The token record held by this agent session"
    : "The keychain token record";
}

function storedRecordPlaceholderCause(kind: KeychainKind): string {
  return placeholderCause(
    kind === "agent" ? "The record held by this agent session" : "The keychain record",
  );
}

export function redactedPlaceholderTokenMessage(kind: KeychainKind): string {
  return `${storedRecordPlaceholderCause(kind)}. \`maruhi login\` overwrites it. If it recurs after re-login, it is a maruhi bug — report it`;
}

export const redactedPlaceholderEnvTokenMessage =
  "MARUHI_TOKEN is the redaction placeholder (<redacted>) itself. maruhi's redacted display was pasted as if it were a token; it cannot authenticate. Set the raw token issued by `maruhi login`" as const;

function quotedEntryName(entryName: string): string {
  return `"${escapeText(entryName)}" (characters outside printable ASCII in the name are displayed escaped as \\u{hex} — at least 4 digits, more for supplementary planes — and backslashes / quotes as \\\\ / \\"; the actual entry name is the unescaped form)`;
}

function manualDeletionGuidance(entryName: string, kind: KeychainKind): string {
  if (kind === "agent") {
    return `Because of overwrite protection, this device's key cannot be repaired by \`maruhi key generate\` / \`maruhi device add\` / \`maruhi key recover\` while this record exists. It lives only in this agent session's memory and cannot be copied out, so first update maruhi to the latest version and re-run inside this session (a record written by a newer maruhi looks corrupt to an older one; leaving the session discards it). Only if that does not fix it: exit the session (the record is discarded with it) and start a new one with \`maruhi agent -- <shell>\` — do this only if you still have another device of yours or your recovery code, because \`maruhi device add\` (approved from that device) or \`maruhi key recover\` is then the only way to give this machine a key again (a new device key; you keep the ability to decrypt existing values). Without either, this record may be the last copy of the key: \`maruhi key generate --new-identity\` after exiting creates a new identity, but existing project values become undecryptable — ask an administrator to re-invite you (re-run \`maruhi member add\`). `;
  }
  return `Because of overwrite protection, this device's key cannot be repaired by \`maruhi key generate\` / \`maruhi device add\` / \`maruhi key recover\`. **Copy down the value first**, then delete the entry ${quotedEntryName(entryName)} of service "${KEYCHAIN_SERVICE}" from the OS keychain by hand (with the copy you can put it back; the copy is the device's private key itself, so destroy it once it is no longer needed — the key is usable again — and avoid forms that linger in terminal scrollback). After deletion, give this machine a key again: \`maruhi device add\` (approved from another device of yours) or, if no device is left, \`maruhi key recover\` with your recovery code — either way a new device key, and you keep the ability to decrypt existing values. Without either, \`maruhi key generate --new-identity\` creates a new identity, but existing project values become undecryptable — ask an administrator to re-invite you (re-run \`maruhi member add\`). `;
}

function hasCurrentMasterKeyShape(value: Record<string, unknown>): boolean {
  return ["suite", "encPubHex", "encSkHex", "sigPubHex", "sigSkSeedHex"].every(
    (field) => typeof value[field] === "string",
  );
}

export function classifyUnreadableMasterKey(json: string): "corrupt" | "foreign" {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return "corrupt";
  }
  if (Array.isArray(value)) {
    return "foreign";
  }
  if (!isRecord(value)) {
    return "corrupt";
  }
  if (hasCurrentMasterKeyShape(value)) {
    return "corrupt";
  }
  return "foreign";
}

export function foreignMasterKeyMessage(
  suite: string | null,
  entryName: string,
  kind: KeychainKind,
): string {
  const named = suite === null ? "" : ` (${escapeText(suite)})`;
  if (kind === "agent") {
    return `The device-key record held by this agent session cannot be read by this version${named}. It may have been written by a newer maruhi — update maruhi to the latest version and re-run inside this session (leaving it discards the record, and nothing can copy it out of agent memory). Only if updating does not fix it, and only if you still have another device of yours or your recovery code: exit the session (the record is discarded with it), start a new one with \`maruhi agent -- <shell>\`, and run \`maruhi device add\` (approved from that device) or \`maruhi key recover\`. Without either, do not exit — the registered blob may be in the same new format, and this record may be the last readable copy of the key. Also report this as a maruhi bug`;
  }
  return `The keychain device-key record cannot be read by this version${named}. It may have been written by a newer maruhi — keep this record (deleting it makes the key unrecoverable). Update maruhi to the latest version and re-run. Only if updating does not fix it: **Copy down the value first**, then delete the entry ${quotedEntryName(entryName)} of service "${KEYCHAIN_SERVICE}" from the OS keychain so you can try \`maruhi device add\` / \`maruhi key recover\` (with the copy you can put it back; the copy is the device's private key itself, so destroy it once it is no longer needed — the key is usable again — and avoid forms that linger in terminal scrollback. Never delete without the copy — even with a recovery code, the registered blob may be in the same new format and unrestorable). Also report this as a maruhi bug`;
}

function masterRecordNoun(kind: KeychainKind): string {
  return kind === "agent"
    ? "the device-key record held by this agent session"
    : "the keychain device-key record";
}

export function declaredSuiteOf(json: string): string | null {
  try {
    const value: unknown = JSON.parse(json);
    return isRecord(value) && nonEmptyString(value["suite"]) ? value["suite"] : null;
  } catch {
    return null;
  }
}

export function corruptMasterKeyMessage(entryName: string, kind: KeychainKind): string {
  return `Cannot read ${masterRecordNoun(kind)} (the record is corrupt). ${manualDeletionGuidance(entryName, kind)}`;
}

export function redactedPlaceholderMasterKeyMessage(entryName: string, kind: KeychainKind): string {
  return `${storedRecordPlaceholderCause(kind)}. ${manualDeletionGuidance(entryName, kind)}Also report this as a maruhi bug`;
}

export function parseStoredToken(json: string): StoredToken | null {
  try {
    const value: unknown = JSON.parse(json);
    if (
      isRecord(value) &&
      nonEmptyString(value["token"]) &&
      !isRedactedPlaceholder(value["token"]) &&
      nonEmptyString(value["userId"]) &&
      nonEmptyString(value["tokenId"]) &&
      typeof value["expiresAtMs"] === "number" &&
      Number.isFinite(value["expiresAtMs"])
    ) {
      return {
        token: Redacted.make(value["token"], { label: "maruhi-token" }),
        userId: decodeUserId(value["userId"]),
        tokenId: value["tokenId"],
        expiresAtMs: value["expiresAtMs"],
      };
    }
    return null;
  } catch {
    return null;
  }
}

export function serializeStoredToken(record: StoredToken): string {
  return JSON.stringify({
    token: Redacted.value(record.token),
    userId: record.userId,
    tokenId: record.tokenId,
    expiresAtMs: record.expiresAtMs,
  });
}

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
