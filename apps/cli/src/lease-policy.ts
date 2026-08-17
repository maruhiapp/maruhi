// `maruhi server grant --lease-policy <file>` の読み込みと正規化
// (lease_policy — CRYPTO_SPEC §6.2)。
//
// cli.ts(gunshi 側)から切り出したのは ADR-0016 第 2 段階の移行のため
// (server grant の引数層は effect-cli.ts)。文言は ADR-0017 に従い英語。

import { readFile } from "node:fs/promises";

import type { LeasePolicyIssuer } from "@maruhi/crypto";
import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";

// lease_policy(CRYPTO_SPEC §6.2)のファイル入力の上限。合意規則の値と同じ
// (超過はチェーン検証 invalid-payload になるため、入力段で先に落とす)
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;
const MAX_LEASE_FIELD_BYTES = 1024;

function leaseFieldOk(value: unknown, allowEmpty: boolean): value is string {
  if (typeof value !== "string") {
    return false;
  }
  if (!allowEmpty && value.length === 0) {
    return false;
  }
  return new TextEncoder().encode(value).length <= MAX_LEASE_FIELD_BYTES;
}

/**
 * lease_policy ファイル(JSON)の解釈と正規化。ファイル形式は camelCase +
 * claimConstraints をオブジェクト(claim 名 → 値)で書く — 同一 claim の矛盾する
 * 重複制約(完全一致 AND では常に偽)を構造的に表現できなくするため。
 * チェーン形式(順序付き配列)への変換で §6.2 の SHOULD(コードポイント昇順・
 * 重複なし)を適用する。
 */
function parseLeasePolicy(content: string): readonly LeasePolicyIssuer[] | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return "not valid JSON";
  }
  if (!Array.isArray(parsed)) {
    return "the top level must be an array of elements";
  }
  if (parsed.length > MAX_LEASE_POLICY_ISSUERS) {
    return `at most ${MAX_LEASE_POLICY_ISSUERS} elements are allowed (consensus rule — CRYPTO_SPEC §6.2)`;
  }
  const elements: LeasePolicyIssuer[] = [];
  for (const element of parsed) {
    const result = parseLeaseElement(element);
    if (typeof result === "string") {
      return result;
    }
    elements.push(result);
  }
  return canonicalizeLeaseElements(elements);
}

/** lease_policy の 1 要素の解釈(不正なら理由の文字列)。 */
function parseLeaseElement(element: unknown): LeasePolicyIssuer | string {
  if (typeof element !== "object" || element === null || Array.isArray(element)) {
    return "each element must be an object of { issuerUrl, audience, claimConstraints }";
  }
  const record = element as Record<string, unknown>;
  if (!leaseFieldOk(record["issuerUrl"], false) || !leaseFieldOk(record["audience"], false)) {
    return `issuerUrl / audience must be non-empty strings (at most ${MAX_LEASE_FIELD_BYTES} bytes each)`;
  }
  const claimConstraints = parseLeaseConstraints(record["claimConstraints"] ?? {});
  if (typeof claimConstraints === "string") {
    return claimConstraints;
  }
  return {
    issuerUrl: record["issuerUrl"] as string,
    audience: record["audience"] as string,
    claimConstraints,
  };
}

/** claimConstraints オブジェクトの解釈と昇順ソート(不正なら理由の文字列)。 */
function parseLeaseConstraints(
  value: unknown,
): { claimName: string; claimValue: string }[] | string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "claimConstraints must be an object of { claimName: value }";
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_LEASE_CLAIM_CONSTRAINTS) {
    return `claimConstraints may have at most ${MAX_LEASE_CLAIM_CONSTRAINTS} entries per element (consensus rule)`;
  }
  const claimConstraints: { claimName: string; claimValue: string }[] = [];
  for (const [claimName, claimValue] of entries) {
    if (!leaseFieldOk(claimName, false) || !leaseFieldOk(claimValue, true)) {
      return `claim constraint names must be non-empty and values must be strings (each at most ${MAX_LEASE_FIELD_BYTES} bytes)`;
    }
    claimConstraints.push({ claimName, claimValue });
  }
  // 制約はコードポイント昇順(§6.2 の SHOULD)。名前はオブジェクトキーなので一意
  claimConstraints.sort((a, b) => (a.claimName < b.claimName ? -1 : 1));
  return claimConstraints;
}

/**
 * 要素のコードポイント昇順 + 重複除去(SHOULD。評価は存在量化 — AUTH_SPEC §14-1 —
 * なので順序・重複は意味論に影響しないが、署名対象バイト列を決定論にする)。
 */
function canonicalizeLeaseElements(
  elements: readonly LeasePolicyIssuer[],
): readonly LeasePolicyIssuer[] {
  const canonical = elements
    .map((element) => ({ element, key: JSON.stringify(element) }))
    .toSorted((a, b) => (a.key < b.key ? -1 : 1));
  const deduped: LeasePolicyIssuer[] = [];
  let previousKey: string | null = null;
  for (const { element, key } of canonical) {
    if (key !== previousKey) {
      deduped.push(element);
      previousKey = key;
    }
  }
  return deduped;
}

/** `--lease-policy <file>` の読み込み(省略時は空 = リース経路なし)。 */
export function loadLeasePolicy(
  path: string | undefined,
): Effect.Effect<readonly LeasePolicyIssuer[], CliError> {
  if (path === undefined) {
    return Effect.succeed([]);
  }
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () => usageError("Cannot read the --lease-policy file (check the path)"),
    });
    const parsed = parseLeasePolicy(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(usageError(`--lease-policy content is invalid: ${parsed}`));
    }
    return parsed;
  });
}
