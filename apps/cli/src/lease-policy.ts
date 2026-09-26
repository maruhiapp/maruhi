// Loading and normalizing `maruhi server grant --lease-policy
// <file>` (lease_policy — CRYPTO_SPEC §6.2). The argument layer is
// effect-cli.ts. Wording is English per ADR-0017.

import { readFile } from "node:fs/promises";

import type { LeasePolicyIssuer } from "@maruhi/crypto";
import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";

// Input-file limits of lease_policy (CRYPTO_SPEC §6.2). Same values
// as the consensus rules (an excess becomes invalid-payload at chain
// verification, so drop it at the input stage first)
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
 * Parses and normalizes a lease_policy file (JSON). The file format
 * writes camelCase + claimConstraints as an object (claim name →
 * value) — so that contradictory duplicate constraints on the same
 * claim (always false under exact-match AND) cannot be expressed
 * structurally. Each element requires at least one claim constraint
 * and cannot create an issuer + audience only grant. The SHOULD of
 * §6.2 (code-point ascending, no duplicates) is applied when
 * converting to the chain form (an ordered array).
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

/** Interprets one lease_policy element (a reason string when malformed). */
function parseLeaseElement(element: unknown): LeasePolicyIssuer | string {
  if (typeof element !== "object" || element === null || Array.isArray(element)) {
    return "each element must be an object of { issuerUrl, audience, claimConstraints }";
  }
  const record = element as Record<string, unknown>;
  if (!leaseFieldOk(record["issuerUrl"], false) || !leaseFieldOk(record["audience"], false)) {
    return `issuerUrl / audience must be non-empty strings (at most ${MAX_LEASE_FIELD_BYTES} bytes each)`;
  }
  if (!Object.hasOwn(record, "claimConstraints")) {
    return "claimConstraints is required for every element";
  }
  const claimConstraints = parseLeaseConstraints(record["claimConstraints"]);
  if (typeof claimConstraints === "string") {
    return claimConstraints;
  }
  return {
    issuerUrl: record["issuerUrl"] as string,
    audience: record["audience"] as string,
    claimConstraints,
  };
}

/** Interprets and ascending-sorts the claimConstraints object (a reason string when malformed). */
function parseLeaseConstraints(
  value: unknown,
): { claimName: string; claimValue: string }[] | string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "claimConstraints must be an object of { claimName: value }";
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) {
    return "claimConstraints must have at least one entry per element";
  }
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
  // Constraints are code-point ascending (§6.2's SHOULD). Names are unique because they are object keys
  claimConstraints.sort((a, b) => (a.claimName < b.claimName ? -1 : 1));
  return claimConstraints;
}

/**
 * Code-point ascending sort + dedup of the elements (SHOULD.
 * Evaluation is existential — AUTH_SPEC §14-1 — so order and
 * duplicates do not affect the semantics, but this makes the signed
 * bytes deterministic).
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

/** Loading `--lease-policy <file>` (empty when omitted = no lease path). */
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
