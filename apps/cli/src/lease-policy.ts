// Loading and normalizing `maruhi server grant --lease-policy
// <file>` (lease_policy — CRYPTO_SPEC §6.2). The argument layer is
// commands/server.ts. Wording is English per ADR-0017.

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import type { LeasePolicyIssuer } from "@maruhi/crypto";
import { Effect, FileSystem, Result, Schema } from "effect";

import { type CliError, usageError } from "./errors.ts";
import { JsonRecord, recordKeysMatch } from "./json-record.ts";

// Input-file limits of lease_policy (CRYPTO_SPEC §6.2). Same values
// as the consensus rules (an excess becomes invalid-payload at chain
// verification, so drop it at the input stage first)
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;
const MAX_LEASE_FIELD_BYTES = 1024;

// A lease_policy field: a string bounded to MAX_LEASE_FIELD_BYTES **bytes**
// (UTF-8 — the §6.2 consensus bound is on bytes, not characters).
const byteBounded = (value: string, allowEmpty: boolean): boolean =>
  (allowEmpty || value.length > 0) &&
  new TextEncoder().encode(value).length <= MAX_LEASE_FIELD_BYTES;

// issuerUrl / audience: non-empty bounded strings.
const LeaseField = Schema.String.check(
  Schema.makeFilter((value) => byteBounded(value, false) || "a non-empty bounded string"),
);
const LeaseFields = Schema.Struct({ issuerUrl: LeaseField, audience: LeaseField });

// A claim constraint value: a bounded string (empty is allowed).
const LeaseValue = Schema.String.check(
  Schema.makeFilter((value) => byteBounded(value, true) || "a bounded string"),
);
const ClaimConstraintsSchema = Schema.Record(Schema.String, LeaseValue).check(
  recordKeysMatch((name) => byteBounded(name, false)),
);

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
  const parsed = Schema.decodeUnknownResult(Schema.fromJsonString(Schema.Unknown))(content);
  if (Result.isFailure(parsed)) {
    return "not valid JSON";
  }
  if (!Array.isArray(parsed.success)) {
    return "the top level must be an array of elements";
  }
  if (parsed.success.length > MAX_LEASE_POLICY_ISSUERS) {
    return `at most ${MAX_LEASE_POLICY_ISSUERS} elements are allowed (consensus rule — CRYPTO_SPEC §6.2)`;
  }
  const elements: LeasePolicyIssuer[] = [];
  for (const element of parsed.success) {
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
  if (!Schema.is(JsonRecord)(element)) {
    return "each element must be an object of { issuerUrl, audience, claimConstraints }";
  }
  const fields = Schema.decodeUnknownResult(LeaseFields)(element);
  if (Result.isFailure(fields)) {
    return `issuerUrl / audience must be non-empty strings (at most ${MAX_LEASE_FIELD_BYTES} bytes each)`;
  }
  if (!Object.hasOwn(element, "claimConstraints")) {
    return "claimConstraints is required for every element";
  }
  const claimConstraints = parseLeaseConstraints(element.claimConstraints);
  if (typeof claimConstraints === "string") {
    return claimConstraints;
  }
  return {
    issuerUrl: fields.success.issuerUrl,
    audience: fields.success.audience,
    claimConstraints,
  };
}

/** Interprets and ascending-sorts the claimConstraints object (a reason string when malformed). */
function parseLeaseConstraints(
  value: unknown,
): { claimName: string; claimValue: string }[] | string {
  if (!Schema.is(JsonRecord)(value)) {
    return "claimConstraints must be an object of { claimName: value }";
  }
  const count = Object.keys(value).length;
  if (count === 0) {
    return "claimConstraints must have at least one entry per element";
  }
  if (count > MAX_LEASE_CLAIM_CONSTRAINTS) {
    return `claimConstraints may have at most ${MAX_LEASE_CLAIM_CONSTRAINTS} entries per element (consensus rule)`;
  }
  if (!Schema.is(ClaimConstraintsSchema)(value)) {
    return `claim constraint names must be non-empty and values must be strings (each at most ${MAX_LEASE_FIELD_BYTES} bytes)`;
  }
  // Constraints are code-point ascending (§6.2's SHOULD). Names are unique because they are object keys
  return Object.entries(value)
    .map(([claimName, claimValue]) => ({ claimName, claimValue }))
    .toSorted((a, b) => (a.claimName < b.claimName ? -1 : 1));
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
    const fs = yield* FileSystem.FileSystem;
    const content = yield* fs
      .readFileString(path, "utf8")
      .pipe(
        Effect.mapError(() => usageError("Cannot read the --lease-policy file (check the path)")),
      );
    const parsed = parseLeasePolicy(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(usageError(`--lease-policy content is invalid: ${parsed}`));
    }
    return parsed;
  }).pipe(Effect.provide(BunFileSystem.layer));
}
