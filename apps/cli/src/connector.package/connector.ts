// The connector frame of `maruhi var rotate` (PF6 — integration-options.md
// §4 option R2, §7 part ② "the connector frame is a client implementation";
// docs/notes/pf6-design.md rulings R2 / R3 / R4): the member's CLI creates a
// new credential at the issuer, the caller pushes it signed as the writer,
// and the old credential stays valid until `--finalize` invalidates it (the
// dual-credential grace period every competitor converged on — Infisical's
// active / inactive slots, Pulumi ESC's current / previous, AWS Secrets
// Manager's AWSCURRENT / AWSPREVIOUS).
//
// Five connectors in four files:
//   - `aws-iam-access-key` (connector-aws-iam.ts): CreateAccessKey
//     (reclaiming an inactive second key first — IAM allows two); finalize
//     = UpdateAccessKey Inactive on the previous key (reversible; the next
//     rotation deletes an inactive key)
//   - `cloudflare-api-token` (connector-cloudflare.ts): a second token with
//     the same policies (create-new-then-delete-old — a roll would
//     invalidate the old value at once); finalize = DELETE the previous
//     token
//   - `postgres` (connector-sql.ts): two roles alternated (ALTER ROLE …
//     PASSWORD on the one not in use; finalize scrambles the previous
//     role's password), or one role in place (no grace — the password
//     changes at once, and the caller asks for confirmation)
//   - `mysql` (connector-sql.ts): the same two shapes, plus MySQL 8's dual
//     password for the in-place one (RETAIN CURRENT PASSWORD; finalize =
//     DISCARD OLD PASSWORD)
//   - `exec` (connector-exec.ts — PF8): a script of the repository prints
//     the new credential; finalize = the rule's finalize script, run with
//     the previous credential (a rule without one has its rotate script
//     retire the previous credential at once)
//
// This file is the frame: it plans a rotation from the rule and the
// current value, runs the rule's connector for the rotation and for a
// finalize (with the services a run requires, ConnectorServices), and
// describes what each connector's finalize does. What the connectors share
// — the issuer origins a run targets, the credential and outcome types,
// ConnectorError and the value shapes — lives in connector-shared.ts.
//
// The issuer's admin credential is a maruhi variable decrypted into memory
// by the caller (never on the server, never on disk); with no admin input
// the credential rotates itself. New passwords are generated from
// `crypto.getRandomValues` (32 alphanumerics — URL-safe and quote-safe —
// connector-sql.ts).
//
// Why this is not a CRYPTO_SPEC operation: every call a connector makes is
// a client of a third party's own protocol on the member's behalf
// (CRYPTO_SPEC §12's scope note, class (b)); maruhi's data is touched only
// by the caller's ordinary signed push.
//
// Error wording carries the connector, the issuer's status code and
// message — never a credential, a password, or a URL with a password in it.

import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import type { ProcessRunner } from "../run.ts";
import { currentKeyId, finalizeAwsIam, rotateAwsIam } from "./connector-aws-iam.ts";
import { finalizeCloudflare, rotateCloudflare } from "./connector-cloudflare.ts";
import { finalizeExec, rotateExec } from "./connector-exec.ts";
import {
  type CompanionAncestors,
  ConnectorError,
  type ConnectorOutcome,
  type CredentialValues,
  type FinalizeOutcome,
  type RotateInputs,
  type RotationOutcome,
  type RotationPlan,
  type RotationSite,
  shapeOf,
} from "./connector-shared.ts";
import {
  dbPlan,
  finalizeMysql,
  finalizePostgres,
  rotateMysql,
  rotatePostgres,
  type SqlRunner,
} from "./connector-sql.ts";
import { companionVariablesOf, type RotateRule } from "./rotate-config.ts";

/**
 * The services a connector run requires — the command's ambient ones (the
 * CLI's egress `HttpClient`, `SqlRunner`, `ProcessRunner`). The `Clock`,
 * `IssuerEndpoints` (connector-shared.ts) and `ConnectorCrypto`
 * (connector-sql.ts) are read from the run's context too, with their
 * defaults in production.
 */
export type ConnectorServices = HttpClient.HttpClient | SqlRunner | ProcessRunner;

/** The companions a rule's credential carries (companion name → the variable that holds it). */
export function companionsOf(rule: RotateRule): Readonly<Record<string, string>> {
  return companionVariablesOf(rule);
}

/** What the rotation will do at the issuer (decided from the current value alone — nothing is sent). */
export function planRotation(
  rule: RotateRule,
  current: CredentialValues,
): Effect.Effect<RotationPlan, ConnectorError> {
  switch (rule.connector) {
    case "postgres":
    case "mysql":
      return dbPlan(rule, current);
    case "aws-iam-access-key":
      return Effect.map(currentKeyId(current), (keyId) => ({
        description: `create a second access key for the IAM user (the current key ${keyId} stays active until you finalize)`,
        immediate: false,
      }));
    case "cloudflare-api-token":
      return Effect.succeed({
        description:
          "create a second token with the current token's policies (the current token stays valid until you finalize)",
        immediate: false,
      });
    case "exec":
      return Effect.succeed(
        rule.finalize === null
          ? {
              description: `run ${rule.rotate[0] ?? ""} — the rule has no finalize script, so that script is expected to retire the current credential itself (no grace period)`,
              immediate: true,
            }
          : {
              description: `run ${rule.rotate[0] ?? ""} to create the new credential (the current one stays valid until you finalize with ${rule.finalize[0] ?? ""})`,
              immediate: false,
            },
      );
  }
}

/** Creates the new credential at the issuer. Fails with {@link ConnectorError}. */
export function rotateCredential(
  rule: RotateRule,
  current: CredentialValues,
  inputs: RotateInputs,
  /** Where the rotation happens (the `exec` connector's scripts receive it; required for that connector). */
  site?: RotationSite,
): Effect.Effect<RotationOutcome, ConnectorError, ConnectorServices> {
  return Effect.map(rotateWith(rule, current, inputs, site), (outcome) => ({
    ...outcome,
    shape: shapeOf(outcome.values.primary),
    companionShapes: Object.fromEntries(
      Object.entries(outcome.values.companions).map(([name, bytes]) => [name, shapeOf(bytes)]),
    ),
    currentShape: shapeOf(current.primary),
  }));
}

function rotateWith(
  rule: RotateRule,
  current: CredentialValues,
  inputs: RotateInputs,
  site?: RotationSite,
): Effect.Effect<ConnectorOutcome, ConnectorError, ConnectorServices> {
  switch (rule.connector) {
    case "postgres":
      return rotatePostgres(rule, current, inputs);
    case "mysql":
      return rotateMysql(rule, current, inputs);
    case "aws-iam-access-key":
      return rotateAwsIam(rule, current, inputs);
    case "cloudflare-api-token":
      return rotateCloudflare(rule, current, inputs);
    case "exec":
      return requireSite(site).pipe(
        Effect.flatMap((resolved) => rotateExec(rule, resolved, current, inputs)),
      );
  }
}

/** What finalizing will do, in one line (for the confirmation). */
export function describeFinalize(rule: RotateRule): string {
  switch (rule.connector) {
    case "postgres":
      return rule.roles === null
        ? "nothing to invalidate (an in-place password change has no previous credential)"
        : "replace the previous role's password with a random one nobody holds";
    case "mysql":
      return rule.roles === null
        ? "discard the account's secondary (previous) password"
        : "replace the previous account's password with a random one nobody holds";
    case "aws-iam-access-key":
      return "deactivate the access key that authenticates with the previous version's secret at the issuer (only a key id an earlier version of the key id variable held; reversible at the issuer; deleted by the next rotation)";
    case "cloudflare-api-token":
      return "delete the previous token";
    case "exec":
      return rule.finalize === null
        ? "nothing to invalidate (the rule has no finalize script — its rotate script retires the previous credential itself)"
        : `run ${rule.finalize[0] ?? ""} with the previous credential in its environment (MH_ROTATE_PREVIOUS)`;
  }
}

/** Invalidates the previous credential at the issuer. Fails with {@link ConnectorError}. */
export function finalizeCredential(
  rule: RotateRule,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  ancestors: CompanionAncestors = {},
  /** Where the rotation happens (required for the `exec` connector). */
  site?: RotationSite,
): Effect.Effect<FinalizeOutcome, ConnectorError, ConnectorServices> {
  switch (rule.connector) {
    case "postgres":
      return finalizePostgres(rule, previous, current, inputs);
    case "mysql":
      return finalizeMysql(rule, previous, current, inputs);
    case "aws-iam-access-key":
      return finalizeAwsIam(rule, previous, current, inputs, ancestors);
    case "cloudflare-api-token":
      return finalizeCloudflare(rule, previous, current, inputs);
    case "exec":
      return requireSite(site).pipe(
        Effect.flatMap((resolved) => finalizeExec(rule, resolved, previous, current, inputs)),
      );
  }
}

/** The exec connector cannot run without knowing the variable and environment (an internal inconsistency, never a user error). */
function requireSite(site: RotationSite | undefined): Effect.Effect<RotationSite, ConnectorError> {
  return site === undefined
    ? new ConnectorError({
        message: "exec: the rotation site (variable and environment) was not supplied",
      })
    : Effect.succeed(site);
}
