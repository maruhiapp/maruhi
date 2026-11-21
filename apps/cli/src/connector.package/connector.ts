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

export type ConnectorServices = HttpClient.HttpClient | SqlRunner | ProcessRunner;

export function companionsOf(rule: RotateRule): Readonly<Record<string, string>> {
  return companionVariablesOf(rule);
}

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

export function rotateCredential(
  rule: RotateRule,
  current: CredentialValues,
  inputs: RotateInputs,
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

export function finalizeCredential(
  rule: RotateRule,
  previous: CredentialValues,
  current: CredentialValues,
  inputs: RotateInputs,
  ancestors: CompanionAncestors = {},
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

function requireSite(site: RotationSite | undefined): Effect.Effect<RotationSite, ConnectorError> {
  return site === undefined
    ? new ConnectorError({
        message: "exec: the rotation site (variable and environment) was not supplied",
      })
    : Effect.succeed(site);
}
