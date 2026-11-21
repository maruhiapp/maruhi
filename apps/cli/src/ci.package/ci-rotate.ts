import { ProjectNotFoundError, RotationProposalRejectedError } from "@maruhi/api-schema";
import {
  cryptoEffect,
  type EnvironmentId,
  type ProjectId,
  type UserId,
  type VariableId,
} from "@maruhi/core";
import type { ProposalRecipient } from "@maruhi/crypto";
import {
  decodeHex,
  encodeHex,
  importEncryptionPublicKey,
  isProposalId,
  proposalRecipientsOf,
  sealProposedValue,
} from "@maruhi/crypto";
import { Clock, Effect, Redacted } from "effect";
import type { HttpClient } from "effect/http";

import {
  companionsOf,
  type CredentialValues,
  describeShape,
  describeValueShapes,
  planRotation,
  type RotateConfig,
  type RotateInputs,
  rotateCredential,
  type RotateRule,
  type RotationOutcome,
  ruleFor,
  type SqlRunner,
} from "../connector.package/index.ts";
import { cryptoErrorKind } from "../crypto-error-kind.ts";
import { countNoun, displayText, formatUtcDate, logWarnings } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import type { VerifiedLeaseMaterial } from "../lease.package/index.ts";
import { fetchGitHubOidcToken, issuanceBoundFor, tokenExpiresAtMs } from "../oidc-github.ts";
import type { DecryptedVariable } from "../pull.ts";
import type { ProcessRunner } from "../run.ts";
import { callConnector, connectorFailure } from "../var.package/index.ts";
import {
  type CiLeaseInput,
  LEASE_NOT_FOUND_MESSAGE,
  type LeasedEnvironments,
  leaseEnvironmentsWithCredential,
} from "./ci-lease.ts";

const MAX_FACTS = 16;
const MAX_FACT_LENGTH = 256;

interface CiRotateInput extends CiLeaseInput {
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly config: RotateConfig;
  readonly configPath: string;
  readonly expiresInDays: number;
}

export interface CiRotateResult {
  readonly proposalId: string;
  readonly primary: string;
  readonly connector: RotateRule["connector"];
  readonly variables: readonly {
    readonly name: string;
    readonly variableId: VariableId;
    readonly baseVersion: number;
  }[];
  readonly recipientDevices: number;
  readonly recipientMembers: number;
  readonly facts: readonly string[];
  readonly valueShape: string;
  readonly currentShape: string;
  readonly previous: string;
  readonly expiresAtMs: number;
  readonly resealed: boolean;
}

type ByName = ReadonlyMap<string, DecryptedVariable>;

function byNameOf(material: VerifiedLeaseMaterial): ByName {
  return new Map(material.variables.map((variable) => [variable.name, variable]));
}

function inputEnvironments(
  rule: RotateRule,
  environmentId: EnvironmentId,
): readonly EnvironmentId[] {
  const others = new Set<EnvironmentId>();
  for (const ref of Object.values(rule.inputs)) {
    if (ref.environment !== null && ref.environment !== environmentId) {
      others.add(ref.environment);
    }
  }
  return [...others].toSorted();
}

function missingValue(name: string, where: string, primary: string): CliError {
  return cliError(
    `Variable ${displayText(name)} has no value in ${where} (the rotation rule for ${displayText(primary)} needs it). Nothing was sent to the issuer`,
  );
}

const currentCredential = Effect.fn("ci-rotate.currentCredential")(function* (
  primary: string,
  rule: RotateRule,
  local: ByName,
): Effect.fn.Return<CredentialValues, CliError> {
  const own = local.get(primary);
  if (own === undefined) {
    return yield* Effect.fail(missingValue(primary, "this environment", primary));
  }
  const companions: Record<string, Uint8Array> = {};
  for (const [companion, variable] of Object.entries(companionsOf(rule))) {
    const value = local.get(variable);
    if (value === undefined) {
      return yield* Effect.fail(missingValue(variable, "this environment", primary));
    }
    companions[companion] = Redacted.value(value.value);
  }
  return { primary: Redacted.value(own.value), companions };
});

const leasedInputs = Effect.fn("ci-rotate.leasedInputs")(function* (
  primary: string,
  rule: RotateRule,
  environmentId: EnvironmentId,
  materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
): Effect.fn.Return<RotateInputs, CliError> {
  const inputs: Record<string, Uint8Array> = {};
  for (const [inputName, ref] of Object.entries(rule.inputs)) {
    const sourceEnvironment = ref.environment ?? environmentId;
    const material = materials.get(sourceEnvironment);
    const value = material === undefined ? undefined : byNameOf(material).get(ref.name);
    if (value === undefined) {
      const where =
        sourceEnvironment === environmentId
          ? "this environment"
          : `environment ${displayText(sourceEnvironment)}`;
      return yield* Effect.fail(
        cliError(
          `The rotation rule for ${displayText(primary)} names variable ${displayText(ref.name)} in ${where} as its ${inputName}, but it has no value there. Set it with \`maruhi push\`, or fix the rule. Nothing was sent to the issuer`,
        ),
      );
    }
    inputs[inputName] = Redacted.value(value.value);
  }
  return inputs;
});

function acceptableFacts(facts: readonly string[]): readonly string[] {
  return facts
    .map((fact) => displayText(fact).slice(0, MAX_FACT_LENGTH))
    .filter((fact) => fact.length > 0)
    .slice(0, MAX_FACTS);
}

interface PlannedValue {
  readonly name: string;
  readonly variableId: VariableId;
  readonly baseVersion: number;
  readonly bytes: Uint8Array;
}

const plannedValues = Effect.fn("ci-rotate.plannedValues")(function* (
  primary: string,
  rule: RotateRule,
  local: ByName,
  outcome: RotationOutcome,
): Effect.fn.Return<readonly PlannedValue[], CliError> {
  const planned: PlannedValue[] = [];
  const push = (name: string, bytes: Uint8Array) =>
    Effect.gen(function* () {
      const variable = local.get(name);
      if (variable === undefined) {
        return yield* Effect.fail(missingValue(name, "this environment", primary));
      }
      planned.push({
        name,
        variableId: variable.variableId,
        baseVersion: variable.version,
        bytes,
      });
    });
  for (const [companion, variable] of Object.entries(companionsOf(rule))) {
    const bytes = outcome.values.companions[companion];
    if (bytes !== undefined) {
      yield* push(variable, bytes);
    }
  }
  yield* push(primary, outcome.values.primary);
  return planned;
});

interface SealedWrap {
  readonly recipientUserId: UserId;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

function sealToRecipients(input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly proposalId: string;
  readonly variableId: VariableId;
  readonly baseVersion: number;
  readonly bytes: Uint8Array;
  readonly recipients: readonly ProposalRecipient[];
}): Effect.Effect<readonly SealedWrap[], CliError> {
  return Effect.forEach(input.recipients, ({ member, device }) =>
    Effect.gen(function* () {
      const keyBytes = decodeHex(device.encPubHex);
      if (keyBytes === null) {
        return yield* Effect.fail(
          cliError(
            `Cannot load the device key ${device.keyFingerprintHex} of member ${displayText(member.userId)} from the chain (a corrupt public key)`,
          ),
        );
      }
      const publicKey = yield* cryptoEffect(() => importEncryptionPublicKey(keyBytes)).pipe(
        Effect.mapError(() =>
          cliError(
            `Cannot load the device key ${device.keyFingerprintHex} of member ${displayText(member.userId)} from the chain (a corrupt public key)`,
          ),
        ),
      );
      const sealed = yield* cryptoEffect(() =>
        sealProposedValue({
          recipientPublicKey: publicKey,
          value: input.bytes,
          context: {
            projectId: input.projectId,
            environmentId: input.environmentId,
            proposalId: input.proposalId,
            variableId: input.variableId,
            baseVersion: input.baseVersion,
            recipientUserId: member.userId,
          },
        }),
      ).pipe(
        Effect.mapError((error) =>
          cliError(
            `Sealing the new value of ${displayText(input.variableId)} to member ${displayText(member.userId)} failed (${cryptoErrorKind(error)})`,
          ),
        ),
      );
      return {
        recipientUserId: member.userId,
        recipientEncPubHex: device.encPubHex,
        encHex: encodeHex(sealed.enc),
        ciphertextHex: encodeHex(sealed.ciphertext),
      };
    }),
  );
}

const preflightVariables = Effect.fn("ci-rotate.preflightVariables")(function* (
  primary: string,
  rule: RotateRule,
  local: ByName,
): Effect.fn.Return<readonly { variableId: VariableId; baseVersion: number }[], CliError> {
  const variables: { variableId: VariableId; baseVersion: number }[] = [];
  for (const name of [...Object.values(companionsOf(rule)), primary]) {
    const variable = local.get(name);
    if (variable === undefined) {
      return yield* Effect.fail(missingValue(name, "this environment", primary));
    }
    variables.push({ variableId: variable.variableId, baseVersion: variable.version });
  }
  return variables;
});

function preflightRefusal(error: unknown, primary: string): CliError {
  const refuse = (why: string, step: string) =>
    cliError(
      `Refusing to rotate ${displayText(primary)} from CI: the server would not store the proposal (${why}). ${step}. Nothing was sent to the issuer`,
    );
  if (error instanceof RotationProposalRejectedError) {
    switch (error.reason) {
      case "variable-pending":
        return refuse(
          "a sealed proposal for one of its variables is already pending",
          "A member accepts or rejects it first (`maruhi rotation proposals`, then `maruhi rotation accept <id>` or `maruhi rotation reject <id>`); re-run the job after that",
        );
      case "base-version-stale":
        return refuse(
          "a member pushed the variable after this job leased it",
          "Re-run the job once the members are done",
        );
      case "pending-limit":
        return refuse(
          "the project already holds the maximum number of pending proposals",
          "A member accepts or rejects some with `maruhi rotation proposals`, then re-run the job",
        );
      case "storage-limit":
        return refuse(
          "the project's stored data has reached the server's storage guard (AUTH_SPEC §12-8)",
          "No new value can be pushed to it either until its members free space or move the project; re-run the job then (against the new project if it moved)",
        );
      default:
        return refuse(`${error.reason} (AUTH_SPEC §14-5)`, "Check the rule and re-run the job");
    }
  }
  if (error instanceof ProjectNotFoundError) {
    return refuse("a uniform 404", LEASE_NOT_FOUND_MESSAGE);
  }
  return refuse(toCliError(error).message, "Re-run the job");
}

function mintRefusal(error: unknown, outcome: RotationOutcome): CliError {
  const next = (why: string, step: string) =>
    cliError(
      `The issuer accepted the rotation (${outcome.facts.join("; ")}) but the server refused to store the proposal: ${why}. ${step}. Recovery for the credential that now exists at the issuer: ${outcome.recovery}`,
    );
  if (error instanceof RotationProposalRejectedError) {
    switch (error.reason) {
      case "base-version-stale":
        return next(
          "a member pushed the variable after this job leased it",
          "Re-run the job once the members are done",
        );
      case "recipients-mismatch":
        return next(
          "the project's members or devices changed after this job leased it",
          "Re-run the job",
        );
      case "pending-limit":
        return next(
          "the project already holds the maximum number of pending proposals",
          "A member accepts or rejects some with `maruhi rotation proposals`, then re-run the job",
        );
      case "storage-limit":
        return next(
          "the project's stored data has reached the server's storage guard, or the proposal would pass its ciphertext limit (AUTH_SPEC §12-8)",
          "No new value can be pushed to it either until its members free space or move the project; re-run the job then (against the new project if it moved)",
        );
      default:
        return next(`${error.reason} (AUTH_SPEC §14-5)`, "Check the rule and re-run the job");
    }
  }
  if (error instanceof ProjectNotFoundError) {
    return next("a uniform 404", LEASE_NOT_FOUND_MESSAGE);
  }
  return next(toCliError(error).message, "Re-run the job");
}

export const ciRotateOp = Effect.fn("ci-rotate.ciRotateOp")(function* (
  input: CiRotateInput,
): Effect.fn.Return<
  CiRotateResult,
  CliError,
  CliIo | HttpClient.HttpClient | SqlRunner | ProcessRunner
> {
  const target = ruleFor(input.config, input.name.normalize("NFC"));
  if (target === null) {
    return yield* Effect.fail(
      cliError(
        `No rotation rule for ${displayText(input.name)} in ${displayText(input.configPath)}. Add one (see the Rotation page in the docs). Nothing was leased`,
      ),
    );
  }
  if (!isProposalId(encodeHex(new Uint8Array(16)))) {
    return yield* Effect.fail(cliError("internal: the proposal id form is inconsistent"));
  }
  const { rule, primary } = target;
  const leased = yield* leaseEnvironmentsWithCredential({
    ...input,
    environmentIds: [input.environmentId, ...inputEnvironments(rule, input.environmentId)],
  });
  const material = leased.materials.get(input.environmentId);
  if (material === undefined) {
    return yield* Effect.fail(cliError("The lease returned no material (internal inconsistency)"));
  }
  const local = byNameOf(material);
  const current = yield* currentCredential(primary, rule, local);
  const inputs = yield* leasedInputs(primary, rule, input.environmentId, leased.materials);
  const plan = yield* planRotation(rule, current).pipe(
    Effect.catchTag("ConnectorError", (error) => Effect.fail(connectorFailure(error))),
  );
  if (plan.immediate) {
    return yield* Effect.fail(
      cliError(
        `Refusing to propose a rotation of ${displayText(primary)} from CI: this rule's rotation invalidates the current credential at once (${plan.description}). A sealed proposal keeps the current credential in use until a member accepts it, so it needs a rule with a grace period (a finalize step). Run \`maruhi var rotate ${displayText(primary)}\` from a member's machine instead. Nothing was sent to the issuer`,
      ),
    );
  }
  const recipients = proposalRecipientsOf(material.verified.state, input.environmentId);
  if (recipients.length === 0) {
    return yield* Effect.fail(
      cliError(
        `No member device can accept a proposal for environment ${displayText(input.environmentId)} (nobody with role member or above has it in scope). Nothing was sent to the issuer`,
      ),
    );
  }
  const params = { projectId: input.projectId, environmentId: input.environmentId };
  yield* leased.client.lease
    .preflight({
      params,
      payload: {
        oidcToken: Redacted.value(leased.credential.token),
        ephemeralPubHex: leased.credential.ephemeralPubHex,
        variables: yield* preflightVariables(primary, rule, local),
        recipients: recipients.map(({ member, device }) => ({
          userId: member.userId,
          encPubHex: device.encPubHex,
        })),
      },
    })
    .pipe(Effect.mapError((error) => preflightRefusal(error, primary)));
  const site = { variable: primary, environmentId: input.environmentId };
  const outcome = yield* callConnector(rotateCredential(rule, current, inputs, site));
  const planned = yield* plannedValues(primary, rule, local, outcome);
  const io = yield* CliIo;
  const mintInput = { input, rule, planned, outcome, params };
  const mintToken = yield* mintTokenFor(input, leased, outcome);
  const minted = yield* sealAndMint({
    ...mintInput,
    lease: leased,
    recipients,
    token: mintToken,
  }).pipe(
    Effect.catchTag(
      "RotationProposalRejected",
      (error) =>
        error.reason === "recipients-mismatch"
          ? Effect.gen(function* () {
              yield* io.logError(
                "The project's members or devices changed after this job leased it: leasing again and sealing the proposal to the current recipients (once)",
              );
              const again = yield* leaseEnvironmentsWithCredential({
                ...input,
                environmentIds: [input.environmentId],
                credential: { ...leased.credential, token: mintToken },
              }).pipe(Effect.mapError((failure) => mintRefusal(failure, outcome)));
              const againMaterial = again.materials.get(input.environmentId);
              if (againMaterial === undefined) {
                return yield* Effect.fail(
                  cliError("The lease returned no material (internal inconsistency)"),
                );
              }
              const againRecipients = proposalRecipientsOf(
                againMaterial.verified.state,
                input.environmentId,
              );
              const second = yield* sealAndMint({
                ...mintInput,
                lease: again,
                recipients: againRecipients,
                token: yield* mintTokenFor(input, again, outcome),
              }).pipe(Effect.mapError((failure) => mintRefusal(failure, outcome)));
              return { ...second, resealed: true };
            })
          : Effect.fail(mintRefusal(error, outcome)),
      (error) => Effect.fail(mintRefusal(error, outcome)),
    ),
  );
  yield* logWarnings([...material.warnings, ...outcome.warnings]);
  return {
    proposalId: minted.proposalId,
    primary,
    connector: rule.connector,
    variables: planned.map(({ name, variableId, baseVersion }) => ({
      name,
      variableId,
      baseVersion,
    })),
    recipientDevices: minted.recipients.length,
    recipientMembers: new Set(minted.recipients.map((recipient) => recipient.member.userId)).size,
    facts: outcome.facts,
    valueShape: describeValueShapes(outcome),
    currentShape: describeShape(outcome.currentShape),
    previous: outcome.previous,
    expiresAtMs: minted.expiresAtMs,
    resealed: minted.resealed,
  };
});

interface SealAndMintInput {
  readonly input: CiRotateInput;
  readonly rule: RotateRule;
  readonly planned: readonly PlannedValue[];
  readonly outcome: RotationOutcome;
  readonly params: { readonly projectId: ProjectId; readonly environmentId: EnvironmentId };
  readonly lease: LeasedEnvironments;
  readonly recipients: readonly ProposalRecipient[];
  readonly token: Redacted.Redacted<string>;
}

interface Minted {
  readonly proposalId: string;
  readonly expiresAtMs: number;
  readonly recipients: readonly ProposalRecipient[];
  readonly resealed: boolean;
}

const sealAndMint = Effect.fn("ci-rotate.sealAndMint")(function* (
  mint: SealAndMintInput,
): Effect.fn.Return<Minted, CliError | RotationProposalRejectedError, CliIo> {
  const { input, outcome, lease, recipients } = mint;
  const proposalId = encodeHex(crypto.getRandomValues(new Uint8Array(16)));
  const variables = yield* Effect.forEach(mint.planned, (value) =>
    Effect.map(
      sealToRecipients({
        projectId: input.projectId,
        environmentId: input.environmentId,
        proposalId,
        variableId: value.variableId,
        baseVersion: value.baseVersion,
        bytes: value.bytes,
        recipients,
      }),
      (wraps) => ({ variableId: value.variableId, baseVersion: value.baseVersion, wraps }),
    ),
  );
  const receipt = yield* lease.client.lease
    .propose({
      params: mint.params,
      payload: {
        oidcToken: Redacted.value(mint.token),
        ephemeralPubHex: lease.credential.ephemeralPubHex,
        proposal: {
          proposalId,
          connector: mint.rule.connector,
          facts: acceptableFacts(outcome.facts),
          expiresInDays: input.expiresInDays,
          variables,
        },
      },
    })
    .pipe(
      Effect.catchTag("RotationProposalRejected", Effect.fail, (error) =>
        Effect.fail(mintRefusal(error, outcome)),
      ),
    );
  return { proposalId, expiresAtMs: receipt.expiresAtMs, recipients, resealed: false };
});

const mintTokenFor = Effect.fn("ci-rotate.mintTokenFor")(function* (
  input: CiRotateInput,
  lease: LeasedEnvironments,
  outcome: RotationOutcome,
): Effect.fn.Return<Redacted.Redacted<string>, CliError, CliIo> {
  const boundNowMs = yield* Clock.currentTimeMillis;
  return yield* fetchGitHubOidcToken(
    input.audience,
    issuanceBoundFor(lease.credential.token, boundNowMs),
  ).pipe(
    Effect.catch((error) =>
      Effect.gen(function* () {
        const io = yield* CliIo;
        const expiresAtMs = tokenExpiresAtMs(lease.credential.token);
        const nowMs = yield* Clock.currentTimeMillis;
        if (expiresAtMs !== null && expiresAtMs <= nowMs) {
          return yield* Effect.fail(
            cliError(
              `The issuer accepted the rotation (${outcome.facts.join("; ")}) but no token is left to store the proposal: the lease's token expired at ${formatUtcDate(expiresAtMs)} before a fresh one could be minted (${error.message}). Recovery for the credential that now exists at the issuer: ${outcome.recovery}`,
            ),
          );
        }
        yield* io.logError(
          `Could not mint a fresh OIDC token for the proposal (${error.message}); presenting the lease's token`,
        );
        return lease.credential.token;
      }),
    ),
  );
});

export function describeProposal(result: CiRotateResult, environmentId: EnvironmentId): string[] {
  const names = result.variables.map(
    (variable) => `${displayText(variable.name)} (replacing version ${variable.baseVersion})`,
  );
  return [
    `Sealed proposal ${result.proposalId} stored for environment ${displayText(environmentId)}: ${names.join(", ")} — minted with the ${result.connector} connector, sealed to ${countNoun(result.recipientDevices, "device")} of ${countNoun(result.recipientMembers, "member")}, expires ${formatUtcDate(result.expiresAtMs)}`,
    ...result.facts.map((fact) => `  ${fact}`),
    `  value: ${result.valueShape} (the current value: ${result.currentShape}; the shape is shown here and at the acceptance only; it is not stored with the proposal)`,
    ...(result.resealed
      ? [
          "The proposal was sealed a second time: the members or devices changed after the lease, so the recipients were taken from the current chain",
        ]
      : []),
    `Previous credential: ${result.previous}`,
    `A member finishes the rotation with \`maruhi rotation accept ${result.proposalId}\` (it pushes the new value signed as that member) or drops it with \`maruhi rotation reject ${result.proposalId}\`. Until then the current credential stays in use; if nobody accepts before the expiry, retire the new credential at the issuer by hand`,
  ];
}
