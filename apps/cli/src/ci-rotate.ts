// `maruhi ci rotate <NAME>`: minting a sealed value proposal from a CI job
// (CRYPTO_SPEC §5.3 / AUTH_SPEC §14-5 — PF7b; the design record is
// docs/notes/pf7-pf8-design.md §6).
//
// The job holds only a workload lease (ci-lease.ts — no signing key, no
// keychain, no config file). It runs the rule's connector exactly like
// `maruhi var rotate` would (the current credential and the admin inputs
// decrypted in memory from the lease), but instead of pushing a signed
// version it seals the new values to the devices of the members who may
// accept them (W(E) — member or above, environment in scope) and stores
// the proposal under the same OIDC token and ephemeral key it leased
// with. A member finishes the rotation with `maruhi rotation accept`
// (rotation-proposals.ts): the push is theirs, signed on their machine.
//
// What this path refuses: a rule whose rotation invalidates the current
// credential at once (no grace period). A proposal can be rejected or
// expire, so the current credential must keep working until a member
// accepts — that is the dual-credential discipline of pf6-design.md §2.
//
// No plaintext leaves the process except sealed: the report names
// variables, counts, dates, and the connector's non-secret facts.

import { ProjectNotFoundError, RotationProposalRejectedError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import {
  decodeHex,
  effectivePermissionOf,
  encodeHex,
  importEncryptionPublicKey,
  isProposalId,
  scopeIncludesEnvironment,
  sealProposedValue,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/http";

import {
  type CiLeaseInput,
  LEASE_NOT_FOUND_MESSAGE,
  type LeasedEnvironments,
  leaseEnvironmentsWithCredential,
} from "./ci-lease.ts";
import { memberDevicesInOrder, ROLE_RANK } from "./dek-wrap.ts";
import { countNoun, displayText, formatUtcDate, logWarnings } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { VerifiedLeaseMaterial } from "./lease-client.ts";
import { fetchGitHubOidcToken, issuanceBoundFor, tokenExpiresAtMs } from "./oidc-github.ts";
import type { DecryptedVariable } from "./pull.ts";
import { type RotateConfig, type RotateRule, ruleFor } from "./rotate-config.ts";
import {
  companionsOf,
  type CredentialValues,
  describeShape,
  describeValueShapes,
  planRotation,
  type RotateDeps,
  type RotateInputs,
  rotateCredential,
  type RotationOutcome,
} from "./rotate-connector.ts";
import type { VerifiedProject } from "./sync.ts";
import { connectorFailure } from "./var-rotate.ts";

/** The server's bound on a proposal's lifetime (AUTH_SPEC §14-5 — 30 days). */
export const MAX_PROPOSAL_DAYS = 30;
/** AUTH_SPEC §14-5: at most 16 facts of 256 characters each. */
const MAX_FACTS = 16;
const MAX_FACT_LENGTH = 256;

/** Input of `maruhi ci rotate` (all from explicit flags — the same discipline as ci run). */
export interface CiRotateInput extends CiLeaseInput {
  readonly environmentId: EnvironmentId;
  /** The variable named on the command line (the rule's variable, or an AWS rule's key id companion). */
  readonly name: string;
  readonly config: RotateConfig;
  readonly configPath: string;
  readonly deps: RotateDeps;
  /** How many days the proposal waits for a member (1 to 30). */
  readonly expiresInDays: number;
  readonly now?: () => number;
}

export interface CiRotateResult {
  readonly proposalId: string;
  readonly primary: string;
  readonly connector: RotateRule["connector"];
  /** Every proposed variable, in push order (companions first), with the version it replaces. */
  readonly variables: readonly {
    readonly name: string;
    readonly variableId: string;
    readonly baseVersion: number;
  }[];
  /** The devices the values were sealed to, and the members they belong to. */
  readonly recipientDevices: number;
  readonly recipientMembers: number;
  readonly facts: readonly string[];
  /** The primary's shape, shown locally only (never a proposal fact — D-8). */
  readonly valueShape: string;
  /** The current primary's shape, beside the new one (D-16). */
  readonly currentShape: string;
  readonly previous: string;
  /** The expiry the server set (the receipt — the lifetime travels as days). */
  readonly expiresAtMs: number;
  /** Whether the proposal was sealed a second time after the recipients changed (O-7). */
  readonly resealed: boolean;
  readonly warnings: readonly string[];
}

/** One recipient device of W(E) (CRYPTO_SPEC §5.3). */
interface Recipient {
  readonly member: ChainMember;
  readonly device: ChainDevice;
}

/**
 * W(E): every device of each current member whose effective permission
 * (person ∩ device — §6.2) has role member or above and a scope that
 * includes E (R(E) minus readers, reader-capped devices, and server keys
 * — CRYPTO_SPEC §5.3). The same predicate as the server's acceptance
 * check; a set that differs is refused as recipients-mismatch.
 */
function proposalRecipients(
  verified: VerifiedProject,
  environmentId: string,
): readonly Recipient[] {
  return memberDevicesInOrder(verified).filter(({ member, device }) => {
    const effective = effectivePermissionOf(member, device);
    return (
      ROLE_RANK[effective.role] >= ROLE_RANK.member &&
      scopeIncludesEnvironment(effective.scope, environmentId)
    );
  });
}

type ByName = ReadonlyMap<string, DecryptedVariable>;

function byNameOf(material: VerifiedLeaseMaterial): ByName {
  return new Map(material.variables.map((variable) => [variable.name, variable]));
}

/** The environments the rule reads admin inputs from (the target's own excluded — leased together with it). */
function inputEnvironments(rule: RotateRule, environmentId: string): readonly EnvironmentId[] {
  const others = new Set<string>();
  for (const ref of Object.values(rule.inputs)) {
    if (ref.environment !== null && ref.environment !== environmentId) {
      others.add(ref.environment);
    }
  }
  return [...others].toSorted() as EnvironmentId[];
}

function missingValue(name: string, where: string, primary: string): CliError {
  return cliError(
    `Variable ${displayText(name)} has no value in ${where} (the rotation rule for ${displayText(primary)} needs it). Nothing was sent to the issuer`,
  );
}

/** The rule's credential as leased: the primary and every companion. */
function currentCredential(
  primary: string,
  rule: RotateRule,
  local: ByName,
): Effect.Effect<CredentialValues, CliError> {
  return Effect.gen(function* () {
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
    // Why it is unwrapped: the connector consumes the credential in memory
    // to authenticate the rotation at the issuer (the same as var rotate)
    return { primary: Redacted.value(own.value), companions };
  });
}

/** The admin inputs the rule names, from the leased environments (a missing one stops before anything is sent). */
function leasedInputs(
  primary: string,
  rule: RotateRule,
  environmentId: string,
  materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
): Effect.Effect<RotateInputs, CliError> {
  return Effect.gen(function* () {
    const inputs: Record<string, Uint8Array> = {};
    for (const [inputName, ref] of Object.entries(rule.inputs)) {
      const sourceEnvironment = ref.environment ?? environmentId;
      const material = materials.get(sourceEnvironment as EnvironmentId);
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
}

/** The facts the server accepts (AUTH_SPEC §14-5): at most 16, each neutralized and at most 256 characters. */
function acceptableFacts(facts: readonly string[]): readonly string[] {
  return facts
    .map((fact) => displayText(fact).slice(0, MAX_FACT_LENGTH))
    .filter((fact) => fact.length > 0)
    .slice(0, MAX_FACTS);
}

interface PlannedValue {
  readonly name: string;
  readonly variableId: string;
  readonly baseVersion: number;
  readonly bytes: Uint8Array;
}

/** The values to propose, companions first (the same order as var rotate's pushes), each with the version it replaces. */
function plannedValues(
  primary: string,
  rule: RotateRule,
  local: ByName,
  outcome: RotationOutcome,
): Effect.Effect<readonly PlannedValue[], CliError> {
  return Effect.gen(function* () {
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
}

interface SealedWrap {
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** Seals one value to every recipient device (one HPKE Seal per device — §5.3). */
function sealToRecipients(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly proposalId: string;
  readonly variableId: string;
  readonly baseVersion: number;
  readonly bytes: Uint8Array;
  readonly recipients: readonly Recipient[];
}): Effect.Effect<readonly SealedWrap[], CliError> {
  return Effect.forEach(input.recipients, ({ member, device }) =>
    Effect.gen(function* () {
      const keyBytes = decodeHex(device.encPubHex);
      const publicKey =
        keyBytes === null ? null : yield* Effect.promise(() => importEncryptionPublicKey(keyBytes));
      if (publicKey === null || !publicKey.ok) {
        return yield* Effect.fail(
          cliError(
            `Cannot load the device key ${device.keyFingerprintHex} of member ${displayText(member.userId)} from the chain (a corrupt public key)`,
          ),
        );
      }
      const sealed = yield* Effect.promise(() =>
        sealProposedValue({
          recipientPublicKey: publicKey.value,
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
      );
      if (!sealed.ok) {
        return yield* Effect.fail(
          cliError(
            `Sealing the new value of ${displayText(input.variableId)} to member ${displayText(member.userId)} failed (${sealed.error.kind})`,
          ),
        );
      }
      return {
        recipientUserId: member.userId,
        recipientEncPubHex: device.encPubHex,
        encHex: encodeHex(sealed.value.enc),
        ciphertextHex: encodeHex(sealed.value.ciphertext),
      };
    }),
  );
}

/** Why the server refused the mint, with the job's next step (the issuer already accepted the rotation). */
/** The variables the mint will name, with the versions the lease holds (the pre-flight's input — O-4). */
function preflightVariables(
  primary: string,
  rule: RotateRule,
  local: ByName,
): Effect.Effect<readonly { variableId: string; baseVersion: number }[], CliError> {
  return Effect.gen(function* () {
    const variables: { variableId: string; baseVersion: number }[] = [];
    for (const name of [...Object.values(companionsOf(rule)), primary]) {
      const variable = local.get(name);
      if (variable === undefined) {
        return yield* Effect.fail(missingValue(name, "this environment", primary));
      }
      variables.push({ variableId: variable.variableId, baseVersion: variable.version });
    }
    return variables;
  });
}

/** The pre-flight's refusal (before the issuer is touched — nothing exists to recover). */
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
      default:
        return next(`${error.reason} (AUTH_SPEC §14-5)`, "Check the rule and re-run the job");
    }
  }
  if (error instanceof ProjectNotFoundError) {
    return next("a uniform 404", LEASE_NOT_FOUND_MESSAGE);
  }
  return next(toCliError(error).message, "Re-run the job");
}

/**
 * Leases the environment (and the environments the rule's admin inputs
 * live in), runs the connector, seals the new values to W(E), and stores
 * the proposal under the lease's credential. Values are never displayed.
 */
export function ciRotateOp(
  input: CiRotateInput,
): Effect.Effect<CiRotateResult, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const target = ruleFor(input.config, input.name.normalize("NFC"));
    if (target === null) {
      return yield* Effect.fail(
        cliError(
          `No rotation rule for ${displayText(input.name)} in ${displayText(input.configPath)}. Add one (see the Rotation page in the docs). Nothing was leased`,
        ),
      );
    }
    if (!isProposalId(encodeHex(new Uint8Array(16)))) {
      // Unreachable (a fixed-size hex); keeps the id form pinned to the crypto package's definition
      return yield* Effect.fail(cliError("internal: the proposal id form is inconsistent"));
    }
    const { rule, primary } = target;
    const leased = yield* leaseEnvironmentsWithCredential({
      ...input,
      environmentIds: [input.environmentId, ...inputEnvironments(rule, input.environmentId)],
    });
    const material = leased.materials.get(input.environmentId);
    if (material === undefined) {
      return yield* Effect.fail(
        cliError("The lease returned no material (internal inconsistency)"),
      );
    }
    const local = byNameOf(material);
    const current = yield* currentCredential(primary, rule, local);
    const inputs = yield* leasedInputs(primary, rule, input.environmentId, leased.materials);
    const plan = yield* Effect.try({
      try: () => planRotation(rule, current),
      catch: connectorFailure,
    });
    if (plan.immediate) {
      return yield* Effect.fail(
        cliError(
          `Refusing to propose a rotation of ${displayText(primary)} from CI: this rule's rotation invalidates the current credential at once (${plan.description}). A sealed proposal keeps the current credential in use until a member accepts it, so it needs a rule with a grace period (a finalize step). Run \`maruhi var rotate ${displayText(primary)}\` from a member's machine instead. Nothing was sent to the issuer`,
        ),
      );
    }
    const recipients = proposalRecipients(material.verified, input.environmentId);
    if (recipients.length === 0) {
      return yield* Effect.fail(
        cliError(
          `No member device can accept a proposal for environment ${displayText(input.environmentId)} (nobody with role member or above has it in scope). Nothing was sent to the issuer`,
        ),
      );
    }
    // The pre-flight (O-4): the mint's checks that the issuer cannot undo
    // once a credential exists (a stale base, a pending proposal for the
    // same variable, the pending cap) are asked first, under the lease's
    // credential; a refusal here strands nothing
    const params = { projectId: input.projectId, environmentId: input.environmentId };
    yield* leased.client.lease
      .preflight({
        params,
        payload: {
          oidcToken: Redacted.value(leased.credential.token),
          ephemeralPubHex: leased.credential.ephemeralPubHex,
          variables: yield* preflightVariables(primary, rule, local),
          // The set the job will seal to, checked against W(E) here too
          // (ruling O revision, round 4): a disagreement that is not a race
          // is answered before the issuer is touched
          recipients: recipients.map(({ member, device }) => ({
            userId: member.userId,
            encPubHex: device.encPubHex,
          })),
        },
      })
      .pipe(Effect.mapError((error) => preflightRefusal(error, primary)));
    const site = { variable: primary, environmentId: input.environmentId };
    const outcome = yield* Effect.tryPromise({
      try: () => rotateCredential(rule, current, inputs, input.deps, site),
      catch: connectorFailure,
    });
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
      Effect.catch((error) =>
        error instanceof RotationProposalRejectedError && error.reason === "recipients-mismatch"
          ? Effect.gen(function* () {
              // The one post-issuer refusal that is purely a race (O-7):
              // the members or devices changed between the lease and the
              // mint. The plaintext is still in memory, so lease again,
              // compute W(E) from the current chain, seal again and mint
              // once more (a new proposal id); a second mismatch stops
              yield* io.logError(
                "The project's members or devices changed after this job leased it: leasing again and sealing the proposal to the current recipients (once)",
              );
              // Under the lease's key and the newest token the job holds
              // for it — the mint's, minted seconds ago, else the lease's —
              // while it lasts (a runner whose issuance endpoint stopped
              // answering can still recover — O-13 / O-15); a fresh pair
              // otherwise
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
              const againRecipients = proposalRecipients(
                againMaterial.verified,
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
      warnings: [],
    };
  });
}

interface SealAndMintInput {
  readonly input: CiRotateInput;
  readonly rule: RotateRule;
  readonly planned: readonly PlannedValue[];
  readonly outcome: RotationOutcome;
  readonly params: { readonly projectId: string; readonly environmentId: EnvironmentId };
  readonly lease: LeasedEnvironments;
  readonly recipients: readonly Recipient[];
  /** The token the mint presents (minted after the connector for the lease's key — K-5; `mintTokenFor`). */
  readonly token: Redacted.Redacted<string>;
}

interface Minted {
  readonly proposalId: string;
  readonly expiresAtMs: number;
  readonly recipients: readonly Recipient[];
  readonly resealed: boolean;
}

/**
 * Seals the planned values to the recipients under a fresh proposal id
 * and stores the proposal under the lease's ephemeral key. The server's
 * refusals come back as they are (the caller decides which one is a
 * race); everything else is the mint refusal with the recovery step.
 */
function sealAndMint(
  mint: SealAndMintInput,
): Effect.Effect<Minted, CliError | RotationProposalRejectedError, CliIo> {
  return Effect.gen(function* () {
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
          // Why it is unwrapped: the wire boundary of the mint request (the
          // lease's ephemeral key under a token of the same workload —
          // AUTH_SPEC §14-5)
          oidcToken: Redacted.value(mint.token),
          ephemeralPubHex: lease.credential.ephemeralPubHex,
          proposal: {
            proposalId,
            connector: mint.rule.connector,
            facts: acceptableFacts(outcome.facts),
            // The lifetime travels as days; the server sets the instant
            // (a CI clock ahead of the server can never make the proposal
            // unacceptable after the issuer was touched — O-9)
            expiresInDays: input.expiresInDays,
            variables,
          },
        },
      })
      .pipe(
        Effect.mapError((error) =>
          error instanceof RotationProposalRejectedError ? error : mintRefusal(error, outcome),
        ),
      );
    return { proposalId, expiresAtMs: receipt.expiresAtMs, recipients, resealed: false };
  });
}

/**
 * The mint's token: one minted now, for the lease's ephemeral key (K-5 —
 * a connector can outlive the lease's token, and the key binding, not the
 * token, is the credential's continuity under §14-1). The lease's token
 * is the fallback when the runner's issuance endpoint does not answer
 * again, unless it has expired meanwhile (K-6): then nothing can store the
 * proposal and the recovery for the credential at the issuer is said.
 */
function mintTokenFor(
  input: CiRotateInput,
  lease: LeasedEnvironments,
  outcome: RotationOutcome,
): Effect.Effect<Redacted.Redacted<string>, CliError, CliIo> {
  // The fetch's bound follows the lease token's life (O-18): a hung
  // endpoint must not eat the fallback to a token that still lives
  return fetchGitHubOidcToken(
    input.audience,
    issuanceBoundFor(lease.credential.token, (input.now ?? Date.now)()),
  ).pipe(
    Effect.catch((error) =>
      Effect.gen(function* () {
        const io = yield* CliIo;
        const expiresAtMs = tokenExpiresAtMs(lease.credential.token);
        if (expiresAtMs !== null && expiresAtMs <= (input.now ?? Date.now)()) {
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
}

/** The report lines of a mint (the command prints them; values never appear). */
export function describeProposal(result: CiRotateResult, environmentId: string): string[] {
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
