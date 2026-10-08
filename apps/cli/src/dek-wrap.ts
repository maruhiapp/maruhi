// Generating the complete wrap set of an epoch DEK (CRYPTO_SPEC §5 /
// §5.1 / §6.3, AUTH_SPEC §12-4 / §12-6).
//
// Shared implementation that generates the "complete wrap set" a composite
// request (environment creation = epoch 1, rotation = new epoch) embeds
// so it exactly matches the verified ChainState's "current member set +
// server keys of valid grant_server whose disclosure scope contains the
// target environment" (§12-4). The wrap-recipient match check (§6.3's
// ghost-member defense) has its main line on the client side; the
// server's §12-6 verification is the auxiliary line (session-07 §5). The
// recipient position of a server-addressed wrap's HPKE info /
// registration signature is the server key FP (CRYPTO_SPEC §9).
//
// Wrap generation → signDekWrap → registration run as one sequence (the
// signer = the calling principal — §5.1 / session-10 §5). On a CAS retry
// the set is rebuilt only when the resync changed the recipient set
// (members + in-scope grants) (§12-4 — HPKE Seal is random, so unneeded
// re-wraps are avoided).

import type { WrappedDek } from "@maruhi/api-schema";
import {
  cryptoEffect,
  type EnvironmentId,
  type KeyFingerprintHex,
  type ProjectId,
  type UserId,
} from "@maruhi/core";
import type {
  ChainDevice,
  ChainMember,
  EffectivePermission,
  Role,
  ServerGrant,
  SigningKeyPair,
} from "@maruhi/crypto";
import {
  decodeHex,
  effectivePermissionOf,
  encodeHex,
  importEncryptionPublicKey,
  scopeIncludesEnvironment,
  signDekWrap,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import { Data, Effect, Redacted } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { devicesOf, ownDeviceBySigningKey } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { outOfScopeMessage, refuseChainDeletedEnvironment } from "./scope.ts";

/**
 * A wrap recipient (recipient class — AUTH_SPEC §12-6). A member's
 * identifier is the user_id; a server's identifier is the server key FP
 * (it goes verbatim into HPKE info / the recipient position of the §5.1
 * signature target — CRYPTO_SPEC §9).
 */
export type WrapRecipient =
  | {
      readonly kind: "member";
      readonly member: ChainMember;
      /** The device the wrap is sealed to (R(E) is a (person, device) pair — CRYPTO_SPEC §6.2, DK K4). */
      readonly device: ChainDevice;
    }
  | { readonly kind: "server"; readonly grant: ServerGrant };

function recipientId(recipient: WrapRecipient): UserId | KeyFingerprintHex {
  return recipient.kind === "member"
    ? recipient.member.userId
    : recipient.grant.serverKeyFingerprintHex;
}

/** The wire recipient position: the class decides the id's brand (api-schema's WrappedDek union). */
function recipientPositionOf(
  recipient: WrapRecipient,
):
  | { readonly recipientClass: "member"; readonly recipientUserId: UserId }
  | { readonly recipientClass: "server"; readonly recipientUserId: KeyFingerprintHex } {
  return recipient.kind === "member"
    ? { recipientClass: "member", recipientUserId: recipient.member.userId }
    : { recipientClass: "server", recipientUserId: recipient.grant.serverKeyFingerprintHex };
}

function recipientEncPubHex(recipient: WrapRecipient): string {
  return recipient.kind === "member" ? recipient.device.encPubHex : recipient.grant.serverEncPubHex;
}

/**
 * The member-side membership predicate of the recipient set R(E)
 * (CRYPTO_SPEC §6.2 — the device axis, 2026-09-19 DK): E ∈ the device's
 * effective scope (person's scope ∩ device's scope —
 * `effectivePermissionOf` is the only computation point). The same
 * predicate as the server's expected count (`expectedWrapRecipientCount`)
 * (design record §9 K4).
 */
export function deviceReceivesEnvironment(
  member: ChainMember,
  device: ChainDevice,
  environmentId: EnvironmentId,
): boolean {
  return scopeIncludesEnvironment(effectivePermissionOf(member, device).scope, environmentId);
}

/**
 * The recipients of the complete wrap set of target environment E = R(E)
 * (the single definition in CRYPTO_SPEC §6.2 — 2026-09-15 ES K4; device
 * expansion 2026-09-19 DK K4): { (m, d) | m a current member, d ∈
 * devices(m), E ∈ effective scope(m, d) } ∪ { valid grant g | E ∈
 * scope_environments(g) }. The check is the same "E ∈ scope" predicate
 * across recipient classes. Ordering is deterministic (members by user_id
 * ascending → devices by FP ascending → servers by FP ascending). Dedup
 * is at the storage-key granularity (identifier + enc key — same as the
 * server's `wrapStorageKey`). Environment creation, rotate composites,
 * and CAS-retry reuse judgment (sameWrapRecipientSet) all pass through
 * here. A wrap addressed to an out-of-scope device is refused by the
 * server with 422 `scope-out-of-range` (§12-6).
 */
/** Every (member, device) pair of the verified state, members by user id and devices in their registry order (the deterministic recipient order). */
export function memberDevicesInOrder(
  verified: VerifiedProject,
): readonly { readonly member: ChainMember; readonly device: ChainDevice }[] {
  const pairs: { readonly member: ChainMember; readonly device: ChainDevice }[] = [];
  for (const member of [...verified.state.members.values()].toSorted((a, b) =>
    a.userId < b.userId ? -1 : 1,
  )) {
    for (const device of devicesOf(member)) {
      pairs.push({ member, device });
    }
  }
  return pairs;
}

function wrapRecipientsFor(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
): readonly WrapRecipient[] {
  const seen = new Set<string>();
  const recipients: WrapRecipient[] = [];
  const push = (recipient: WrapRecipient) => {
    const key = `${recipientId(recipient)}:${recipientEncPubHex(recipient)}`;
    if (!seen.has(key)) {
      seen.add(key);
      recipients.push(recipient);
    }
  };
  for (const { member, device } of memberDevicesInOrder(verified)) {
    if (deviceReceivesEnvironment(member, device, environmentId)) {
      push({ kind: "member", member, device });
    }
  }
  for (const grant of [...verified.state.serverGrants.values()]
    .filter((candidate) => candidate.scopeEnvironmentIds.includes(environmentId))
    .toSorted((a, b) => (a.serverKeyFingerprintHex < b.serverKeyFingerprintHex ? -1 : 1))) {
    push({ kind: "server", grant });
  }
  return recipients;
}

/**
 * The expected recipient count of the complete wrap set (pre-flight
 * self-check — the same predicate and the same dedup granularity as the
 * server's `expectedWrapRecipientCount`).
 */
export function expectedWrapRecipientCount(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
): number {
  return wrapRecipientsFor(verified, environmentId).length;
}

/** Result of building one wrap (a tagged Result with the real reason code — do not crush multiple causes into one generic message). */
type WrapBuildResult =
  | { readonly kind: "ok"; readonly wrap: WrappedDek }
  | { readonly kind: "failed"; readonly reason: string };

/** Why building one wrap failed (the reason is folded into the caller's message verbatim). */
class WrapBuildFailed extends Data.TaggedError("WrapBuildFailed")<{
  readonly reason: string;
}> {}

function wrapAndSignForEffect(input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly recipient: WrapRecipient;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<WrappedDek, WrapBuildFailed> {
  const { environmentId, epoch, dek, recipient } = input;
  // Recipient identifier: member = user_id / server = server key FP (§9 —
  // the same value goes into HPKE info and the recipient_user_id position
  // of the §5.1 signature target)
  const id = recipientId(recipient);
  const encPubHex = recipientEncPubHex(recipient);
  return Effect.gen(function* () {
    const recipientKeyBytes = decodeHex(encPubHex);
    if (recipientKeyBytes === null) {
      return yield* Effect.fail(
        new WrapBuildFailed({ reason: "Cannot decode the recipient's enc public-key hex" }),
      );
    }
    const recipientKey = yield* cryptoEffect(() =>
      importEncryptionPublicKey(recipientKeyBytes),
    ).pipe(
      Effect.mapError(
        () => new WrapBuildFailed({ reason: "Cannot load the recipient's enc public key" }),
      ),
    );
    const wrapped = yield* cryptoEffect(() =>
      wrapDek({
        recipientPublicKey: recipientKey,
        // Why it is unwrapped: input to the HPKE wrap (the crypto boundary). The product is the wrapped ciphertext
        dek: Redacted.value(dek),
        context: {
          projectId: input.projectId,
          environmentId,
          epoch,
          recipientUserId: id,
        },
      }),
    ).pipe(Effect.mapError(() => new WrapBuildFailed({ reason: "The HPKE wrap failed" })));
    const encHex = encodeHex(wrapped.enc);
    const ciphertextHex = encodeHex(wrapped.ciphertext);
    const signatureHex = yield* cryptoEffect(() =>
      signDekWrap({
        context: {
          suite: SUITE_ID,
          projectId: input.projectId,
          environmentId,
          epoch,
          recipientUserId: id,
          recipientEncPubHex: encPubHex,
          encHex,
          ciphertextHex,
          signerUserId: input.signerUserId,
        },
        signingKey: input.signingKeyPair.privateKey,
      }),
    ).pipe(
      Effect.mapError(
        () => new WrapBuildFailed({ reason: "Failed to create the registration signature" }),
      ),
    );
    return {
      suite: SUITE_ID,
      epoch,
      ...recipientPositionOf(recipient),
      recipientEncPubHex: encPubHex,
      encHex,
      ciphertextHex,
      signatureHex,
    };
  });
}

export function wrapAndSignFor(input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly recipient: WrapRecipient;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Promise<WrapBuildResult> {
  return Effect.runPromise(
    wrapAndSignForEffect(input).pipe(
      Effect.map((wrap): WrapBuildResult => ({ kind: "ok", wrap })),
      Effect.catchTag("WrapBuildFailed", (error) =>
        Effect.succeed<WrapBuildResult>({ kind: "failed", reason: error.reason }),
      ),
    ),
  );
}

/**
 * Builds the wrap set for one epoch: exactly the verified current member set
 * plus the server keys of active grants whose scope covers the environment
 * (§6.3 / §12-4), each wrap signed by the caller (§5.1).
 * Deterministic recipient order for reproducible requests.
 */
export const buildWrapCompleteSet = Effect.fn("dek-wrap.buildWrapCompleteSet")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<readonly WrappedDek[], CliError> {
  const recipients = wrapRecipientsFor(input.verified, input.environmentId);
  const wraps: WrappedDek[] = [];
  for (const recipient of recipients) {
    // Identifiers are chain-derived free-form strings — always neutralize before emitting to the terminal
    const label =
      recipient.kind === "member"
        ? `member ${displayText(recipient.member.userId)} (device ${recipient.device.keyFingerprintHex})`
        : `server key ${displayText(recipient.grant.serverKeyFingerprintHex)}`;
    const wrap = yield* wrapAndSignForEffect({
      projectId: input.verified.projectId,
      environmentId: input.environmentId,
      epoch: input.epoch,
      dek: input.dek,
      recipient,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    }).pipe(
      Effect.mapError((error) =>
        cliError(`Failed to generate the DEK wrap for ${label} (${error.reason})`),
      ),
    );
    wraps.push(wrap);
  }
  return wraps;
});

/**
 * Sameness of the target environment's wrap recipient set (members +
 * in-scope grants). Judges whether the wrap set may be reused on a CAS
 * retry (§12-4).
 */
export function sameWrapRecipientSet(
  a: VerifiedProject,
  b: VerifiedProject,
  environmentId: EnvironmentId,
): boolean {
  const left = wrapRecipientsFor(a, environmentId);
  const right = wrapRecipientsFor(b, environmentId);
  if (left.length !== right.length) {
    return false;
  }
  return left.every((recipient, index) => {
    const other = right[index];
    return (
      other !== undefined &&
      recipient.kind === other.kind &&
      recipientId(recipient) === recipientId(other) &&
      recipientEncPubHex(recipient) === recipientEncPubHex(other)
    );
  });
}

/**
 * Order of roles (CRYPTO_SPEC §6.2). **Do not write it in the negative
 * form (`=== "reader"`)**: when Role gains a value below member, a
 * negative-form check silently passes. With `satisfies Record<Role,
 * number>`, this becomes a type error the moment a value is added.
 */
export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } satisfies Record<
  Role,
  number
>;

/** The signing member with the device that signs and its effective permission (§3 / §6.2). */
interface WritingMember {
  readonly member: ChainMember;
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
}

/**
 * The shared guard of composite operations (environment creation,
 * rotation): that I am a chain-derived current member, that the signing
 * device (the key at hand) is a valid device of that person, that the
 * **device's effective role** is member or above (admin or above for
 * environment deletion — minimumRole), and that **the target
 * environment is included in the device's effective scope** (§6.2 / §6.3
 * — 2026-09-15 ES K4; device effective permission 2026-09-19 DK K4-17:
 * for create, `listed` cannot contain a nonexistent id, so only devices
 * with effective scope = all pass = the same single predicate as the
 * server). All exist to drop the request **before** DEK generation, HPKE
 * wrap, and pull (= recording `var.read`); they do not wait for the
 * server's 403. There is no refusal guard for when grant_server is valid
 * — the complete set includes the server-key recipient
 * (buildWrapCompleteSet / §12-4).
 *
 * The environment-existence check (rotate) and the ID-duplication check
 * (create) are operation-specific, so they stay with the callers.
 */
export const requireWritingMember = Effect.fn("dek-wrap.requireWritingMember")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /**
   * Whether the operation acts on an environment the chain already holds
   * (`existing`: a chain-deleted one is refused first — §6.2 pruned it from
   * every listed scope, so the scope judgment would misreport it) or names a
   * new one (`new`: env create, whose own check reports a burned ID as
   * duplicate-environment). Required, so every caller decides.
   */
  readonly target: "existing" | "new";
  readonly signerUserId: UserId;
  /** The signing device's key (the computation point of effective permission — the person's (role, scope) is not passed to the check directly). */
  readonly signingKeyPair: SigningKeyPair;
  /** Operation name embedded in the message (e.g. "rotation"). */
  readonly operation: string;
  /** Wording for insufficient permission (written concretely per operation). */
  readonly forbidden: string;
  /**
   * Wording for out-of-scope (omitted = the default "ask for a widening"
   * guidance). create guides with "creation requires scope = all" ("ask
   * for a widening" does not apply).
   */
  readonly outOfScope?: string;
  /** The device's minimum effective role (omitted = member; environment deletion = admin — §12-3). */
  readonly minimumRole?: "member" | "admin";
}): Effect.fn.Return<WritingMember, CliError> {
  const minimumRank = ROLE_RANK[input.minimumRole ?? "member"];
  const member = input.verified.state.members.get(input.signerUserId);
  if (member === undefined) {
    return yield* Effect.fail(
      cliError(`You are not a chain-derived member of this project (cannot ${input.operation})`),
    );
  }
  if (input.target === "existing") {
    yield* refuseChainDeletedEnvironment(input.verified, input.environmentId);
  }
  const device = yield* ownDeviceBySigningKey(input.verified, member, input.signingKeyPair);
  const permission = effectivePermissionOf(member, device);
  if (ROLE_RANK[permission.role] < minimumRank) {
    return yield* Effect.fail(
      cliError(
        ROLE_RANK[member.role] < minimumRank
          ? input.forbidden
          : `${input.forbidden}. Your role is ${member.role}, but this device's key is capped at ${device.roleCap} (\`maruhi device list\`) — use a device without that cap`,
      ),
    );
  }
  if (!scopeIncludesEnvironment(permission.scope, input.environmentId)) {
    return yield* Effect.fail(
      cliError(
        input.outOfScope ??
          outOfScopeMessage({
            member,
            device,
            environmentId: input.environmentId,
            operation: input.operation,
          }),
      ),
    );
  }
  return { member, device, permission };
});
