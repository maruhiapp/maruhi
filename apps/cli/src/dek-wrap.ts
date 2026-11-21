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
  SigningKeyPair,
  WrapRecipient,
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
  wrapRecipientsOf,
} from "@maruhi/crypto";
import { Data, Effect, Redacted } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { ownDeviceBySigningKey } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { outOfScopeMessage, refuseChainDeletedEnvironment } from "./scope.ts";

function recipientId(recipient: WrapRecipient): UserId | KeyFingerprintHex {
  return recipient.kind === "member"
    ? recipient.member.userId
    : recipient.grant.serverKeyFingerprintHex;
}

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

type WrapBuildResult =
  | { readonly kind: "ok"; readonly wrap: WrappedDek }
  | { readonly kind: "failed"; readonly reason: string };

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

export const buildWrapCompleteSet = Effect.fn("dek-wrap.buildWrapCompleteSet")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<readonly WrappedDek[], CliError> {
  const recipients = wrapRecipientsOf(input.verified.state, input.environmentId);
  const wraps: WrappedDek[] = [];
  for (const recipient of recipients) {
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

export function sameWrapRecipientSet(
  a: VerifiedProject,
  b: VerifiedProject,
  environmentId: EnvironmentId,
): boolean {
  const left = wrapRecipientsOf(a.state, environmentId);
  const right = wrapRecipientsOf(b.state, environmentId);
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

export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } satisfies Record<
  Role,
  number
>;

interface WritingMember {
  readonly member: ChainMember;
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
}

export const requireWritingMember = Effect.fn("dek-wrap.requireWritingMember")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly target: "existing" | "new";
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly operation: string;
  readonly forbidden: string;
  readonly outOfScope?: string;
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
