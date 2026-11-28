import type { ChainEntry } from "@maruhi/crypto";
import { vectorKeys } from "@maruhi/crypto/test-support";
import type { TestIdentity, WireWrappedDek } from "@maruhi/test-kit";
import { vectorIdentity, vectorIdentityByFingerprint, wrapDekTo } from "@maruhi/test-kit";

const VECTOR_KEY_ALIASES: Record<string, string> = {
  "user-reader-0003": "user-admin-0003",
};

const deviceKeyOverrides = new Map<string, string>();

export function useDeviceKey(userId: string, vectorKeyName: string | null): void {
  if (vectorKeyName === null) {
    deviceKeyOverrides.delete(userId);
  } else {
    deviceKeyOverrides.set(userId, vectorKeyName);
  }
}

export function resetDeviceKeys(): void {
  deviceKeyOverrides.clear();
}

export function vectorKeyNamed(name: string) {
  const keys = vectorKeys[name];
  if (keys === undefined) {
    throw new Error(`no vector keys named ${name}`);
  }
  return keys;
}

function vectorKeyNameOf(userId: string): string {
  return deviceKeyOverrides.get(userId) ?? VECTOR_KEY_ALIASES[userId] ?? userId;
}

export function vectorKeyOf(userId: string) {
  const keys = vectorKeys[vectorKeyNameOf(userId)];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${userId}`);
  }
  return keys;
}

export function identityOf(userId: string): TestIdentity {
  return vectorIdentity(vectorKeyNameOf(userId), userId);
}

export function signerOf(entry: ChainEntry): TestIdentity {
  return (
    vectorIdentityByFingerprint(entry.actor.keyFingerprintHex, entry.actor.userId) ??
    identityOf(entry.actor.userId)
  );
}

export async function wrapDekForAll(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserIds: readonly string[];
  readonly signerUserId: string;
}): Promise<WireWrappedDek[]> {
  const wraps: WireWrappedDek[] = [];
  for (const recipientUserId of input.recipientUserIds) {
    wraps.push(
      await wrapDekTo({
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.epoch,
        dek: input.dek,
        recipient: identityOf(recipientUserId),
        signer: identityOf(input.signerUserId),
      }),
    );
  }
  return wraps;
}
