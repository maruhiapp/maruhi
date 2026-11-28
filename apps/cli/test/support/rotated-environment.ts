import type { BuiltChain, GeneratedIdentity, WireRecipientDek } from "@maruhi/test-kit";
import {
  buildChain,
  createEnvironmentOp,
  distributedWrap,
  genesisOp,
  rotateEpochOp,
} from "@maruhi/test-kit";

export async function rotatedEnvironmentFor(input: {
  readonly owner: GeneratedIdentity;
  readonly environmentId: string;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
}): Promise<{
  readonly chain: BuiltChain;
  readonly wraps: readonly [WireRecipientDek, WireRecipientDek];
}> {
  const { owner, environmentId, dek1, dek2 } = input;
  const chain = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(environmentId, dek1) },
    { actor: owner, operation: rotateEpochOp(environmentId, 2, dek2) },
  ]);
  const common = { projectId: chain.projectId, environmentId, recipient: owner, signer: owner };
  const wraps = [
    await distributedWrap({ ...common, epoch: 1, dek: dek1 }),
    await distributedWrap({ ...common, epoch: 2, dek: dek2 }),
  ] as const;
  return { chain, wraps };
}
