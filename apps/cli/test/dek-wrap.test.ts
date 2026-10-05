// wrapAndSignFor's `Promise<WrapBuildResult>` contract (the shape backfill.ts
// consumes): every crypto failure folds into a `reason` string the caller
// embeds verbatim in its message. Driven through the exported function, which
// runs the internal effect and folds `WrapBuildFailed` back into the Result.

import { Redacted } from "effect";
import { describe, expect, it } from "vitest";

import { wrapAndSignFor } from "../src/dek-wrap.ts";
import { makeTestUser } from "./support/crypto.ts";

function serverRecipient(serverEncPubHex: string) {
  return {
    kind: "server" as const,
    grant: {
      serverKeyFingerprintHex: "ab".repeat(16),
      serverEncPubHex,
      grantSeq: 1,
      scopeEnvironmentIds: ["prod"],
      leasePolicy: [],
    },
  };
}

describe("wrapAndSignFor", () => {
  it("fails with the hex-decode reason for a non-hex recipient enc key", async () => {
    const signer = await makeTestUser("user-signer-0001");
    const built = await wrapAndSignFor({
      projectId: "aa".repeat(32),
      environmentId: "prod",
      epoch: 1,
      dek: Redacted.make(new Uint8Array(32), { label: "dek" }),
      recipient: serverRecipient("not-hex"),
      signerUserId: signer.userId,
      signingKeyPair: signer.sigKeyPair,
    });
    expect(built).toEqual({
      kind: "failed",
      reason: "Cannot decode the recipient's enc public-key hex",
    });
  });

  it("fails with the key-import reason for an enc key that is hex but not a public key", async () => {
    const signer = await makeTestUser("user-signer-0001");
    const built = await wrapAndSignFor({
      projectId: "aa".repeat(32),
      environmentId: "prod",
      epoch: 1,
      dek: Redacted.make(new Uint8Array(32), { label: "dek" }),
      recipient: serverRecipient("abcd"),
      signerUserId: signer.userId,
      signingKeyPair: signer.sigKeyPair,
    });
    expect(built).toEqual({
      kind: "failed",
      reason: "Cannot load the recipient's enc public key",
    });
  });

  it("wraps and signs for a valid recipient ({kind: 'ok'} shape)", async () => {
    const signer = await makeTestUser("user-signer-0001");
    const server = await makeTestUser("user-server-0001");
    const built = await wrapAndSignFor({
      projectId: "aa".repeat(32),
      environmentId: "prod",
      epoch: 1,
      dek: Redacted.make(new Uint8Array(32), { label: "dek" }),
      recipient: serverRecipient(server.encPubHex),
      signerUserId: signer.userId,
      signingKeyPair: signer.sigKeyPair,
    });
    expect(built.kind).toBe("ok");
    if (built.kind !== "ok") {
      throw new Error("expected an ok wrap");
    }
    expect(built.wrap).toMatchObject({
      suite: "maruhi/v1",
      epoch: 1,
      recipientClass: "server",
      recipientUserId: "ab".repeat(16),
      recipientEncPubHex: server.encPubHex,
    });
  });
});
