// A rotate that races a delete_environment: the server answers the stale
// head with 409, and the re-synced chain carries the deletion. Both an
// all-scope owner and a listed member must get the chain-derived deletion
// refusal, not a scope refusal (the deletion pruned the id from the listed
// scope — §6.2).
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addScopedMemberOp,
  buildChain,
  createEnvironmentOp,
  deleteEnvironmentOp,
  genesisOp,
  makeTestUser,
  wrapDekFor,
} from "./support/crypto.ts";
import { dek1, ENV_ID, makeServer, owner, startEnv } from "./support/env-rotate.ts";

describe("env rotate racing a delete_environment", () => {
  for (const listed of [false, true]) {
    it(`refuses with the deletion, not the scope (${listed ? "listed member" : "all-scope owner"})`, async () => {
      const dev = await makeTestUser("user-dev-3333");
      const prefix = [
        { actor: owner, operation: genesisOp(owner) },
        { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
        { actor: owner, operation: addScopedMemberOp(dev, "member", [ENV_ID]) },
      ];
      const pre = await buildChain(prefix);
      const post = await buildChain([
        ...prefix,
        { actor: owner, operation: deleteEnvironmentOp(ENV_ID) },
      ]);
      const deks = [];
      for (const recipient of [owner, dev]) {
        deks.push(
          await wrapDekFor({
            projectId: pre.projectId,
            environmentId: ENV_ID,
            epoch: 1,
            dek: dek1,
            recipient,
            signer: owner,
          }),
        );
      }
      const state = makeServer({
        built: pre,
        variables: [],
        deks,
        currentEpoch: 1,
        onRotate: () => ({
          status: 409,
          json: {
            _tag: "ChainHeadConflict",
            currentHeadSeq: post.entries.length,
            currentHeadHashHex: post.hashes[post.hashes.length - 1],
          },
        }),
        chainAfterRotateAttempt: post,
      });
      const env = await startEnv(state.handlers, listed ? dev : owner);
      expect(await runCli(["env", "rotate", ENV_ID, "--reason", "raced"], env.layer)).not.toBe(0);
      const errors = env.errors.join("\n");
      expect(errors).toContain("is deleted (delete_environment at chain seq 4)");
      expect(errors).not.toContain("outside your environment scope");
    });
  }
});
