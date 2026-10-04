// Tests for pull (§5.1 distribution-time verification + §12-7 all-epoch DEKs)
// and run (memory injection), and for the AI-agent-detection boundary
// (value display is refused / run is allowed).

import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { statementFor } from "./support/crypto.ts";
import {
  chainHandler,
  ENV_ID,
  fixture,
  pullHandler,
  servers,
  startEnv,
} from "./support/pull-run.ts";
import { type MockHandler, onRequest } from "./support/server.ts";

/** The version history of one variable, as the server declares it (PF7a — the push time behind the max-age note). */
function historyHandler(variableId: string, pushedAtMs: number, status = 200): MockHandler {
  const { built, owner } = fixture;
  return onRequest(
    "GET",
    `/projects/${built.projectId}/environments/${ENV_ID}/variables/${variableId}/versions`,
    () =>
      status !== 200
        ? { status, json: { message: "injected history failure" } }
        : {
            status: 200,
            json: {
              variableId,
              versions: [
                {
                  version: 3,
                  epoch: 2,
                  writerUserId: owner.userId,
                  writerKeyFingerprintHex: owner.fingerprintHex,
                  pushedAtMs,
                  flagsIfCurrent: 0,
                },
              ],
            },
          },
  );
}

describe("the max-age note at the point of use (PF7a S-E)", () => {
  const day = 24 * 60 * 60 * 1000;

  /** ALPHA re-declared under layout v3 with a 30-day max age (the value is unchanged). */
  async function expiringAlpha() {
    const { built, owner, entryAlpha } = fixture;
    return {
      ...entryAlpha,
      statement: await statementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        variableId: "va",
        name: "ALPHA",
        author: owner,
        head: { seq: 1, hashHex: built.projectId },
        schema: { varType: "string", required: true, description: "", maxAgeDays: 30 },
      }),
    };
  }

  it("`maruhi run` and `maruhi pull` note a value past its declared max age, in one line, without changing the outcome", async () => {
    const alpha = await expiringAlpha();
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [alpha, fixture.entryBeta] }),
      historyHandler("va", Date.now() - 40 * day),
    ]);
    expect(await runCli(["run", "--", "printenv", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
    const errors = env.errors.join("\n");
    expect(errors).toMatch(
      /Note: 1 value past the max age its schema declares: ALPHA \(max age 30d, pushed \d{4}-\d{2}-\d{2}, expired 10 days ago\) — rotate it \(`maruhi rotation list` shows the next step for each\)/,
    );
    // BETA declares no interval: no history call was made for it
    const server = servers[servers.length - 1];
    expect(
      server?.requests.filter((request) => request.path.includes("/variables/vb/versions")),
    ).toHaveLength(0);
    // The same note on pull
    const pullEnv = await startEnv([
      chainHandler(),
      pullHandler({ variables: [alpha, fixture.entryBeta] }),
      historyHandler("va", Date.now() - 40 * day),
    ]);
    expect(await runCli(["pull"], pullEnv.layer)).toBe(0);
    expect(pullEnv.errors.join("\n")).toContain(
      "Note: 1 value past the max age its schema declares: ALPHA",
    );
    expect(pullEnv.logs.join("\n")).not.toContain("alpha-value");
  });

  it("says nothing while the value is within its max age, and says so when the history cannot be read", async () => {
    const alpha = await expiringAlpha();
    const fresh = await startEnv([
      chainHandler(),
      pullHandler({ variables: [alpha, fixture.entryBeta] }),
      historyHandler("va", Date.now() - 20 * day),
    ]);
    expect(await runCli(["run", "--", "true"], fresh.layer)).toBe(0);
    expect(fresh.errors.join("\n")).not.toContain("past the max age");
    const broken = await startEnv([
      chainHandler(),
      pullHandler({ variables: [alpha, fixture.entryBeta] }),
      historyHandler("va", 0, 500),
    ]);
    expect(await runCli(["run", "--", "true"], broken.layer)).toBe(0);
    expect(broken.errors.join("\n")).toContain(
      "could not read the history of ALPHA in environment prod",
    );
  });
});
