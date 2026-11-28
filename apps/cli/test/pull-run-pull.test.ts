import { signDekWrap } from "@maruhi/crypto";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  distributedManifest,
  distributedValue,
  distributedWrap,
  generateIdentity,
  genesisOp,
  headOf,
  removeMemberOp,
  rotateEpochOp,
  testEnvironmentId,
  testProjectId,
} from "@maruhi/test-kit";
import { describe, expect, it } from "vite-plus/test";

import { runCli } from "../src/cli.ts";
import { makeTestEnv, seedConfig, seedSession } from "./support/env.ts";
import {
  chainHandler,
  ENV_ID,
  fixture,
  pullEntry,
  pullEnvStatement,
  pullHandler,
  servers,
  startEnv,
} from "./support/pull-run.ts";
import { MockServer, onRequest } from "./support/server.ts";

describe("maruhi pull", () => {
  it("syncs + §5.1-verifies + decrypts, then shows only metadata (never the value)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("ALPHA");
    expect(output).toContain("version=3");
    expect(output).toContain("epoch=2");
    expect(output).toContain("BETA");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
  });

  it("warns about epochs missing a wrap for self (self-side detection of the diff from §7's all-epoch distribution)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [fixture.entryAlpha], deks: [fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("no DEK wraps for you exist at epochs 1");
    expect(errors).toContain("re-run `maruhi member add`");
    expect(errors).toContain(
      `fills the missing epochs when it runs \`maruhi pull --project ${fixture.built.projectId} --env ${ENV_ID}\``,
    );
    expect(errors).not.toContain("maruhi device approve");

    const complete = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], complete.layer)).toBe(0);
    expect(complete.errors.join("\n")).not.toContain("no DEK wraps for you exist at epochs");
  });

  it("--show displays the value to a human", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    expect(env.logs).toContain("ALPHA=alpha-value");
    expect(env.logs).toContain("BETA=beta-value");
  });

  it("command output goes only through CliIo (no path that hits real fds directly)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    const bypassed: string[] = [];
    const realWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array): boolean => {
      bypassed.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    } finally {
      process.stdout.write = realWrite;
    }
    const written = bypassed.join("");
    expect(written).not.toContain("alpha-value");
    expect(written).not.toContain("beta-value");
    expect(written).not.toContain("Sync and verification OK");
  });

  it("--show=false / --show false are read **exactly as written** and do not display the value", async () => {
    const inline = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show=false"], inline.layer)).toBe(0);
    expect(inline.logs.join("\n")).not.toContain("alpha-value");
    expect(inline.logs.join("\n")).toContain("Sync and verification OK");

    const spaced = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "false"], spaced.layer)).toBe(0);
    expect(spaced.logs.join("\n")).not.toContain("alpha-value");
  });

  it("duplicate flags like `--no-show --show` fail without displaying the value", async () => {
    const later = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["pull", "--no-show", "--show"], later.layer)).toBe(2);
    expect(later.logs.join("\n")).not.toContain("alpha-value");
    expect(later.errors.join("\n")).toContain("Flag --show was specified more than once");
    expect(server?.requests).toHaveLength(0);

    const earlier = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "--no-show"], earlier.layer)).toBe(2);
    expect(earlier.errors.join("\n")).toContain("Flag --show was specified more than once");

    const same = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "--show"], same.layer)).toBe(2);
    expect(same.logs.join("\n")).not.toContain("alpha-value");

    const single = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--no-show"], single.layer)).toBe(0);
    expect(single.logs.join("\n")).not.toContain("alpha-value");
  });

  it("--show neutralizes ANSI/control sequences in the value while keeping newlines", async () => {
    const evil = "sk-\u001b[31mFAKE\u0007\nline2";
    const value = await distributedValue({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vs",
      version: 1,
      plaintext: evil,
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vs", "SECRET", value)],
      }),
    ]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    expect(output).toContain("SECRET= (a 2-line value");
    expect(output).toContain("| sk-\uFFFD[31mFAKE\uFFFD\n| line2");
  });

  it("--show fails when a value is invalid UTF-8, and prints no value at all", async () => {
    const binary = await distributedValue({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vbin",
      version: 1,
      plaintext: new Uint8Array([0x41, 0xff, 0xfe, 0x42]),
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          fixture.entryAlpha,
          await pullEntry(fixture.built.projectId, "vbin", "BINARY", binary),
        ],
      }),
    ]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not valid UTF-8 and cannot be displayed");
    expect(env.logs.join("\n")).not.toContain("ALPHA=alpha-value");
  });

  it("when an AI agent is detected, --show is refused (never suggests run as a workaround)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("AI agent environment was detected");
    expect(errors).not.toContain("maruhi run");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
    expect(env.logs.join("\n")).not.toContain("Sync and verification OK");
  });

  it("--show is refused even for an **unknown** agent (TTY is the primary boundary = fail-closed)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("stdout is not an interactive terminal");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
    expect(env.logs.join("\n")).not.toContain("Sync and verification OK");
  });

  it("runs whose stdin is not a terminal (CI, heredoc) are refused too", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setTerminal({ stdin: false });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
  });

  it("a pull that displays no value passes without a terminal (refusal is only for --show)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Sync and verification OK");
  });

  it("refuses a wrap that forges the signer (a false signerUserId claim)", async () => {
    const stranger = await generateIdentity("user-stranger-9999");
    const spoofed = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    const lying = {
      ...spoofed,
      signerUserId: fixture.owner.userId,
      signerKeyFingerprintHex: fixture.owner.fingerprintHex,
    };
    const env = await startEnv([chainHandler(), pullHandler({ deks: [lying, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("registration signature does not verify");
  });

  it("refuses a wrap whose signer does not exist in chain history", async () => {
    const stranger = await generateIdentity("user-stranger-9999");
    const foreign = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [foreign, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("signer does not exist in the chain history");
  });

  it("refuses a signature bit-flip", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const flipped = `${wrap.signatureHex.slice(0, -1)}${wrap.signatureHex.endsWith("0") ? "1" : "0"}`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [{ ...wrap, signatureHex: flipped }, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("registration signature does not verify");
  });

  it("reports the full refusal message for a signature bit-flip (§5.1)", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const flipped = `${wrap.signatureHex.slice(0, -1)}${wrap.signatureHex.endsWith("0") ? "1" : "0"}`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [{ ...wrap, signatureHex: flipped }, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: The DEK wrap's registration signature does not verify (epoch=1, signer=${fixture.owner.userId})`,
      ]),
    );
  });

  it("reports the full refusal message for a wrap §5.1-signed but sealed to another key (not addressed to your key)", async () => {
    const stranger = await generateIdentity("user-stranger-9999");
    const base = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: stranger,
      signer: fixture.owner,
    });
    const resigned = await signDekWrap({
      context: {
        suite: base.suite,
        projectId: testProjectId(fixture.built.projectId),
        environmentId: testEnvironmentId(ENV_ID),
        epoch: 1,
        recipientUserId: fixture.owner.userId,
        recipientEncPubHex: fixture.owner.encPubHex,
        encHex: base.encHex,
        ciphertextHex: base.ciphertextHex,
        signerUserId: fixture.owner.userId,
      },
      signingKey: fixture.owner.sigKeyPair.privateKey,
    });
    if (!resigned.ok) {
      throw new Error("test fixture: signDekWrap failed");
    }
    const misaddressed = {
      ...base,
      recipientEncPubHex: fixture.owner.encPubHex,
      signatureHex: resigned.value,
    };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [misaddressed, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: Cannot decrypt the DEK (epoch=1, signer=${fixture.owner.userId}). The wrap is not addressed to your key, or it is corrupt`,
      ]),
    );
  });

  it("reports the full refusal message for a poisoned DEK (a fake-DEK injection — §5.2)", async () => {
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([chainHandler(), pullHandler({ deks: [poison, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: The DEK does not match the commitment on the chain (epoch=1, signer=${fixture.owner.userId}). This may be a poisoned wrap (a fake DEK) — an administrator must repair it (delete the wrap, then re-register)`,
      ]),
    );
  });

  it("reports the full refusal message for a signer absent from chain history", async () => {
    const stranger = await generateIdentity("user-stranger-9999");
    const foreign = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [foreign, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors).toEqual(
      expect.arrayContaining([
        `maruhi: The signer does not exist in the chain history (signer=${stranger.userId}, fp=${stranger.fingerprintHex})`,
      ]),
    );
  });

  it("a variable whose declared-epoch DEK is not distributed is an error", async () => {
    const env = await startEnv([chainHandler(), pullHandler({ deks: [fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("your wrap is missing");
  });

  it("ciphertext swapped in from another variable (metadata / AAD mismatch) is refused before decryption", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "va", "ALPHA", fixture.valueBeta)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "declares AAD coordinates that do not match the requested context",
    );
  });

  it("refuses a wrap beyond the chain's current epoch (a phantom epoch)", async () => {
    const phantom = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 3,
      dek: crypto.getRandomValues(new Uint8Array(32)),
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [...fixture.wraps, phantom] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("beyond the chain's current epoch (2)");
  });

  it("refuses a variable whose declared epoch exceeds the chain's current epoch", async () => {
    const phantomValue = await distributedValue({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 3,
      variableId: "vp",
      version: 1,
      plaintext: "phantom",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vp", "PHANTOM", phantomValue)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
  });

  it("refuses a DEK that does not match the on-chain commitment (a poisoned wrap = fake-DEK injection) (§5.2)", async () => {
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([chainHandler(), pullHandler({ deks: [poison, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the commitment on the chain");
  });

  it("refuses a commitment-mismatched DEK even pre-push (via listMine) (the §5.2 confidentiality side)", async () => {
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      onRequest(
        "GET",
        `/projects/${fixture.built.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => ({
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 2,
            statement: fixture.envStatement,
            variables: [fixture.entryAlpha.statement, fixture.entryBeta.statement],
            deletedVariables: [],
            manifest: await distributedManifest({
              projectId: fixture.built.projectId,
              environmentId: ENV_ID,
              epoch: 2,
              issuer: fixture.owner,
              head: headOf(fixture.built, 3),
              envStatement: fixture.envStatement,
              statements: [fixture.entryAlpha.statement, fixture.entryBeta.statement],
            }),
            schemaPolicy: "enabled" as const,
          },
        }),
      ),
      onRequest("GET", `/projects/${fixture.built.projectId}/environments/${ENV_ID}/deks`, () => ({
        status: 200,
        json: { deks: [fixture.wraps[0], poison] },
      })),
    ]);
    env.setStdin(new TextEncoder().encode("new-value"));
    expect(await runCli(["push", "GAMMA"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the commitment on the chain");
  });

  it("refuses a distribution for an environment with no create_environment on the chain (a phantom environment)", async () => {
    const ghostValue = await distributedValue({
      dek: fixture.dek1,
      projectId: fixture.built.projectId,
      environmentId: "ghost",
      epoch: 1,
      variableId: "vg",
      version: 1,
      plaintext: "ghost",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const ghostWrap = await distributedWrap({
      projectId: fixture.built.projectId,
      environmentId: "ghost",
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const ghostEnvStatement = await pullEnvStatement(fixture.built.projectId, undefined, "ghost");
    const ghostEntry = await pullEntry(
      fixture.built.projectId,
      "vg",
      "GHOST",
      ghostValue,
      undefined,
      "ghost",
    );
    const env = await startEnv([
      chainHandler(),
      onRequest(
        "GET",
        `/projects/${fixture.built.projectId}/environments/ghost/pull`,
        async () => ({
          status: 200,
          json: {
            environmentId: "ghost",
            currentEpoch: 1,
            statement: ghostEnvStatement,
            variables: [ghostEntry],
            deletedVariables: [],
            deks: [ghostWrap],
            manifest: await distributedManifest({
              projectId: fixture.built.projectId,
              environmentId: "ghost",
              epoch: 1,
              issuer: fixture.owner,
              head: headOf(fixture.built, 3),
              envStatement: ghostEnvStatement,
              statements: [ghostEntry.statement],
            }),
            schemaPolicy: "enabled",
          },
        }),
      ),
    ]);
    expect(await runCli(["pull", "--env", "ghost"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=environment-not-created-at-head");
  });

  it("refuses a wrap whose signer FP matches no key in chain history", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const wrongFp = { ...wrap, signerKeyFingerprintHex: "00".repeat(16) };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [wrongFp, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("signer does not exist in the chain history");
  });

  it("refuses duplicate DEK wraps for the same epoch", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [fixture.wraps[0], fixture.wraps[0], fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Duplicate DEK wraps");
  });

  it("ciphertext swapped in that was encrypted under another environment's coordinates is refused before decryption", async () => {
    const crossEnv = await distributedValue({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: "other-env",
      epoch: 2,
      variableId: "va",
      version: 3,
      plaintext: "cross",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "va", "ALPHA", crossEnv)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "declares AAD coordinates that do not match the requested context",
    );
  });

  it("a removed→re-added (new key) member's past signature verifies under the key of its time (§5.1)", async () => {
    const oldKeys = await generateIdentity("user-rotated-5555");
    const newKeys = await generateIdentity("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(newKeys, "member") },
    ]);
    const wrap = await distributedWrap({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: oldKeys,
    });
    const value = await distributedValue({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vr",
      version: 1,
      plaintext: "historic",
      writer: oldKeys,
      head: headOf(built, 3),
    });
    const historicEnvStatement = await pullEnvStatement(built.projectId, owner);
    const historicEntry = await pullEntry(built.projectId, "vr", "HISTORIC", value, owner);
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: historicEnvStatement,
      variables: [historicEntry],
      deletedVariables: [],
      deks: [wrap],
      manifest: await distributedManifest({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, 5),
        envStatement: historicEnvStatement,
        statements: [historicEntry.statement],
      }),
      schemaPolicy: "enabled" as const,
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
          attestations: [],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("HISTORIC");
  });

  it("tokens / secret-key material never appear in the output", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("maruhi_pat_");
    expect(output).not.toContain(fixture.owner.encSkHex);
    expect(output).not.toContain(fixture.owner.sigSkSeedHex);
  });

  it("control characters in variable names (ANSI, newlines) are sanitized in terminal output", async () => {
    const evilName = "EVIL\u001b[2J\nNAME";
    const value = await distributedValue({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "ve",
      version: 1,
      plaintext: "v",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "ve", evilName, value)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).toContain("EVIL\uFFFD[2J\uFFFDNAME");
  });

  it("refuses duplicate variable names (a server-response inconsistency)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          fixture.entryAlpha,
          await pullEntry(fixture.built.projectId, "vb", "ALPHA", fixture.valueBeta),
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Multiple live statements with the same name");
  });

  it("refuses a value-signature bit-flip before decryption (§4.1)", async () => {
    const value = fixture.valueAlpha;
    const flipped = `${value.signatureHex.slice(0, -1)}${
      value.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, value: { ...value, signatureHex: flipped } }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });

  it("refuses a false writer claim (the signature stays someone else's) (the §4.1 attribution)", async () => {
    const stranger = await generateIdentity("user-stranger-9999");
    const lying = {
      ...fixture.valueAlpha,
      writerUserId: stranger.userId,
      writerKeyFingerprintHex: stranger.fingerprintHex,
    };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, value: lying }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=writer-unknown");
  });

  it("refuses a value whose removed writer declared a post-removal head (§6.3-3)", async () => {
    const oldKeys = await generateIdentity("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(await generateIdentity("user-other-7777"), "member") },
    ]);
    const wrap = await distributedWrap({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const forged = await distributedValue({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vf",
      version: 1,
      plaintext: "forged-after-removal",
      writer: oldKeys,
      head: headOf(built, 5),
    });
    const forgedEntry = await pullEntry(built.projectId, "vf", "FORGED", forged, owner);
    const envStatement = await pullEnvStatement(built.projectId, owner);
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: envStatement,
      variables: [forgedEntry],
      deletedVariables: [],
      deks: [wrap],
      manifest: await distributedManifest({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(built, built.entries.length),
        envStatement,
        statements: [forgedEntry.statement],
      }),
      schemaPolicy: "enabled" as const,
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
          attestations: [],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: pullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=writer-not-member-at-head");
  });

  it("refuses duplicate variableIds within one response (the carriage form of equivocation)", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          fixture.entryAlpha,
          { ...fixture.entryAlpha, statement: { ...fixture.entryAlpha.statement, name: "ALPHA2" } },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Duplicate variable IDs within one response");
  });

  it("a value written by a member added in the unsynced gap is accepted via bounded resync", async () => {
    const owner = fixture.owner;
    const newcomer = await generateIdentity("user-newcomer-2222");
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const shortBuilt = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const fullBuilt = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(newcomer, "member") },
      { actor: newcomer, operation: createEnvironmentOp(ENV_ID, dek) },
    ]);
    expect(shortBuilt.projectId).toBe(fullBuilt.projectId);
    const wrap = await distributedWrap({
      projectId: fullBuilt.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: newcomer,
    });
    const value = await distributedValue({
      dek,
      projectId: fullBuilt.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vn",
      version: 1,
      plaintext: "by-newcomer",
      writer: newcomer,
      head: headOf(fullBuilt, 3),
    });
    const newcomerEnvStatement = await pullEnvStatement(fullBuilt.projectId, owner);
    const newcomerEntry = await pullEntry(fullBuilt.projectId, "vn", "NEWCOMER", value, owner);
    const newcomerPullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: newcomerEnvStatement,
      variables: [newcomerEntry],
      deletedVariables: [],
      deks: [wrap],
      manifest: await distributedManifest({
        projectId: fullBuilt.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        issuer: owner,
        head: headOf(fullBuilt, 3),
        envStatement: newcomerEnvStatement,
        statements: [newcomerEntry.statement],
      }),
      schemaPolicy: "enabled" as const,
    };
    let chainCalls = 0;
    const server = await MockServer.start([
      onRequest("GET", `/projects/${fullBuilt.projectId}/chain`, () => {
        chainCalls += 1;
        const source = chainCalls === 1 ? shortBuilt : fullBuilt;
        return {
          status: 200,
          json: {
            projectId: fullBuilt.projectId,
            entries: source.entries,
            headSeq: source.entries.length,
            headHashHex: source.hashes[source.hashes.length - 1],
            attestations: [],
          },
        };
      }),
      onRequest("GET", `/projects/${fullBuilt.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: newcomerPullJson,
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: fullBuilt.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("NEWCOMER");
  });

  it("a future head (a declared seq beyond our view) is accepted via the bounded-resync extension check (§6.3-2b)", async () => {
    const { built } = fixture;
    const shortChain = built.entries.slice(0, 2);
    let chainCalls = 0;
    const progressiveChain = onRequest("GET", `/projects/${built.projectId}/chain`, () => {
      chainCalls += 1;
      const entries = chainCalls === 1 ? shortChain : built.entries;
      return {
        status: 200,
        json: {
          projectId: built.projectId,
          entries,
          headSeq: entries.length,
          headHashHex: built.hashes[entries.length - 1],
          attestations: [],
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [fixture.entryAlpha],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("ALPHA");
  });

  it("refuses when the future-head resync is not an extension of the old view (a swapped different-history chain)", async () => {
    const { built, owner } = fixture;
    const forkDek = crypto.getRandomValues(new Uint8Array(32));
    const forked = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, fixture.dek1) },
      { actor: owner, operation: createEnvironmentOp("side", forkDek) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, fixture.dek2) },
    ]);
    expect(forked.projectId).toBe(built.projectId);
    const futureValue = await distributedValue({
      dek: fixture.dek2,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 1,
      plaintext: "future",
      writer: owner,
      head: headOf(forked, 4),
    });
    let chainCalls = 0;
    const progressiveChain = onRequest("GET", `/projects/${built.projectId}/chain`, () => {
      chainCalls += 1;
      const source = chainCalls === 1 ? built : forked;
      return {
        status: 200,
        json: {
          projectId: built.projectId,
          entries: source.entries,
          headSeq: source.entries.length,
          headHashHex: source.hashes[source.hashes.length - 1],
          attestations: [],
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [{ ...fixture.entryAlpha, value: futureValue }],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not an extension of the verified view");
  });

  it("a head declaration whose seq is at-or-below our view but whose hash mismatches is refused immediately (§6.3-2a)", async () => {
    const bogus = await distributedValue({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 1,
      plaintext: "bogus-head",
      writer: fixture.owner,
      head: { seq: 3, hashHex: "ee".repeat(32) },
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, value: bogus }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=chain-head-mismatch");
  });
});
