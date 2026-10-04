// Integration tests for `maruhi device add / approve / list / revoke` and the
// first-sync device registration (CRYPTO_SPEC §3 / §6.2 / §7, AUTH_SPEC §13-11
// — 2026-09-19 DK K4. Design doc dk-design.md §9).
// Device ops are signed / verified with real crypto; the server is a wire-level mock.
//
// Pinned properties:
//  5. `device add` refuses by default on a device that already has a key
//     (rebuild with `--replace` — K4-18); the signal of approval is the
//     registry, confirmation of completion is the chain (K4-5)

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { DEVICE_ADD_REQUEST_TTL_MS } from "@maruhi/api-schema";
import { computeUserKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { DEVICE_ADD_WAIT_HINT_AFTER_MS } from "../src/device-add.ts";
import { masterKeyEntryName, tokenEntryName } from "../src/keychain.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
  hexBytes,
  rotateEpochOp,
  type TestUser,
  wrapDekFor,
} from "./support/crypto.ts";
import {
  ENV_ID,
  FAR_FUTURE_MS,
  owner,
  dev2,
  reserve,
  member,
  dek,
  addDeviceOp,
  revokeDeviceOp,
  type ServerState,
  makeServer,
  startEnv,
  requestRowOf,
  registryRowOf,
  startEnvWithoutKey,
} from "./support/device.ts";
import { makeTestEnv, seedConfig, type TestEnv } from "./support/env.ts";
import { onRequest } from "./support/server.ts";

describe("maruhi device add", () => {
  it("a device holding a registered key reports it as registered (no request is created); --replace swaps after the new key's request (K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    // An existing key never goes to create a request (never spends the server's 5-per-hour window)
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );

    // --replace: show the discarded key's standing → generate a new key → request → swap → signal → confirm on the chain
    const before = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(
      await runCli(["device", "add", "--label", "phone", "--replace"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const after = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(after).toBeDefined();
    expect(after).not.toBe(before);
    const requestBody = server.requests.find(
      (request) => request.method === "POST" && request.path === "/auth/devices/requests",
    )?.body as { label: string; encPubHex: string } | undefined;
    expect(requestBody?.label).toBe("phone");
    expect(after).toContain(requestBody?.encPubHex ?? "never");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: replacing this machine's key ${owner.fingerprintHex}, which is registered on ${built.projectId}. Once the new key is approved, revoke the previous key where it is still registered unless another machine holds it (\`maruhi device revoke ${owner.fingerprintHex}\` from a registered device)`,
    );
    expect(errors).toContain("replaced the previous key in this machine's keychain (--replace)");
    const logs = env.logs.join("\n");
    expect(logs).toContain("This device's key fingerprint:");
    expect(logs).toContain("fp words:");
    // The chain is the truth: sync after the signal and count the projects it has not landed on yet
    expect(logs).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain)",
    );
    // The shortfall guidance (K7-2): the approver's work is done · the request
    // is spent · registration happens on the next keyed command of a device
    // the cap covers (never says "re-run the approval" or "still working")
    const missingNote = env.errors.find((line) => line.includes("not registered yet on"));
    expect(missingNote).toContain(`not registered yet on ${built.projectId}`);
    expect(missingNote).toContain("skipped or failed on them");
    expect(missingNote).toContain("The request is used up");
    // The prelude is one command per project, so it is "a keyed command aimed at that project" (DK K10-5)
    expect(missingNote).toContain(
      "when it runs a keyed command on that project at a terminal (`maruhi pull --project <id>`, for instance)",
    );
    expect(missingNote).not.toContain("may still be working");
    expect(missingNote).not.toContain("Re-run `maruhi device approve`");
  });

  it("when resuming on a 409 request-exists and the request lookup fails, reports that failure (never misguides as 'revoked')", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => ({
          status: 409,
          json: { _tag: "DeviceRegistryConflict", reason: "request-exists" },
        })),
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // The default mock returns 404 for GET /auth/devices/requests/:fp
    expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("expired before this machine saw the completion signal");
    expect(errors).toContain("DeviceNotFound");
  });

  it("a new key's 409 device-registered (only possible on an FP collision) never waits, never claims 'Approved', and reports in terms of the chain's standing (K13-3 — hole-5 defense)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true, conflict: "device-registered" },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: owner.userId,
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const logs = env.logs.join("\n");
    expect(logs).not.toContain("Approved:");
    expect(logs).not.toContain("The request expires at");
    expect(logs).not.toContain("Waiting for approval");
    expect(env.errors.join("\n")).not.toContain("still waiting (");
    // The new key is on no chain — it says 'nothing is lost' with the scope attached
    expect(env.errors.join("\n")).toContain(
      "has no pending device-add request and is on no project the server lists for you (1 listed), each chain synced and verified, so replacing it loses nothing there",
    );
    // Never goes to look up the request (the new key has no live request)
    expect(
      state.paths().some((path) => /^GET \/auth\/devices\/requests\/[0-9a-f]{32}$/.test(path)),
    ).toBe(false);
  });

  it("when a third of the TTL has passed since the request's creation with no signal, emits 'check the approver's output' exactly once (K7-3)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // Pretend the request was created 6 minutes ago (deadline = creation + 15 min). No signal yet
    const requestedAtMs = Date.now() - DEVICE_ADD_WAIT_HINT_AFTER_MS - 60 * 1000;
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: requestedAtMs + DEVICE_ADD_REQUEST_TTL_MS, signal: false },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: owner.userId,
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // After round 1 (no signal → guidance), place a row equivalent to the approver's PUT: round 2 picks up the signal
    const run = runCli(["device", "add", "--label", "phone"], env.layer);
    const rowPlaced = new Promise<void>((resolve) => {
      const tick = (): void => {
        const stored = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
        const hinted = env.errors.some((line) => line.includes("still waiting ("));
        if (stored !== undefined && hinted) {
          const record = JSON.parse(stored) as { encPubHex: string; sigPubHex: string };
          void computeUserKeyFingerprint(
            hexBytes(record.encPubHex),
            hexBytes(record.sigPubHex),
          ).then((fp) => {
            if (!fp.ok) throw new Error("fp");
            state.registry.push({
              keyFingerprintHex: encodeHex(fp.value),
              encPubHex: record.encPubHex,
              sigPubHex: record.sigPubHex,
              label: "phone",
              createdAtMs: Date.now(),
            });
            resolve();
          });
          return;
        }
        setTimeout(tick, 20);
      };
      tick();
    });
    await rowPlaced;
    expect(await run, env.errors.join("\n")).toBe(0);
    const hints = env.errors.filter((line) => line.includes("still waiting ("));
    expect(hints).toHaveLength(1);
    // Elapsed is measured for real (a resumed wait exceeds the threshold) — here threshold + 1 minute
    expect(hints[0]).toContain("6 minutes since the request");
    expect(hints[0]).toContain("this key is not in your device registry yet");
    expect(hints[0]).toContain(
      "failed on every project, or could not list this device in your device registry, the cause is in its output",
    );
    expect(env.logs.join("\n")).toContain("Approved: this device is registered on 0 projects");
  }, 15_000);

  it("when the request has expired, it ends with the TTL guidance (no signal)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: Date.now() - 1, signal: false },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_stored",
        userId: owner.userId,
        tokenId: "tok_1",
        expiresAtMs: 4_102_444_800_000,
      }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const expired = env.errors.join("\n");
    expect(expired).toContain(
      "The device-add request expired before this machine saw the completion signal (requests live 15 minutes)",
    );
    // The guidance matches the implementation (K7-1): re-running is refused
    // (K4-21), so it guides toward `--replace` conditioned on the approver
    // having registered nothing. Never says "rebuild with the same key"
    expect(expired).toContain("if it registered nothing, run `maruhi device add --replace`");
    expect(expired).not.toContain("it reuses this key");
    // K9-3's T3: when the approver registered but could not get onto the
    // registry and nobody re-ran before the deadline, the key is on the chain
    // — carrying the branch that never lets `--replace` discard it
    expect(expired).toContain(
      "If it registered this device but could not list it in your device registry, keep this key",
    );
    // The chain's fact at this point (K13-4 — appended while keeping the conditions)
    expect(expired).toContain(
      "On the project chains right now, this key is on no project the server lists for you (1 listed). If the approving device is still working, re-running `maruhi device add` on this machine later shows whether it registered this key, without a new request",
    );
    // The key stays generated (it is discarded only when a human types `--replace`)
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeDefined();
  });
});

/**
 * Scaffolding for the new device dev2's `device add` re-run (the registry row
 * is the signal — no request): the chain is genesis → environment (epoch 1) →
 * rotate (epoch 2) → dev2's `add_device` (cap is an argument).
 * The key at hand is dev2. The response of the GET for DEKs addressed to self is `listMine` (DK K12).
 */
async function deviceAddReachFixture(input: {
  readonly cap?: Parameters<typeof addDeviceOp>[1];
  /** Places dev2's live request (the resume-wait → signal → "Approved" path — DK K13-2). */
  readonly pending?: boolean;
  readonly listMine: (
    projectId: string,
  ) => Promise<{ readonly rows: readonly Record<string, unknown>[] } | { readonly status: number }>;
}): Promise<{ readonly env: TestEnv; readonly state: ServerState; readonly built: BuiltChain }> {
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    { actor: owner, operation: addDeviceOp(dev2, input.cap) },
  ]);
  reachDeks.set(built.projectId, [dek, dek2]);
  const { server, state } = await makeServer({
    built,
    withEnvironment: true,
    registryRows: [registryRowOf(dev2)],
    requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    listMine: await input.listMine(built.projectId),
    pendingRequests: input.pending === true ? [requestRowOf(dev2)] : [],
  });
  const env = await startEnv(server.origin, built.projectId, dev2);
  return { env, state, built };
}

/** The DEK of each epoch of `deviceAddReachFixture`'s chain (per project). */
const reachDeks = new Map<string, readonly Uint8Array[]>();

/** A device-addressed distribution row (the new server's shape — with `recipientEncPubHex`, owner's registration signature). */
async function deviceRowsOf(
  projectId: string,
  device: TestUser,
  epochs: readonly number[],
): Promise<Record<string, unknown>[]> {
  const deks = reachDeks.get(projectId) ?? [];
  return Promise.all(
    epochs.map(async (epoch) => ({
      ...(await wrapDekFor({
        projectId,
        environmentId: ENV_ID,
        epoch,
        dek: deks[epoch - 1] ?? new Uint8Array(32),
        recipient: device,
        signer: owner,
      })),
      recipientEncPubHex: device.encPubHex,
    })),
  );
}

function listMineGets(state: ServerState, projectId: string): number {
  return state
    .paths()
    .filter((path) => path === `GET /projects/${projectId}/environments/${ENV_ID}/deks`).length;
}

describe("maruhi device add — key arrival and revocation after the signal (DK K12)", () => {
  it("if an epoch addressed to this device is missing, emits pull's same warning with the real-id path, exits 0, and registers nothing", async () => {
    // Only epoch 1 is addressed to dev2 (the sibling's owner gets 1 and 2 —
    // rows addressed to other devices are not counted). Resume waiting on the
    // live request (no request is created), and check after the signal (the registry row)
    const { env, state, built } = await deviceAddReachFixture({
      pending: true,
      listMine: async (projectId) => ({
        rows: [
          ...(await deviceRowsOf(projectId, dev2, [1])),
          ...(await deviceRowsOf(projectId, owner, [1, 2])),
        ],
      }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 1 project (verified on each project's chain)",
    );
    const warning = env.errors.find((line) => line.includes("no DEK wraps for you exist"));
    expect(warning).toContain(
      `Warning: ${built.projectId}: environment ${ENV_ID}: no DEK wraps for you exist at epochs 2 (inconsistent with the CRYPTO_SPEC §7 all-epoch distribution)`,
    );
    expect(warning).toContain(
      "If this machine was added as a device, the backfill to it may not have completed instead.",
    );
    expect(warning).toContain(
      `A registered device of yours whose cap covers environment ${ENV_ID} and that holds its keys fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    // The new device lacks the missing DEKs, so it does not fill them (the sibling device's pull fills them — K11)
    expect(state.registered).toEqual([]);
    expect(env.errors.join("\n")).toContain("resuming the wait for its approval");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
    expect(env.errors.join("\n")).not.toContain("not registered yet");
  });

  it("when every epoch has arrived, nothing is appended (the check does run — GET is once)", async () => {
    const { env, state, built } = await deviceAddReachFixture({
      listMine: async (projectId) => ({ rows: await deviceRowsOf(projectId, dev2, [1, 2]) }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(listMineGets(state, built.projectId)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).not.toContain("could not check");
  });

  it("does not check environments outside this device's cap (an environment it is not a recipient of is called neither missing nor a check failure)", async () => {
    const { env, state, built } = await deviceAddReachFixture({
      cap: { roleCap: "owner", environmentIds: [] },
      listMine: async () => ({ rows: [] }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(listMineGets(state, built.projectId)).toBe(0);
    // Called neither missing nor a check failure (outside the cap, cannot be opened) — never enters the enumeration
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).not.toContain("could not check");
  });

  it("an environment that could not be checked is not called missing — a Note with the cause, exit code 0", async () => {
    const { env, built } = await deviceAddReachFixture({
      listMine: async () => ({ status: 500 }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).toContain(
      `Note: ${built.projectId}: could not check that the keys of environment ${ENV_ID} reached this device (`,
    );
    expect(errors).toContain(
      `\`maruhi pull --project ${built.projectId} --env ${ENV_ID}\` on this machine reports any missing epochs`,
    );
  });

  it("a key revoked on every project never waits even if the registry row remains, and stops with revocation and re-adding (K13-2 — collecting consultation point (2))", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    // "Approved: … 0 projects" can structurally never appear (there is no path that waits on the registry row as the signal)
    expect(env.logs.join("\n")).not.toContain("Approved:");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) is revoked on ${built.projectId} and registered on no project the server lists for you (1 listed), and it has no pending device-add request. To add this machine back, run \`maruhi device add --replace\` on this machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device — you choose its cap again when approving`,
    );
    expect(errors).not.toContain("not registered yet");
    expect(errors).not.toContain("the approving device skipped or failed");
    expect(errors).not.toContain("loses nothing");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
  });

  it("a key revoked on only some projects says to revoke it on the remaining projects after re-adding (K12-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    // On another project (its genesis key differs → a different id — same person), dev2 is valid
    const other = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extraProjects: [other],
      registryRows: [registryRowOf(dev2)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    // A valid project exists, and there the provenance is add_device → a
    // usable key (exit 0 — K13-2). No approval happened, so it never says "Approved" (K13-3)
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    expect(logs).not.toContain("Approved:");
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Note: this key was revoked on ${built.projectId},`);
    expect(errors).toContain(
      `. This keychain then no longer holds this key, so revoke it on ${other.projectId}, where it is still registered (\`maruhi device revoke ${dev2.fingerprintHex}\` from a registered device)`,
    );
    expect(errors).not.toContain("not registered yet");
  });
});

function requestPosts(state: ServerState): readonly string[] {
  return state.paths().filter((path) => path === "POST /auth/devices/requests");
}

describe("maruhi device add — an existing key's standing on the chain (DK K13)", () => {
  it("a valid key whose provenance is add_device on every project reports registered and exits 0 without creating a request. Appends a note if the registry row is missing (T3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    expect(logs).not.toContain("Approved:");
    expect(env.errors.join("\n")).toContain(
      "Note: this key has no row in your device registry (an approval whose registry write failed leaves it so). The registry only labels devices, so nothing else is needed",
    );
    expect(requestPosts(state)).toEqual([]);

    // No note when the registry has a row (the note is only for a missing row)
    const withRow = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
    });
    const env2 = await startEnv(withRow.server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env2.layer), env2.errors.join("\n")).toBe(0);
    expect(env2.errors.join("\n")).not.toContain("has no row in your device registry");
  });

  it("a project missing on a path where no approval happened is stated in a neutral sentence, not the approver-side script (K13-3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const other = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extraProjects: [other],
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: this key is not registered on ${other.projectId}. A device of yours whose cap covers them registers it on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance), once it has synced a project that has this key`,
    );
    expect(errors).not.toContain("the approving device skipped or failed");
    expect(errors).not.toContain("The request is used up");
  });

  it("when everything synced with zero valid placements and the key is nowhere, it says 'nothing is lost' with the list count attached", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `This machine's device key (${dev2.fingerprintHex}) has no pending device-add request and is on no project the server lists for you (1 listed), each chain synced and verified, so replacing it loses nothing there: re-run with --replace — it discards this key, generates a new one and prints its fingerprint to approve from a registered device`,
    );
    expect(env.errors.join("\n")).not.toContain("local records of");
    expect(requestPosts(state)).toEqual([]);
  });

  it("plan B: a project in the floor but absent from the list is only attached as information — it never stops the judgment ('nowhere')", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    const unlisted = "ab".repeat(32);
    await mkdir(env.floorDir, { recursive: true });
    await writeFile(join(env.floorDir, `${unlisted}.jsonl`), "");
    // Things that are not ID-shaped and sidecar files are not counted
    await writeFile(join(env.floorDir, `${"cd".repeat(32)}.attested.json`), "{}");
    await writeFile(join(env.floorDir, "notes.jsonl"), "");
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("so replacing it loses nothing there");
    expect(errors).toContain(
      `. This machine also has local records of 1 project that list does not include (${unlisted}); those records are not separated by server or account, so they may not be yours here — if one is, check it with \`maruhi project verify --project <id>\` before replacing`,
    );
    expect(errors).not.toContain("could not check every project");
  });

  it("when a project cannot be synced, it neither says 'nowhere' nor asserts it. A verification contradiction is a Warning as a tampering sign", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const tampered = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      brokenProjects: [
        { built: down, mode: "unavailable" },
        { built: tampered, mode: "tampered" },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) has no pending device-add request, and maruhi could not check every project it may be registered on: `,
    );
    expect(errors).toContain(`${down.projectId} could not be synced (`);
    expect(errors).toContain(`It is not on ${built.projectId}. `);
    expect(errors).toContain(
      "Nothing is decided from a project that was not checked, so this does not say the key is unused",
    );
    expect(errors).not.toContain("loses nothing");
    const warnings = env.errors.filter((line) => line.startsWith("Warning:"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: ${tampered.projectId}: `);
    expect(warnings[0]).toContain(
      "— a sign of tampering rather than a network error, so nothing about this key is decided from that project",
    );
    expect(requestPosts(state)).toEqual([]);
  });

  it("does not fail when the project list cannot be fetched, and never asserts it as unsyncable (hole 6)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false, projectsStatus: 500 });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "and maruhi could not check every project it may be registered on: your projects could not be listed (",
    );
    expect(errors).not.toContain("loses nothing");
    expect(errors).not.toContain("is revoked on");
  });

  it("after the signal: unsyncable projects are not mixed into 'not registered yet', and a list failure never counts a 0 (K13-3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      brokenProjects: [{ built: down, mode: "unavailable" }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 1 project (verified on each project's chain)",
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Note: ${down.projectId}: could not sync this project (`);
    expect(errors).toContain(
      "so whether this key is registered there is unknown; `maruhi device list` checks again",
    );
    expect(errors).not.toContain("not registered yet");
    expect(errors).not.toContain("Warning:");
    // Resuming a live request never creates a request (never spends the window — and no hole-5 path exists)
    expect(requestPosts(state)).toEqual([]);

    const listDown = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      projectsStatus: 500,
    });
    const env2 = await startEnv(listDown.server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env2.layer), env2.errors.join("\n")).toBe(0);
    const logs2 = env2.logs.join("\n");
    expect(logs2).toContain(
      "Approved: the approving device gave the completion signal (this device is listed in your device registry)",
    );
    expect(logs2).not.toContain("registered on 0 projects");
    expect(env2.errors.join("\n")).toContain("Note: your projects could not be listed (");
  });

  it("when no project can be synced after the signal, it never counts 0 as fact — it attaches the count of what could not be checked (K13-16)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({
      built: await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]),
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      brokenProjects: [{ built, mode: "unavailable" }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    // The list's first entry (genesis is reserve) syncs and dev2 is absent; the second cannot be synced
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain), and 1 project could not be checked",
    );
    expect(env.errors.join("\n")).toContain(
      `Note: ${built.projectId}: could not sync this project (`,
    );
  });

  it("on expiry, appends the chain's fact at this point while keeping the approver-side output's conditions (K13-4)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    // The registry row stays missing (T3 — the approver's PUT dropped), and the request has expired
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      pendingRequests: [{ ...requestRowOf(dev2), expiresAtMs: Date.now() - 1 }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const expired = env.errors.join("\n");
    expect(expired).toContain(
      "If it registered this device but could not list it in your device registry, keep this key",
    );
    expect(expired).toContain(
      `On the project chains right now, this key is registered on ${built.projectId} — keep it; re-running \`maruhi device add\` on this machine confirms that without a new request`,
    );
  });

  it("--replace: when request creation fails (cap · full), nothing is replaced and the old key remains (K13-8)", async () => {
    for (const reason of ["add-requests", "device-rows"] as const) {
      const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
      const { server } = await makeServer({
        built,
        withEnvironment: false,
        extra: [
          onRequest("POST", "/auth/devices/requests", () => ({
            status: 429,
            json: {
              _tag: "DeviceRegistryLimit",
              reason,
              limit: reason === "add-requests" ? 5 : 32,
            },
          })),
        ],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      const entry = masterKeyEntryName(server.origin, owner.userId);
      const before = env.keychain.get(entry);
      expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
      expect(env.keychain.get(entry), reason).toBe(before);
      const errors = env.errors.join("\n");
      expect(errors).toContain(
        "nothing was replaced: the previous key is still in this machine's keychain (--replace replaces it only once the new key's request exists)",
      );
      expect(errors).not.toContain("replaced the previous key in this machine's keychain");
      expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
    }
  });

  it("a keyless device follows the same order 'generate → request → save': a failed request leaves no key (K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => ({
          status: 429,
          json: { _tag: "DeviceRegistryLimit", reason: "add-requests", limit: 5 },
        })),
      ],
    });
    const env = await startEnvWithoutKey(server.origin, built.projectId);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeUndefined();
    expect(env.errors.join("\n")).not.toContain("nothing was replaced");
  });

  it("the guarded replace never overwrites a key another process wrote during request creation, and emits no FP (K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let env: TestEnv | null = null;
    let entry = "";
    // A value written by another process (the guard only compares the value)
    const intruder = "written-by-another-process";
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => {
          // Another process rewrites the keychain while the request is being created
          env?.keychain.set(entry, intruder);
          return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
        }),
      ],
    });
    env = await startEnv(server.origin, built.projectId, owner);
    entry = masterKeyEntryName(server.origin, owner.userId);
    expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
    expect(env.keychain.get(entry)).toBe(intruder);
    expect(env.errors.join("\n")).toContain(
      "Another process wrote this machine's device key while `maruhi device add` was running, so the new key was not stored and the key now in the keychain was left as it is. The request made for the new key is never approved (its fingerprint was not shown) and expires in 15 minutes",
    );
    expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
    expect(env.errors.join("\n")).not.toContain(
      "replaced the previous key in this machine's keychain",
    );
  });

  it("on detecting a concurrent write while a keyless device saves, it states that the request was already created and never emits the key-generate sentence (K13-14)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let env: TestEnv | null = null;
    let entry = "";
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => {
          env?.keychain.set(entry, "written-by-another-process");
          return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
        }),
      ],
    });
    env = await startEnvWithoutKey(server.origin, built.projectId);
    entry = masterKeyEntryName(server.origin, owner.userId);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.keychain.get(entry)).toBe("written-by-another-process");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "Another process wrote this machine's device key while `maruhi device add` was running, so the new key was not stored",
    );
    expect(errors).not.toContain("nothing was left behind");
    expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
  });
});
