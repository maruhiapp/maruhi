// `maruhi invite create|accept|list|revoke`(AUTH_SPEC §15 / CRYPTO_SPEC §6.5 —
// 2026-09-13 IV revision / v2 links).
//
// Properties pinned here:
//  1. Link assembly / parsing (§15-3): parameter order, optional il; broken
//     links / old versions (v=1) / raw tokens are all rejected (no compat path)
//  2. create: client-numbered id + issuance signature (own chain sig key) +
//     issuance pin (link_pub / role) saved + role=admin is owner-only + refusal on key mismatch
//  3. accept: issuance-signature verification (mechanical) → ceremony (last-word
//     re-entry / --inviter-fingerprint / agent refusal) → key guard →
//     co-signature (verifiable) → response match (p / r are signed, so mismatch = refusal) → anchor pinning (only after acceptance succeeds)
//  4. list: §6.5 independent verification of the issuance signature / acceptance block + issuance-pin match (mismatch = exit 1)
//  5. revoke: revocation and the 410 wording

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  decodeHex,
  fingerprintToWords,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { buildInviteLink, parseInviteAcceptInput } from "../src/invite-link.ts";
import { serializeStoredToken, tokenEntryName, type StoredToken } from "../src/keychain.ts";
import {
  addScopedMemberOp,
  buildChain,
  createEnvironmentOp,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import {
  acceptanceFixture,
  flipHex,
  githubSigningKeysHandler,
  INVITE_ID,
  inviteLinkText,
  issueInviteFixture,
  type IssuedInviteFixture,
  LINK_SEED_HEX,
  sshLineOf,
} from "./support/invite.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let inviter: TestUser;
let acceptor: TestUser;
let inviterWords: readonly string[];

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
  const bytes = decodeHex(inviter.fingerprintHex);
  if (bytes === null) throw new Error("inviter fp");
  const words = await fingerprintToWords(bytes);
  if (!words.ok) throw new Error("inviter fp words");
  inviterWords = words.value;
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

function chainHandler(built: {
  readonly projectId: string;
  readonly entries: readonly unknown[];
  readonly hashes: readonly string[];
}): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

/** Seeds a logged-in state (no device key) — for key-generation-path tests. */
function seedTokenOnly(env: TestEnv, origin: string, user: TestUser): void {
  const token: StoredToken = {
    token: Redacted.make("maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123"),
    userId: user.userId,
    tokenId: "tok_0001",
  };
  env.keychain.set(tokenEntryName(origin), serializeStoredToken(token));
}

/** Reads the accepter-side pins file (anchors). */
async function readPins(env: TestEnv, projectId: string): Promise<Record<string, unknown>> {
  const json = await readFile(join(env.pinsDir, `${projectId}.json`), "utf8");
  return JSON.parse(json) as Record<string, unknown>;
}

/** The issuance POST body (wire form). */
interface IssueBody {
  readonly id: string;
  readonly role: string;
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly string[];
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

/** The acceptance POST body (wire form). */
interface AcceptBody {
  readonly linkPubHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly acceptSignatureHex: string;
  readonly linkSignatureHex: string;
}

describe("invite link(§15-3 v2)", () => {
  const PROJECT_ID = "ab".repeat(32);
  let issued: IssuedInviteFixture;

  beforeAll(async () => {
    issued = await issueInviteFixture({
      inviter,
      projectId: PROJECT_ID,
      headHashHex: "cd".repeat(32),
      headSeq: 7,
      inviterLogin: "octocat",
    });
  });

  it("assembly → parsing round-trips (parameter order follows the spec's listing order)", () => {
    const link = inviteLinkText("https://maruhi.example", issued);
    expect(link).toBe(
      `https://maruhi.example/invite#v=2&i=${INVITE_ID}&k=${LINK_SEED_HEX}&p=${PROJECT_ID}&h=${"cd".repeat(32)}&s=7&iu=${inviter.userId}&ie=${inviter.encPubHex}&is=${inviter.sigPubHex}&r=member&sk=all&se=&il=octocat&sig=${issued.link.issueSignatureHex}`,
    );
    const parsed = parseInviteAcceptInput(Redacted.make(link));
    if (parsed.kind !== "link") throw new Error(`expected link, got ${parsed.kind}`);
    // The seed is compared unwrapped: toEqual does not inspect Redacted's
    // contents (no own properties — two different values compare equal), so
    // comparing while wrapped is a vacuous "any seed passes" assertion
    expect(Redacted.value(parsed.link.linkSeedHex)).toBe(LINK_SEED_HEX);
    expect({ ...parsed.link, linkSeedHex: undefined }).toEqual({
      ...issued.link,
      linkSeedHex: undefined,
    });
  });

  it("also parses an il-less link as valid (inviterLogin = null)", () => {
    const link = inviteLinkText("https://maruhi.example", issued).replace("&il=octocat", "");
    const parsed = parseInviteAcceptInput(Redacted.make(link));
    if (parsed.kind !== "link") throw new Error("expected link");
    expect(parsed.link.inviterLogin).toBeNull();
    expect(
      Redacted.value(buildInviteLink({ origin: "https://maruhi.example", link: parsed.link })),
    ).toBe(link);
  });

  it("rejects raw tokens, the old version (v=1), and missing v (no compatibility path)", () => {
    expect(
      parseInviteAcceptInput(
        Redacted.make("maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01"),
      ),
    ).toEqual({ kind: "rejected", reason: "not-a-link" });
    expect(
      parseInviteAcceptInput(
        Redacted.make(
          `https://maruhi.example/invite#v=1&t=maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01&p=${PROJECT_ID}`,
        ),
      ),
    ).toEqual({ kind: "rejected", reason: "unsupported-version" });
    expect(
      parseInviteAcceptInput(Redacted.make(`https://maruhi.example/invite#p=${PROJECT_ID}`)),
    ).toEqual({ kind: "rejected", reason: "missing-or-invalid-fragment-params" });
  });

  it("errors on missing required parameters / malformed formats (never lets a broken link slide into acceptance)", () => {
    const link = inviteLinkText("https://maruhi.example", issued);
    for (const broken of [
      link.replace(`&i=${INVITE_ID}`, ""),
      link.replace(`&k=${LINK_SEED_HEX}`, `&k=${"zz".repeat(32)}`),
      link.replace(`&h=${"cd".repeat(32)}`, ""),
      link.replace("&s=7", "&s=0"),
      link.replace("&r=member", "&r=superuser"),
      link.replace(`&is=${inviter.sigPubHex}`, "&is=zz"),
      link.replace("&il=octocat", "&il=-bad-"),
      link.replace(`&sig=${issued.link.issueSignatureHex}`, "&sig=00"),
    ]) {
      expect(parseInviteAcceptInput(Redacted.make(broken))).toEqual({
        kind: "rejected",
        reason: "missing-or-invalid-fragment-params",
      });
    }
  });
});

describe("maruhi invite create", () => {
  function issueHandler(
    projectId: string,
    record: (body: IssueBody) => void,
    status = 200,
  ): MockHandler {
    return onRequest("POST", `/projects/${projectId}/invites`, (request) => {
      record(request.body as IssueBody);
      return status === 200
        ? { status, json: { expiresAtMs: 1755993600000 } }
        : { status, json: {} };
    });
  }

  it("assigns an id, sends the issuance text with the issuance signature, displays the link (seed + issuance text), and saves the issuance pin", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issued.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(issued).toHaveLength(1);
    const body = issued[0];
    if (body === undefined) throw new Error("no issue body");
    expect(body.role).toBe("member");
    expect(body.scopeKind).toBe("all");
    expect(body.scopeEnvironmentIds).toEqual([]);
    expect(body.headSeq).toBe(1);
    expect(body.headHashHex).toBe(built.hashes[0]);
    // The issuance signature verifies with the inviter's chain key (CRYPTO_SPEC §6.5)
    const verified = await verifyInviteIssueSignature({
      context: {
        suite: SUITE_ID,
        inviteId: body.id,
        projectId: built.projectId,
        linkPubHex: body.linkPubHex,
        headHashHex: body.headHashHex,
        headSeq: body.headSeq,
        role: "member",
        inviterUserId: inviter.userId,
        inviterEncPubHex: inviter.encPubHex,
        inviterSigPubHex: inviter.sigPubHex,
        // The K2 CLI issues only scope = all (carried on both the issuance body and the issuance signature)
        scopeKind: body.scopeKind,
        scopeEnvironmentIds: body.scopeEnvironmentIds,
      },
      signatureHex: body.issueSignatureHex,
    });
    expect(verified.ok).toBe(true);
    // The seed is never sent to the server (only the public key and issuance text)
    expect(JSON.stringify(body)).not.toContain("k=");
    expect(Object.keys(body).toSorted()).toEqual([
      "headHashHex",
      "headSeq",
      "id",
      "issueSignatureHex",
      "linkPubHex",
      "role",
      "scopeEnvironmentIds",
      "scopeKind",
    ]);

    // The displayed link parses and matches the issuance text (the public key derived from the seed = the link_pub that was sent)
    const shown = env.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    if (shown === undefined) throw new Error("link not shown");
    const parsed = parseInviteAcceptInput(Redacted.make(shown));
    if (parsed.kind !== "link") throw new Error("link did not parse");
    expect(parsed.link.inviteId).toBe(body.id);
    expect(parsed.link.issueSignatureHex).toBe(body.issueSignatureHex);
    expect(parsed.link.inviterSigPubHex).toBe(inviter.sigPubHex);
    expect(parsed.link.inviterLogin).toBeNull();
    const reissued = await issueInviteFixture({
      inviter,
      projectId: built.projectId,
      headHashHex: body.headHashHex,
      headSeq: body.headSeq,
      inviteId: body.id,
      seedHex: Redacted.value(parsed.link.linkSeedHex),
    });
    expect(reissued.linkPubHex).toBe(body.linkPubHex);

    // The issuance pin (the inviter-side counterpart of §6.5 — SHOULD): link_pub and role to non-secret local storage
    const pins = await readPins(env, built.projectId);
    expect(pins["issued"]).toEqual({
      [body.id]: {
        linkPubHex: body.linkPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
        expiresAtMs: 1755993600000,
        expectedGithubLogin: null,
      },
    });
    expect(env.errors.join("\n")).toContain("This link is shown only once");
  });

  it("--github keeps the destination login in the issuance pin and builds il= from the own login in /auth/me (IV2)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, () => undefined),
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: inviter.userId, orgs: [], providerLogin: "alice" },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(
      await runCli(["invite", "create", "--role", "member", "--github", "bob"], env.layer),
    ).toBe(0);
    const shown = env.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    const parsed = parseInviteAcceptInput(Redacted.make(shown ?? ""));
    if (parsed.kind !== "link") throw new Error("link did not parse");
    expect(parsed.link.inviterLogin).toBe("alice");
    const pins = await readPins(env, built.projectId);
    const issued = pins["issued"] as Record<string, { expectedGithubLogin: string | null }>;
    expect(issued[parsed.link.inviteId]?.expectedGithubLogin).toBe("bob");
    // The destination login is never sent to the server (only into the issuance pin) — the guidance mentions the GitHub match
    expect(env.errors.join("\n")).toContain("github.com/bob's signing keys");

    // A malformed login form fails before issuance (usage)
    expect(
      await runCli(["invite", "create", "--role", "member", "--github", "bad--login"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--github must be a GitHub login");

    // With identityBacking = none, il is not built (an environment that does not use the backing source)
    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, inviter);
    await seedConfig(env2, {
      server: server.origin,
      defaultProject: built.projectId,
      identityBacking: "none",
    });
    expect(await runCli(["invite", "create", "--role", "member"], env2.layer)).toBe(0);
    const shown2 = env2.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    expect(shown2).not.toContain("&il=");
  });

  it("role=admin issuance is owner-only (an admin attempt is refused before any communication)", async () => {
    const admin2 = await makeTestUser("user-admin2-333");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      {
        actor: inviter,
        operation: {
          op: "add_member",
          payload: {
            targetUserId: admin2.userId,
            encPubHex: admin2.encPubHex,
            sigPubHex: admin2.sigPubHex,
            role: "admin",
            scopeKind: "all",
            scopeEnvironmentIds: [],
          },
        },
      },
    ]);
    const issueCalls: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issueCalls.push(b), 500),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, admin2);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "admin"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Only an owner can issue a role=admin invite");
    expect(issueCalls).toHaveLength(0);
  });

  it("repeated --env puts the listed scope, sorted ascending, onto the issuance text / body / link / issuance pin (ES K4 — ruling K)", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp("env-staging", dek) },
      { actor: inviter, operation: createEnvironmentOp("env-dev", dek) },
    ]);
    const issued: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issued.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(
      await runCli(
        ["invite", "create", "--role", "reader", "--env", "env-staging", "--env", "env-dev"],
        env.layer,
      ),
    ).toBe(0);
    const body = issued[0];
    if (body === undefined) throw new Error("no issue body");
    expect(body.scopeKind).toBe("listed");
    expect(body.scopeEnvironmentIds).toEqual(["env-dev", "env-staging"]);
    // The issuance signature covers the scope (CRYPTO_SPEC §6.5)
    const verified = await verifyInviteIssueSignature({
      context: {
        suite: SUITE_ID,
        inviteId: body.id,
        projectId: built.projectId,
        linkPubHex: body.linkPubHex,
        headHashHex: body.headHashHex,
        headSeq: body.headSeq,
        role: "reader",
        inviterUserId: inviter.userId,
        inviterEncPubHex: inviter.encPubHex,
        inviterSigPubHex: inviter.sigPubHex,
        scopeKind: "listed",
        scopeEnvironmentIds: ["env-dev", "env-staging"],
      },
      signatureHex: body.issueSignatureHex,
    });
    expect(verified.ok).toBe(true);
    const shown = env.logs.find((line) => line.startsWith(`${server.origin}/invite#v=2&`));
    const parsed = parseInviteAcceptInput(Redacted.make(shown ?? ""));
    if (parsed.kind !== "link") throw new Error("link did not parse");
    expect(parsed.link.scopeKind).toBe("listed");
    expect(parsed.link.scopeEnvironmentIds).toEqual(["env-dev", "env-staging"]);
    const pins = await readPins(env, built.projectId);
    const pin = (pins["issued"] as Record<string, Record<string, unknown>>)[body.id];
    expect(pin?.["scopeKind"]).toBe("listed");
    expect(pin?.["scopeEnvironmentIds"]).toEqual(["env-dev", "env-staging"]);
    expect(env.errors.join("\n")).toContain("scope=env-dev, env-staging");

    // A duplicate flag is usage (2). An environment absent from the chain is refused before communication (the unknown-environment pre-check)
    const dup = await makeTestEnv();
    seedSession(dup, server.origin, inviter);
    await seedConfig(dup, { server: server.origin, defaultProject: built.projectId });
    expect(
      await runCli(
        ["invite", "create", "--role", "reader", "--env", "env-dev", "--env", "env-dev"],
        dup.layer,
      ),
    ).toBe(2);
    expect(dup.errors.join("\n")).toContain("--env lists the same environment more than once");
    const unknown = await makeTestEnv();
    seedSession(unknown, server.origin, inviter);
    await seedConfig(unknown, { server: server.origin, defaultProject: built.projectId });
    expect(
      await runCli(["invite", "create", "--role", "reader", "--env", "env-prod"], unknown.layer),
    ).toBe(1);
    expect(unknown.errors.join("\n")).toContain("does not exist on this project's chain");
    expect(issued).toHaveLength(1);
  });

  it("a listed admin cannot issue an invite outside their own scope or for all (the scope-not-contained pre-check — ruling K4-G)", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const devAdmin = await makeTestUser("user-devadmin-44");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp("env-dev", dek) },
      { actor: inviter, operation: createEnvironmentOp("env-prod", dek) },
      { actor: inviter, operation: addScopedMemberOp(devAdmin, "admin", ["env-dev"]) },
    ]);
    const issued: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issued.push(b)),
    ]);
    const run = async (argv: readonly string[]) => {
      const env = await makeTestEnv();
      seedSession(env, server.origin, devAdmin);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
      return { code: await runCli([...argv], env.layer), errors: env.errors.join("\n") };
    };
    const prod = await run(["invite", "create", "--role", "reader", "--env", "env-prod"]);
    expect(prod.code).toBe(1);
    expect(prod.errors).toContain("does not contain the invite's scope");
    // Omitted = all is not contained for a listed admin (all is U, including future environments)
    const all = await run(["invite", "create", "--role", "reader"]);
    expect(all.code).toBe(1);
    expect(all.errors).toContain("does not contain the invite's scope");
    expect(issued).toHaveLength(0);
    // Issuance is allowed within one's own scope
    const dev = await run(["invite", "create", "--role", "reader", "--env", "env-dev"]);
    expect(dev.code).toBe(0);
    expect(issued).toHaveLength(1);
    expect(issued[0]?.scopeEnvironmentIds).toEqual(["env-dev"]);
  });

  it("--no-envs issues with listed{} (zero environments — §6.2's empty listed), exclusive with --env / omission", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp("env-dev", new Uint8Array(32)) },
    ]);
    const issued: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issued.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "reader", "--no-envs"], env.layer)).toBe(0);
    expect(issued).toHaveLength(1);
    expect(issued[0]?.scopeKind).toBe("listed");
    expect(issued[0]?.scopeEnvironmentIds).toEqual([]);
    expect(env.errors.join("\n")).toContain("scope=no environments");

    const mixed = await makeTestEnv();
    seedSession(mixed, server.origin, inviter);
    await seedConfig(mixed, { server: server.origin, defaultProject: built.projectId });
    expect(
      await runCli(
        ["invite", "create", "--role", "reader", "--no-envs", "--env", "env-dev"],
        mixed.layer,
      ),
    ).toBe(2);
    expect(issued).toHaveLength(1);
  });

  it("does not issue when the local device key differs from one's own key on the chain (never produces an unverifiable issuance text)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    // The same user_id with a different key (the shape of regenerating on another device)
    const otherKeys = await makeTestUser(inviter.userId);
    const issueCalls: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issueCalls.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, otherKeys);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "This machine's key is not one of your registered devices on this project's chain",
    );
    expect(issueCalls).toHaveLength(0);
  });

  it("refuses issuance itself in an agent environment (the seed would remain in the transcript)", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issueCalls: IssueBody[] = [];
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, (b) => issueCalls.push(b)),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the invite was not issued");
    // Refuses before the issuance POST (no pending is created server-side)
    expect(issueCalls).toHaveLength(0);
  });

  it("refuses before issuance when any of stdin / stdout / stderr is non-TTY", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    for (const terminal of [
      { stdin: false, stdout: true, stderr: true },
      { stdin: true, stdout: false, stderr: true },
      { stdin: true, stdout: true, stderr: false },
    ]) {
      const issueCalls: IssueBody[] = [];
      const server = await start([
        chainHandler(built),
        issueHandler(built.projectId, (b) => issueCalls.push(b)),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, inviter);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
      env.setTerminal(terminal);

      expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("stdin, stdout, and stderr must all be terminals");
      expect(issueCalls).toHaveLength(0);
      expect(env.logs.some((line) => line.includes("#v=2&"))).toBe(false);
    }
  });

  it("issuance still succeeds when saving the issuance pin fails (corrupt pins file); the link is displayed with a warning", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      issueHandler(built.projectId, () => undefined),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // A corrupt pins file (merge refuses to overwrite — the pins.ts rule)
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${built.projectId}.json`), "{ broken");

    // The link is displayed exactly once: a pin-save failure must not fail the already-succeeded issuance
    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("/invite#v=2&i=");
    expect(env.errors.join("\n")).toContain("could not save the issuance pin");
    // The corrupt file is not overwritten (preserving detectability)
    expect(await readFile(join(env.pinsDir, `${built.projectId}.json`), "utf8")).toBe("{ broken");
  });

  it("distinguishes 409 (id / link_pub collision) from the two kinds of 429 (pending cap / rate limit) in the display", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    for (const [status, json, fragment] of [
      [
        409,
        { _tag: "InviteConflict", field: "linkPub" },
        "already has an invite with the same id or link key",
      ],
      [429, { _tag: "InvitePendingLimit", limit: 100 }, "reached the limit (100)"],
      [429, { _tag: "InviteRateLimited", retryAfterSeconds: 1800 }, "about 1800 seconds"],
    ] as const) {
      const server = await start([
        chainHandler(built),
        onRequest("POST", `/projects/${built.projectId}/invites`, () => ({ status, json })),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, inviter);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
      expect(await runCli(["invite", "create", "--role", "reader"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });
});

describe("maruhi invite accept", () => {
  const PROJECT_ID = "ab".repeat(32);
  const HEAD_HASH = "cd".repeat(32);

  async function issuedFor(
    role: "reader" | "member" | "admin" = "member",
  ): Promise<IssuedInviteFixture> {
    return issueInviteFixture({
      inviter,
      projectId: PROJECT_ID,
      headHashHex: HEAD_HASH,
      headSeq: 3,
      role,
    });
  }

  async function linkFor(role: "reader" | "member" | "admin" = "member"): Promise<string> {
    return inviteLinkText("https://maruhi.example", await issuedFor(role));
  }

  function acceptHandler(record: (body: AcceptBody) => void, role = "member"): MockHandler {
    return onRequest("POST", "/invites/accept", (request) => {
      record(request.body as AcceptBody);
      return {
        status: 200,
        json: {
          id: INVITE_ID,
          projectId: PROJECT_ID,
          role,
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      };
    });
  }

  /** Independently verifies both signatures on the acceptance POST body per §6.5. */
  async function verifyBody(body: AcceptBody, linkPubHex: string): Promise<void> {
    const context = {
      suite: SUITE_ID,
      projectId: PROJECT_ID,
      linkPubHex,
      inviteeUserId: acceptor.userId,
      inviteeEncPubHex: body.encPubHex,
      inviteeSigPubHex: body.sigPubHex,
    };
    expect(body.linkPubHex).toBe(linkPubHex);
    const accept = await verifyInviteAcceptSignature({
      context,
      signatureHex: body.acceptSignatureHex,
    });
    const link = await verifyInviteLinkSignature({
      context,
      linkSignatureHex: body.linkSignatureHex,
    });
    expect(accept.ok).toBe(true);
    expect(link.ok).toBe(true);
  }

  it("issuance-signature verification → ceremony (last-word re-entry) → co-sign → accept. Pins the anchor and displays own FP words", async () => {
    const issued = await issuedFor();
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(
      await runCli(["invite", "accept", inviteLinkText(server.origin, issued)], env.layer),
    ).toBe(0);

    // The acceptance / link signatures verify per §6.5 (bound to project /
    // link_pub / the parties / the declared keys). The seed is never sent to the server
    expect(bodies).toHaveLength(1);
    const body = bodies[0];
    if (body === undefined) throw new Error("no accept body");
    expect(body.encPubHex).toBe(acceptor.encPubHex);
    expect(body.sigPubHex).toBe(acceptor.sigPubHex);
    expect(JSON.stringify(body)).not.toContain(LINK_SEED_HEX);
    await verifyBody(body, issued.linkPubHex);

    // Pinning the anchor (§6.3 (a)) (unmatched = verifiedAtSeq null; also keeps the inviter's sig key)
    const pins = await readPins(env, PROJECT_ID);
    expect(pins["anchor"]).toEqual({
      headSeq: 3,
      headHashHex: HEAD_HASH,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });

    const logs = env.logs.join("\n");
    expect(logs).toContain("Accepted the invite");
    expect(logs).toContain(`  hex:  ${inviter.fingerprintHex}`);
    expect(logs).toContain("read these 12 words to them out of band");
    expect(logs).toContain(
      "the link anchor (genesis, head, inviter key) is machine-checked automatically",
    );
  });

  it("rejects a link whose issuance signature cannot be verified before the ceremony (tampering / ghost inviter)", async () => {
    const issued = await issuedFor();
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    for (const tampered of [
      // tampering with the signature itself
      inviteLinkText(server.origin, {
        ...issued,
        link: { ...issued.link, issueSignatureHex: flipHex(issued.link.issueSignatureHex) },
      }),
      // tampering with the signed target (role)
      inviteLinkText(server.origin, { ...issued, link: { ...issued.link, role: "admin" } }),
      // seed substitution (link_pub does not match the issuance text)
      inviteLinkText(server.origin, {
        ...issued,
        link: { ...issued.link, linkSeedHex: Redacted.make("d8".repeat(32)) },
      }),
    ]) {
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", tampered], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(
        "issue signature does not verify under the inviter key it names",
      );
      expect(env.prompts).toHaveLength(0);
    }
    expect(bodies).toHaveLength(0);
  });

  it("does not accept when the ceremony re-entry mismatches 3 times", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses(["wrong1", "wrong2", "wrong3"]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Inviter fingerprint confirmation failed");
    expect(bodies).toHaveLength(0);
  });

  it("--inviter-fingerprint is matched against the FP derived from the link's ie/is — a match accepts without interaction, a mismatch refuses before acceptance", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(0);
    expect(env.prompts).toHaveLength(0);
    expect(bodies).toHaveLength(1);

    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, acceptor);
    await seedConfig(env2, { server: server.origin });
    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", "0".repeat(32)],
        env2.layer,
      ),
    ).toBe(1);
    expect(env2.errors.join("\n")).toContain(
      "--inviter-fingerprint does not match the inviter fingerprint derived from the link (ie= / is=)",
    );
    expect(bodies).toHaveLength(1);
  });

  it("an agent environment refuses to stand in for the ceremony without --inviter-fingerprint", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the inviter-fingerprint confirmation ceremony",
    );
    expect(bodies).toHaveLength(0);

    // An explicit flag allows acceptance (the line drawn: never stand in for the ceremony's out-of-band match)
    env.errors.length = 0;
    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(0);
    expect(bodies).toHaveLength(1);
  });

  it("fingerprint book: a ceremony success records the inviter's fingerprint; the next acceptance from the same inviter passes with a yes confirmation only (KF)", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    // Run 1: the ceremony (last-word re-entry) → the success is recorded to the book
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    const json = await readFile(env.fingerprintBookPath, "utf8");
    const stored = JSON.parse(json) as {
      known: Record<string, Record<string, { fingerprints: Record<string, unknown> }>>;
    };
    expect(Object.keys(stored.known[server.origin]?.[inviter.userId]?.fingerprints ?? {})).toEqual([
      inviter.fingerprintHex,
    ]);
    expect(env.errors.join("\n")).toContain("recorded the verified fingerprint");

    // Run 2 (equivalent to another invite from the same inviter): a book hit
    // exempts the 12-word read-out re-run, but the explicit confirmation (yes)
    // of the acceptance itself remains. The two read-out-match instruction lines are not printed on a hit (no exemption note right after the instruction)
    const logsBeforeSecondRun = env.logs.length;
    env.setPromptResponses(["yes"]);
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(2);
    expect(env.prompts[1]).toContain("Type yes to accept this invite attributed to");
    const secondRunLogs = env.logs.slice(logsBeforeSecondRun).join("\n");
    expect(secondRunLogs).toContain("not required again");
    expect(secondRunLogs).not.toContain("reads to you out of band");
    expect(bodies).toHaveLength(2);

    // Run 3 (agent environment): a book hit does not allow standing in (the flag
    // is required — pinned symmetrically with the member-add side)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.prompts).toHaveLength(2);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the inviter-fingerprint confirmation ceremony",
    );
    expect(bodies).toHaveLength(2);

    // Run 4 (non-interactive — stdin is a pipe): a book hit does not advance to
    // the yes confirmation; it returns to the full ceremony (last-word re-entry)
    // — a blind `printf yes |` cannot pass (the primary boundary is the terminal)
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(3);
    expect(env.prompts[2]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");
    expect(bodies).toHaveLength(3);
  });

  it("no key yet: interactive confirmation → generation → recovery ceremony → accept with the generated key (the §15-3 chaining)", async () => {
    const issued = await issuedFor();
    const bodies: AcceptBody[] = [];
    const server = await start([
      acceptHandler((body) => bodies.push(body)),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: false, updatedAtMs: null },
      })),
      onRequest("PUT", "/auth/recovery", () => ({ status: 204 })),
    ]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([
      inviterWords[inviterWords.length - 1] ?? "",
      "yes",
      // Recovery-code save verification (reads the last group from the displayed stderr)
      () => {
        const line = env.errors.find((item) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4})+$/.test(item));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);

    expect(
      await runCli(["invite", "accept", inviteLinkText(server.origin, issued)], env.layer),
    ).toBe(0);
    expect(bodies).toHaveLength(1);
    const body = bodies[0];
    if (body === undefined) throw new Error("no accept body");
    // The self-bound signature with the generated key passes verification (declared key = verification key)
    await verifyBody(body, issued.linkPubHex);
    expect(env.logs.join("\n")).toContain("Generated this device's key");
  });

  it("no-key guard: if recovery is already registered, guides to key recover instead of generating", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([
      acceptHandler((body) => bodies.push(body)),
      onRequest("GET", "/auth/recovery/status", () => ({
        status: 200,
        json: { registered: true, updatedAtMs: 1754006400000 },
      })),
    ]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "add this machine as a device instead (`maruhi device add` here, `maruhi device approve` on a device you have), or `maruhi key recover` if no device of yours is left, then re-run",
    );
    expect(bodies).toHaveLength(0);
    // No key was generated (the keychain holds only the token entry)
    expect(env.keychain.size).toBe(1);
  });

  it("no-key guard: does not generate in an agent environment (refuses the acceptance itself and guides)", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedTokenOnly(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setAgent({ isAgent: true, name: "test-agent" });

    expect(
      await runCli(
        ["invite", "accept", await linkFor(), "--inviter-fingerprint", inviter.fingerprintHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Key generation is not performed in AI agent environments",
    );
    expect(bodies).toHaveLength(0);
    expect(env.keychain.size).toBe(1);
  });

  it("raw-token / old-version (v=1) links are a usage error (2) that guides toward re-issuance (no compatibility path)", async () => {
    const bodies: AcceptBody[] = [];
    const server = await start([acceptHandler((body) => bodies.push(body))]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });

    expect(
      await runCli(
        ["invite", "accept", "maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify an invite link (…/invite#v=2&…)");

    env.errors.length = 0;
    expect(
      await runCli(
        ["invite", "accept", `${server.origin}/invite#v=1&t=maruhi_inv_x&p=${PROJECT_ID}`],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("Ask the inviter to issue a new link");
    expect(bodies).toHaveLength(0);
    expect(env.prompts).toHaveLength(0);
  });

  describe("the identity-backing source (IV2 — fulfillment shape 4)", () => {
    async function backedLink(origin: string): Promise<string> {
      const issued = await issueInviteFixture({
        inviter,
        projectId: PROJECT_ID,
        headHashHex: HEAD_HASH,
        headSeq: 3,
        inviterLogin: "alice",
      });
      return inviteLinkText(origin, issued);
    }

    async function backedEnv(
      registeredKeys: readonly string[],
      status = 200,
    ): Promise<{ env: TestEnv; bodies: AcceptBody[]; origin: string }> {
      const bodies: AcceptBody[] = [];
      const server = await start([
        acceptHandler((body) => bodies.push(body)),
        githubSigningKeysHandler("alice", registeredKeys, status),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setVendorOrigin("api.github.com", server.origin);
      return { env, bodies, origin: server.origin };
    }

    it("accepts without interaction on an --from match when is= is registered under il='s signing key, and the completion display guides registration", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      expect(
        await runCli(["invite", "accept", await backedLink(origin), "--from", "alice"], env.layer),
      ).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(bodies).toHaveLength(1);
      const logs = env.logs.join("\n");
      expect(logs).toContain("Inviter key verified");
      expect(logs).toContain("--from matches the link's inviter login");
      expect(logs).not.toContain("reads to you out of band");
      expect(logs).toContain(
        "Register this key on GitHub as a signing key with `maruhi key publish`",
      );
    });

    it("in interaction, a yes that names the login suffices for acceptance (no 12-word read-out needed)", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      env.setPromptResponses(["yes"]);
      expect(await runCli(["invite", "accept", await backedLink(origin)], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(1);
      expect(env.prompts[0]).toContain("Type yes to accept this invite from github.com/alice");
      expect(bodies).toHaveLength(1);

      // Anything but yes is not accepted
      const second = await backedEnv([sshLineOf(inviter)]);
      second.env.setPromptResponses(["no"]);
      expect(
        await runCli(["invite", "accept", await backedLink(second.origin)], second.env.layer),
      ).toBe(1);
      expect(second.env.errors.join("\n")).toContain("The acceptance was cancelled");
      expect(second.bodies).toHaveLength(0);
    });

    it("rejects an --from / il= mismatch (a substituted, still-valid link belonging to someone else)", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      expect(
        await runCli(
          ["invite", "accept", await backedLink(origin), "--from", "mallory"],
          env.layer,
        ),
      ).toBe(1);
      expect(env.errors.join("\n")).toContain("The link may have been swapped");
      expect(bodies).toHaveLength(0);
    });

    it("unregistered / unreachable listings return to the ceremony (with a note). An agent environment refuses without --from and passes with it", async () => {
      // Unregistered (only other keys are listed)
      const { env, bodies, origin } = await backedEnv([sshLineOf(acceptor)]);
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", await backedLink(origin)], env.layer)).toBe(0);
      expect(env.errors.join("\n")).toContain(
        "not registered as a signing key on github.com/alice — falling back to the inviter fingerprint confirmation",
      );
      expect(env.prompts[0]).toContain("type the last of the 12 words");
      expect(bodies).toHaveLength(1);

      // Unreachable (cap)
      const limited = await backedEnv([], 403);
      limited.env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(
        await runCli(["invite", "accept", await backedLink(limited.origin)], limited.env.layer),
      ).toBe(0);
      expect(limited.env.errors.join("\n")).toContain("could not be fetched");
      expect(limited.bodies).toHaveLength(1);

      // Agent environment: even when registered, yes is never stood in for — only an explicit --from is the path
      const agent = await backedEnv([sshLineOf(inviter)]);
      agent.env.setAgent({ isAgent: true, name: "test-agent" });
      expect(
        await runCli(["invite", "accept", await backedLink(agent.origin)], agent.env.layer),
      ).toBe(1);
      expect(agent.env.errors.join("\n")).toContain("Re-run with --from alice");
      expect(agent.bodies).toHaveLength(0);
      expect(
        await runCli(
          ["invite", "accept", await backedLink(agent.origin), "--from", "alice"],
          agent.env.layer,
        ),
      ).toBe(0);
      expect(agent.bodies).toHaveLength(1);
    });

    it("with identityBacking = none, --from is not matched and it returns to the ceremony", async () => {
      const { env, bodies, origin } = await backedEnv([sshLineOf(inviter)]);
      await seedConfig(env, { server: origin, identityBacking: "none" });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(
        await runCli(["invite", "accept", await backedLink(origin), "--from", "alice"], env.layer),
      ).toBe(0);
      expect(env.errors.join("\n")).toContain(
        "identityBacking is none, so --from cannot be checked",
      );
      expect(bodies).toHaveLength(1);
    });
  });

  it("translates the reasons of 404 / 410 / 422 into operational steps (first-come acceptance = interception surfacing)", async () => {
    for (const [status, json, fragment] of [
      [404, { _tag: "InviteNotFound" }, "does not know this invite link's key"],
      [410, { _tag: "InviteGone", reason: "accepted" }, "the link may have been intercepted"],
      [410, { _tag: "InviteGone", reason: "expired" }, "This invite has expired"],
      [422, { _tag: "InviteSignatureInvalid", which: "link" }, "The link signature was rejected"],
      [
        422,
        { _tag: "InviteSignatureInvalid", which: "accept" },
        "The acceptance signature was rejected",
      ],
    ] as const) {
      const server = await start([onRequest("POST", "/invites/accept", () => ({ status, json }))]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, acceptor);
      await seedConfig(env, { server: server.origin });
      env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
      expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });

  it("does not pin the anchor when acceptance fails (no pins file on 410)", async () => {
    // Pinning before acceptance would let a crafted-link submission carrying a
    // failing acceptance (revoked / fake link) replace an existing anchor (self-DoS / substitution)
    const server = await start([
      onRequest("POST", "/invites/accept", () => ({
        status: 410,
        json: { _tag: "InviteGone", reason: "expired" },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(1);
    await expect(readPins(env, PROJECT_ID)).rejects.toThrow(); // no pins file
  });

  it("a machine-matched anchor is not overwritten by re-acceptance; an unmatched anchor is replaced by the latest acceptance", async () => {
    const verifiedAnchor = {
      headSeq: 9,
      headHashHex: "12".repeat(32),
      inviterUserId: "user-original-77",
      inviterKeyFingerprintHex: "34".repeat(16),
      inviterSigPubHex: "56".repeat(32),
      verifiedAtSeq: 9,
    };
    const server = await start([acceptHandler(() => undefined)]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(
      join(env.pinsDir, `${PROJECT_ID}.json`),
      JSON.stringify({ v: 1, anchor: verifiedAnchor, issued: {} }),
    );
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect((await readPins(env, PROJECT_ID))["anchor"]).toEqual(verifiedAnchor);
    expect(env.logs.join("\n")).toContain("keeping the existing anchor");

    // For an unmatched anchor (verifiedAtSeq: null), the last proper acceptance wins
    const env2 = await makeTestEnv();
    seedSession(env2, server.origin, acceptor);
    await seedConfig(env2, { server: server.origin });
    await mkdir(env2.pinsDir, { recursive: true });
    await writeFile(
      join(env2.pinsDir, `${PROJECT_ID}.json`),
      JSON.stringify({ v: 1, anchor: { ...verifiedAnchor, verifiedAtSeq: null }, issued: {} }),
    );
    env2.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", await linkFor()], env2.layer)).toBe(0);
    expect((await readPins(env2, PROJECT_ID))["anchor"]).toEqual({
      headSeq: 3,
      headHashHex: HEAD_HASH,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      inviterSigPubHex: inviter.sigPubHex,
      verifiedAtSeq: null,
    });
    // Replacement leaves a trace (substitution via a fake link = auditability of the DoS path)
    expect(env2.logs.join("\n")).toContain(
      "Replacing the unverified existing anchor with this acceptance's link anchor",
    );
  });

  it("warns while keeping the acceptance successful on a corrupt pins file, and does not overwrite the corrupt file", async () => {
    // The acceptance already succeeded server-side (the link is consumed) —
    // treating a pin failure as a failure would misguide: the "re-run" path leads to 410 (accepted)
    const server = await start([acceptHandler(() => undefined)]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${PROJECT_ID}.json`), "{ broken");
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);

    expect(await runCli(["invite", "accept", await linkFor()], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("could not pin the invite link anchor");
    expect(await readFile(join(env.pinsDir, `${PROJECT_ID}.json`), "utf8")).toBe("{ broken");
    // The completion report does not contradict the warning: it makes no machine-match promise and guides the degradation
    const logs = env.logs.join("\n");
    expect(logs).not.toContain(
      "the link anchor (genesis, head, inviter key) is machine-checked automatically",
    );
    expect(logs).toContain("the first-sync machine check will not run");
  });

  it("rejects a mismatch between the signed link's r / p and the response (server self-contradiction / row substitution)", async () => {
    // A link signed r=admin, the response's role is member → refuse (contradicts the issuance signature)
    const server = await start([acceptHandler(() => undefined, "member")]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, acceptor);
    await seedConfig(env, { server: server.origin });
    env.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor("admin")], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The role declared in the signed link (admin) does not match the role the server reports (member)",
    );

    // The response's projectId differs from the signed target = server self-contradiction → refuse
    const server2 = await start([
      onRequest("POST", "/invites/accept", () => ({
        status: 200,
        json: {
          id: INVITE_ID,
          projectId: "ff".repeat(32),
          role: "member",
          scopeKind: "all",
          scopeEnvironmentIds: [],
        },
      })),
    ]);
    const env2 = await makeTestEnv();
    seedSession(env2, server2.origin, acceptor);
    await seedConfig(env2, { server: server2.origin });
    env2.setPromptResponses([inviterWords[inviterWords.length - 1] ?? ""]);
    expect(await runCli(["invite", "accept", await linkFor()], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("the server's response contradicts itself");
  });
});

describe("maruhi invite list / revoke", () => {
  async function issuedFor(
    built: { readonly projectId: string; readonly hashes: readonly string[] },
    role: "reader" | "member" | "admin" = "member",
  ): Promise<IssuedInviteFixture> {
    return issueInviteFixture({
      inviter,
      projectId: built.projectId,
      headHashHex: built.hashes[built.hashes.length - 1] ?? "",
      headSeq: built.hashes.length,
      role,
    });
  }

  function listRow(
    projectId: string,
    issued: IssuedInviteFixture,
    acceptance: unknown,
    role = "member",
  ): unknown {
    return {
      id: INVITE_ID,
      projectId,
      role,
      scopeKind: "all",
      scopeEnvironmentIds: [],
      status: acceptance === null ? "pending" : "accepted",
      inviterUserId: inviter.userId,
      issuance: issued.issuance,
      createdAtMs: 1755200000000,
      expiresAtMs: 1755993600000,
      acceptance,
    };
  }

  it("§6.5-independently verifies the issuance text and acceptance block, and displays the acceptance key's FP words", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued = await issuedFor(built);
    const acceptance = await acceptanceFixture({
      projectId: built.projectId,
      issued,
      invitee: acceptor,
    });
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, issued, acceptance)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("issuance: signature verified against the inviter's chain key");
    expect(logs).toContain(
      `accepted: ${acceptor.userId} (acceptance and link signatures verified)`,
    );
    expect(logs).toContain(`fp:   ${acceptor.fingerprintHex}`);
  });

  it("warns on tampered issuance / acceptance / link signatures as verification failures and exits 1", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued = await issuedFor(built);
    const acceptance = await acceptanceFixture({
      projectId: built.projectId,
      issued,
      invitee: acceptor,
    });
    for (const [row, fragment] of [
      // role tampering in the issuance text (covered by the issuance signature)
      [
        listRow(built.projectId, issued, acceptance, "admin"),
        "issue signature that does not verify",
      ],
      // reassignment to another user_id (breaks both signatures' invitee_user_id binding — the link signature is reported first)
      [
        listRow(built.projectId, issued, { ...acceptance, inviteeUserId: "user-attacker-99" }),
        "the link signature failed verification",
      ],
      // tampering of the acceptance signature only
      [
        listRow(built.projectId, issued, {
          ...acceptance,
          signatureHex: flipHex(acceptance.signatureHex),
        }),
        "the acceptance signature failed verification",
      ],
    ] as const) {
      const server = await start([
        chainHandler(built),
        onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
          status: 200,
          json: { invitations: [row] },
        })),
      ]);
      const env = await makeTestEnv();
      seedSession(env, server.origin, inviter);
      await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

      expect(await runCli(["invite", "list"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain(fragment);
    }
  });

  it("warns on a mismatch between the issuance pin and the server's declaration (link_pub) and exits 1", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const issued = await issuedFor(built);
    const server = await start([
      chainHandler(built),
      onRequest("GET", `/projects/${built.projectId}/invites`, () => ({
        status: 200,
        json: { invitations: [listRow(built.projectId, issued, null)] },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // Prepare a local issuance-time pin (a different link key) — the shape where the server's row was substituted
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(
      join(env.pinsDir, `${built.projectId}.json`),
      JSON.stringify({
        v: 1,
        anchor: null,
        issued: {
          [INVITE_ID]: {
            linkPubHex: "ee".repeat(32),
            role: "member",
            expiresAtMs: 1755993600000,
            expectedGithubLogin: null,
          },
        },
      }),
    );

    expect(await runCli(["invite", "list"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the local record from issuance");
  });

  it("revoke: successful revocation, and a 410 against completed, guides to member remove", async () => {
    const built = await buildChain([{ actor: inviter, operation: genesisOp(inviter) }]);
    const server = await start([
      chainHandler(built),
      onRequest("DELETE", `/projects/${built.projectId}/invites/${INVITE_ID}`, () => ({
        status: 204,
      })),
      onRequest("DELETE", `/projects/${built.projectId}/invites/inv-0002`, () => ({
        status: 410,
        json: { _tag: "InviteGone", reason: "completed" },
      })),
    ]);
    const env = await makeTestEnv();
    seedSession(env, server.origin, inviter);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["invite", "revoke", INVITE_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Revoked the invite");

    expect(await runCli(["invite", "revoke", "inv-0002"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("run `maruhi member remove`");
  });
});
