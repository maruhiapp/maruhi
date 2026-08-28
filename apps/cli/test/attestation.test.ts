// ヘッドゴシップのクライアント面(CRYPTO_SPEC §6.3 / §6.6 — PR-M4)のテスト。
// session-27 §13-5 の申告項: 配布照合の 2 種区別(seq ≤ 自ヘッドの不一致 =
// 即時証拠 / seq > 自ヘッド = 再同期 → 解決)・証拠保存(floor-evidence 様式)・
// 矛盾申告での中断・提出契機(前進時のみ — 前回申告の追跡)。

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { ProjectId } from "@maruhi/core";
import { signHeadAttestation } from "@maruhi/crypto";
import { Effect, Exit, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import {
  reconcileDistributedAttestations,
  submitHeadAttestationIfAdvanced,
} from "../src/attestation.ts";
import type { CliError } from "../src/errors.ts";
import {
  type DistributedAttestationWire,
  verifyChainSnapshot,
  type VerifiedProject,
} from "../src/sync.ts";
import {
  addMemberOp,
  type BuiltChain,
  buildChain,
  genesisOp,
  makeTestUser,
  removeMemberOp,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, type TestEnv } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
let member: TestUser;
let outsider: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  outsider = await makeTestUser("user-outsider-3333");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startServer(handlers: Parameters<typeof MockServer.start>[0]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

/** 検証済みビューを直接組み立てる(照合はネットワーク非依存の純粋検査)。 */
async function verifiedViewOf(
  built: BuiltChain,
  upTo: number,
  attestations: readonly DistributedAttestationWire[],
): Promise<VerifiedProject> {
  return Effect.runPromise(
    verifyChainSnapshot({
      projectId: built.projectId as ProjectId,
      entries: built.entries.slice(0, upTo),
      claimedHeadSeq: upTo,
      claimedHeadHashHex: built.hashes[upTo - 1] ?? "",
      attestations,
    }),
  );
}

/** attester の鍵で §6.6 の申告ワイヤを署名して組む。 */
async function attestationBy(
  attester: TestUser,
  projectId: string,
  head: { readonly seq: number; readonly hashHex: string },
  overrides?: Partial<DistributedAttestationWire>,
): Promise<DistributedAttestationWire> {
  const signed = await signHeadAttestation({
    context: {
      suite: "maruhi/v1",
      projectId,
      attesterUserId: attester.userId,
      chainHeadHashHex: head.hashHex,
      chainHeadSeq: head.seq,
    },
    signingKey: attester.sigKeyPair.privateKey,
  });
  if (!signed.ok) {
    throw new Error("attestation signing failed");
  }
  return {
    suite: "maruhi/v1",
    attesterUserId: attester.userId,
    attesterKeyFingerprintHex: attester.fingerprintHex,
    chainHeadHashHex: head.hashHex,
    chainHeadSeq: head.seq,
    signatureHex: signed.value,
    ...overrides,
  };
}

function runReconcile(
  env: TestEnv,
  input: {
    readonly projectId: string;
    readonly view: VerifiedProject;
    readonly resync?: Effect.Effect<VerifiedProject, CliError>;
  },
) {
  return Effect.runPromiseExit(
    reconcileDistributedAttestations({
      projectId: input.projectId,
      view: input.view,
      resync: input.resync ?? Effect.die(new Error("resync must not be reached in this test")),
    }).pipe(Effect.provide(env.layer)),
  );
}

function failureText(exit: Exit.Exit<unknown, unknown>): string {
  return JSON.stringify(exit);
}

/** genesis → add_member(member)→ remove_member の 3 エントリ標準チェーン。 */
async function buildStandardChain(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: addMemberOp(member, "member") },
    { actor: owner, operation: removeMemberOp(member) },
  ]);
}

describe("reconcileDistributedAttestations(照合 — §6.3 / §6.6)", () => {
  it("一致する申告・検証に失敗する偽申告・非現メンバーの申告を正しく選別する(中断しない)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const head2 = { seq: 2, hashHex: built.hashes[1] ?? "" };
    const matching = await attestationBy(member, built.projectId, head2);
    // 偽署名(1 バイト反転)= 照合材料にしない(警告誘発 DoS の排除)
    const forged = {
      ...matching,
      signatureHex: `${matching.signatureHex.slice(0, -2)}${matching.signatureHex.endsWith("00") ? "01" : "00"}`,
    };
    // 履歴外 attester = 照合材料にしない
    const unknown = await attestationBy(outsider, built.projectId, head2);
    const view = await verifiedViewOf(built, 2, [matching, forged, unknown]);
    const exit = await runReconcile(env, { projectId: built.projectId, view });
    expect(Exit.isSuccess(exit), failureText(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value).toBe(view);
    }
    expect(env.errors).toEqual([]);
  });

  it("削除済みメンバーの在籍中ヘッドへの過去申告は照合材料にしない(§6.6 (1) の現メンバー検査)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    // member は seq 3 で削除済み。在籍区間内(seq 2)への申告は §6.6 検証を
    // 通る形だが、現メンバーでないため配布されても照合材料にしない
    const inTenure = await attestationBy(member, built.projectId, {
      seq: 2,
      hashHex: built.hashes[1] ?? "",
    });
    const view = await verifiedViewOf(built, 3, [inTenure]);
    const exit = await runReconcile(env, { projectId: built.projectId, view });
    expect(Exit.isSuccess(exit), failureText(exit)).toBe(true);
  });

  it("(a) 申告 seq ≤ 自ヘッドでハッシュ不一致 = 硬い証拠: 中断・警告・追記専用の証拠保存", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    // member(現メンバー)の有効署名で、自ビューの seq 2 と異なるヘッドを申告
    // する = split view の交差配布の形
    const forkedHash = "ef".repeat(32);
    const contradicting = await attestationBy(member, built.projectId, {
      seq: 2,
      hashHex: forkedHash,
    });
    const view = await verifiedViewOf(built, 2, [contradicting]);
    const exit = await runReconcile(env, { projectId: built.projectId, view });
    expect(Exit.isFailure(exit)).toBe(true);
    const message = failureText(exit);
    expect(message).toContain("Head-attestation cross-check");
    expect(message).toContain("server equivocation");
    expect(message).toContain(forkedHash);
    // 証拠(申告 + 自ビューのチェーンダイジェスト)が追記専用ファイルに残る
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    const records = evidenceRaw
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      kind: "head-mismatch",
      attestation: {
        attesterUserId: member.userId,
        chainHeadHashHex: forkedHash,
        chainHeadSeq: 2,
        signatureHex: contradicting.signatureHex,
      },
      localView: {
        headSeq: 2,
        headHashHex: built.hashes[1],
        entryHashAtAttestedSeq: built.hashes[1],
      },
    });
  });

  it("(b) 申告 seq > 自ヘッド = 有界再同期で延長として解決すれば正常(前進後のビューを返す)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const head3 = { seq: 3, hashHex: built.hashes[2] ?? "" };
    const ahead = await attestationBy(owner, built.projectId, head3);
    // 自ビューは seq 2 で、申告は seq 3(自分が古いだけ)。再同期は全 3
    // エントリ + 同じ申告集合を返す
    const view = await verifiedViewOf(built, 2, [ahead]);
    const resyncView = await verifiedViewOf(built, 3, [ahead]);
    const exit = await runReconcile(env, {
      projectId: built.projectId,
      view,
      resync: Effect.succeed(resyncView),
    });
    expect(Exit.isSuccess(exit), failureText(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value.state.headSeq).toBe(3);
    }
  });

  it("(b) 再同期しても解決しない申告は (a) と同じ扱い(unresolved-after-resync の証拠。重複排除込み)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    // 自ヘッド(3)より先の seq 5 を申告する — 再同期後も届かない
    const unresolvable = await attestationBy(owner, built.projectId, {
      seq: 5,
      hashHex: "ab".repeat(32),
    });
    const view = await verifiedViewOf(built, 3, [unresolvable]);
    const resyncView = await verifiedViewOf(built, 3, [unresolvable]);
    const exit = await runReconcile(env, {
      projectId: built.projectId,
      view,
      resync: Effect.succeed(resyncView),
    });
    expect(Exit.isFailure(exit)).toBe(true);
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    const records = evidenceRaw.split("\n").filter((line) => line.trim() !== "");
    // 同一申告は「持ち越した future 分」と「再同期ビュー自身の申告集合」の
    // 両方に現れるが、証拠は 1 レコードに重複排除される(2 行あると 2 人の
    // メンバーが矛盾しているように読める — pullfrog レビュー)
    expect(records).toHaveLength(1);
    expect(records[0]).toContain('"kind":"unresolved-after-resync"');
  });

  it("(b) 再同期ビューにハッシュだけ書き換えた同キー偽レコードを混ぜても持ち越し照合は無効化されない", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    // 本物: 自ヘッド(3)より先の seq 5 への申告(再同期後も未解決になる形)
    const genuineHash = "ab".repeat(32);
    const genuine = await attestationBy(owner, built.projectId, {
      seq: 5,
      hashHex: genuineHash,
    });
    // 偽: attesterUserId / chainHeadSeq / signatureHex は本物と同一のまま
    // chainHeadHashHex だけ書き換えたレコード。部分キーの重複排除だと本物の
    // 持ち越し分(first.future)がキー衝突で捨てられ、偽側は署名検証で無言
    // skip されて second.future が空になる = 中断が起きなくなる
    const tampered = { ...genuine, chainHeadHashHex: "cd".repeat(32) };
    const view = await verifiedViewOf(built, 3, [genuine]);
    const resyncView = await verifiedViewOf(built, 3, [tampered]);
    const exit = await runReconcile(env, {
      projectId: built.projectId,
      view,
      resync: Effect.succeed(resyncView),
    });
    expect(Exit.isFailure(exit)).toBe(true);
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    const records = evidenceRaw.split("\n").filter((line) => line.trim() !== "");
    // 本物の申告が unresolved-after-resync の証拠として残る(偽レコードは
    // 署名検証に落ちて照合材料にならない)
    expect(records).toHaveLength(1);
    expect(records[0]).toContain('"kind":"unresolved-after-resync"');
    expect(records[0]).toContain(genuineHash);
  });
});

describe("コマンド前段への接続(project verify — 矛盾申告での中断)", () => {
  async function verifyCommandEnv(
    built: BuiltChain,
    attestations: readonly DistributedAttestationWire[],
  ): Promise<TestEnv> {
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
          attestations,
        },
      })),
    ]);
    const env = await makeTestEnv();
    const { seedConfig, seedSession } = await import("./support/env.ts");
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    return env;
  }

  it("一致する申告の配布下で project verify は成功する", async () => {
    const { runCli } = await import("../src/cli.ts");
    const built = await buildStandardChain();
    const matching = await attestationBy(owner, built.projectId, {
      seq: 3,
      hashHex: built.hashes[2] ?? "",
    });
    const env = await verifyCommandEnv(built, [matching]);
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    // 照合を通過したビューのヘッドは従来どおり床に記録される(前進の位置が
    // 全検査通過後へ移っただけで、成功時の床の材料は落とさない)
    const floorLog = await readFile(join(env.floorDir, `${built.projectId}.jsonl`), "utf8");
    expect(floorLog).toContain('"r":"head"');
  });

  it("矛盾申告の配布下で project verify は中断し、警告と証拠を残す", async () => {
    const { runCli } = await import("../src/cli.ts");
    const built = await buildStandardChain();
    const contradicting = await attestationBy(owner, built.projectId, {
      seq: 2,
      hashHex: "ef".repeat(32),
    });
    const env = await verifyCommandEnv(built, [contradicting]);
    expect(await runCli(["project", "verify"], env.layer)).not.toBe(0);
    const output = env.errors.join("\n");
    expect(output).toContain("Head-attestation cross-check");
    const evidenceRaw = await readFile(
      join(env.floorDir, `${built.projectId}.attestation-evidence.jsonl`),
      "utf8",
    );
    expect(evidenceRaw).toContain('"kind":"head-mismatch"');
    // 中断したビューのヘッドは床に記録されない: 照合前に記録すると、拒否した
    // はずの fork が床の恒久記録になり、以後の正直なチェーンをハッシュ不一致と
    // して拒否させられる(Cursor Security Agent 指摘 — 床前進は全検査通過後)
    const floorLog = await readFile(join(env.floorDir, `${built.projectId}.jsonl`), "utf8").catch(
      () => "",
    );
    expect(floorLog).not.toContain('"r":"head"');
  });
});

describe("submitHeadAttestationIfAdvanced(提出 — SHOULD)", () => {
  async function submissionProgram(
    env: TestEnv,
    origin: string,
    view: VerifiedProject,
    projectId: string,
  ): Promise<void> {
    await Effect.runPromise(
      Effect.gen(function* () {
        const client = yield* makeApiClient({
          baseUrl: origin,
          token: Redacted.make("maruhi_pat_test"),
        });
        yield* submitHeadAttestationIfAdvanced({
          client,
          projectId,
          view,
          attesterUserId: owner.userId,
          signingKey: owner.sigKeyPair.privateKey,
        });
      }).pipe(Effect.provide(env.layer)),
    );
  }

  it("検証済みヘッドが前回申告より前進した時だけ提出し、追跡を更新する", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onRequest("PUT", `/projects/${built.projectId}/head-attestation`, () => ({
        status: 204,
        bodyText: "",
      })),
    ]);
    const view2 = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view2, built.projectId);
    const puts = () =>
      server.requests.filter(
        (request) =>
          request.method === "PUT" &&
          request.path === `/projects/${built.projectId}/head-attestation`,
      );
    expect(puts()).toHaveLength(1);
    expect(puts()[0]?.body).toMatchObject({
      suite: "maruhi/v1",
      chainHeadHashHex: built.hashes[1],
      chainHeadSeq: 2,
    });
    // 前進していない再実行は提出しない(前回申告の追跡 — attested.json)
    await submissionProgram(env, server.origin, view2, built.projectId);
    expect(puts()).toHaveLength(1);
    // ヘッドが前進したら再提出する
    const view3 = await verifiedViewOf(built, 3, []);
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(puts()).toHaveLength(2);
    expect(puts()[1]?.body).toMatchObject({ chainHeadSeq: 3 });
    expect(env.errors).toEqual([]);
    const tracked = JSON.parse(
      await readFile(join(env.floorDir, `${built.projectId}.attested.json`), "utf8"),
    ) as { head: { seq: number } };
    expect(tracked.head.seq).toBe(3);
  });

  it("同一 seq でもハッシュが違えば提出する(seq のみの抑制は equivocation 下で申告経路を閉じる)", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onRequest("PUT", `/projects/${built.projectId}/head-attestation`, () => ({
        status: 204,
        bodyText: "",
      })),
    ]);
    const view3 = await verifiedViewOf(built, 3, []);
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(1);
    // 床破損・初回の fail-open 下で、同一 seq・異ハッシュの別チェーン
    // (equivocation)を見せられた形を模す: 追跡の hash を別値に書き換える。
    // seq は前進していないがハッシュが違うので提出は抑制されない — この端末の
    // 申告経由で他メンバーが分岐を検出する経路を保つ(pullfrog レビュー)
    const { writeFile } = await import("node:fs/promises");
    await writeFile(
      join(env.floorDir, `${built.projectId}.attested.json`),
      `${JSON.stringify({ v: 1, head: { seq: 3, hashHex: "ef".repeat(32) } })}\n`,
    );
    await submissionProgram(env, server.origin, view3, built.projectId);
    expect(server.requests).toHaveLength(2);
  });

  it("提出失敗(旧サーバー = ルート不在)はコマンドを失敗させず警告 1 行に落とす", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([]); // すべて 404(申告 PUT 未実装の旧サーバー)
    const view = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view, built.projectId);
    expect(env.errors.some((line) => line.includes("could not submit the head attestation"))).toBe(
      true,
    );
    // 提出できていないので追跡は前進しない(次回また試みる)
    await expect(
      readFile(join(env.floorDir, `${built.projectId}.attested.json`), "utf8"),
    ).rejects.toThrow();
  });

  it("409(AttestationRegression)は床破損・並行 CLI の徴候として区別して警告する", async () => {
    const env = await makeTestEnv();
    const built = await buildStandardChain();
    const server = await startServer([
      onRequest("PUT", `/projects/${built.projectId}/head-attestation`, () => ({
        status: 409,
        json: { _tag: "AttestationRegression", storedSeq: 9 },
      })),
    ]);
    const view = await verifiedViewOf(built, 2, []);
    await submissionProgram(env, server.origin, view, built.projectId);
    expect(
      env.errors.some((line) => line.includes("rejected this head attestation as a regression")),
    ).toBe(true);
  });
});
