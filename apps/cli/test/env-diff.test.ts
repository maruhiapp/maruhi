// 環境間パリティチェック(`maruhi env diff`)のテスト。
//
// 固定する不変条件:
//  1. **値を取得しない**: 叩くのは §12-7 のメタデータのみ pull だけで、値 pull
//     (`/pull`)と DEK 配布(`/deks`)には 1 度も触れない(サーバーは
//     `var.read` を記録しない — AUDIT_SPEC §3.3)
//  2. 差分の内容と件数、および**名前でソートされた安定な出力順**
//     (ワイヤの並びを変えても出力が変わらない)
//  3. 変数名は他メンバーが書いた平文メタデータなので ANSI / BEL / 改行を中和し、
//     視覚的に同名でも正規化形が違えば別物として報告する(NFC / NFD)
//  4. 2 環境ぶんの警告は環境 ID でラベルする(文面まで同一の警告が畳まれて
//     片方の事実が消えない)
//  5. **前段は 1 回だけ**(チェーン同期は 1 回)で、1 つ目の pull が有界再同期で
//     前進させたビューを 2 つ目の pull が引き継ぐ
//  6. 環境水準の床(メタ・マニフェスト・座標 (ii))はコミットするが、値床と
//     規則 (c) の pull 基準は捏造しない(M1-A3 — チェーン床のヘッドは pull ごとに前進)
//  7. 順に読むことによる標本のずれを、**差分の有無によらず** stderr で開示する
//     (差分ゼロこそ、ずれに覆されうる結論)
//  8. **master 鍵を要求しない**(復号しないため。MARUHI_TOKEN 経由のセッションでも動く)
//  9. 書き方の誤り(環境 1 つ・同一環境 ID・他操作専用オプション)は
//     usage エラー(2)で、**通信より前**に落ちる

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { reportEnvironmentDiff, reportEnvironmentWarnings } from "../src/env-diff.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const DEV = "dev";
const PROD = "prod";

let owner: TestUser;
let chain: BuiltChain;
let devStatement: WireDistributedEnvironmentStatement;
let prodStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

/** 床(観測ログの fold)を読む(floor-log.ts の追記専用 JSONL)。 */
async function loadFloor(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(chain.projectId));
  expect(loaded.floor).not.toBeNull();
  return loaded.floor as ProjectFloor;
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  chain = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(DEV, crypto.getRandomValues(new Uint8Array(32))),
    },
    {
      actor: owner,
      operation: createEnvironmentOp(PROD, crypto.getRandomValues(new Uint8Array(32))),
    },
    // 4 つ目: 2 回の pull がそれぞれ有界再同期を起こす形(seq 2 → 3 → 4)を
    // 作るためだけの追加エントリ。diff の対象ではない
    {
      actor: owner,
      operation: createEnvironmentOp("staging", crypto.getRandomValues(new Uint8Array(32))),
    },
  ]);
  devStatement = await environmentStatementOf(DEV);
  prodStatement = await environmentStatementOf(PROD);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function environmentStatementOf(
  environmentId: string,
): Promise<WireDistributedEnvironmentStatement> {
  return environmentStatementFor({
    projectId: chain.projectId,
    environmentId,
    name: environmentId,
    author: owner,
    head: headOf(chain, 1),
  });
}

/** 検証済みステートメント 1 件(宣言ヘッドは既定で genesis)。 */
function variableOf(
  environmentId: string,
  variableId: string,
  name: string,
  headSeq = 1,
): Promise<WireDistributedVariableStatement> {
  return statementFor({
    projectId: chain.projectId,
    environmentId,
    variableId,
    name,
    author: owner,
    head: headOf(chain, headSeq),
  });
}

/**
 * チェーン配布。呼び出しごとに `heads` を進む(最後で止まる)ため、
 * 「同期時点では短いチェーン → 有界再同期で伸びる」形を作れる。接頭辞は
 * 同一ビルドから切り出すので prev_hash 連鎖は正しいまま。
 */
function chainHandlerOf(heads: readonly number[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chain.projectId}/chain`, () => {
    const headSeq = heads[Math.min(call, heads.length - 1)] ?? chain.entries.length;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chain.projectId,
        entries: chain.entries.slice(0, headSeq),
        headSeq,
        headHashHex: chain.hashes[headSeq - 1],
      },
    };
  });
}

/** create_environment の位置(seq)。マニフェストの宣言ヘッドはこれ以降が必要。 */
const CREATED_AT_SEQ: Readonly<Record<string, number>> = { [DEV]: 2, [PROD]: 3 };

/** メタデータのみ pull(§12-7)の応答。値も DEK も運ばない形(マニフェストは同梱)。 */
function pullMetadataHandlerOf(
  environmentId: string,
  statement: WireDistributedEnvironmentStatement,
  variables: readonly WireDistributedVariableStatement[],
): MockHandler {
  // 宣言ヘッドは「環境作成の seq」と「配布ステートメントの最大宣言 seq」の大きい
  // 方: 有界再同期テスト(短いチェーン → 延長)がステートメントの宣言 seq までしか
  // ビューを進めないため、それより先を宣言すると再同期後も future のまま落ちる
  const headSeq = Math.max(
    CREATED_AT_SEQ[environmentId] ?? chain.entries.length,
    ...variables.map((variable) => variable.chainHeadSeq),
  );
  return onRequest(
    "GET",
    `/projects/${chain.projectId}/environments/${environmentId}/pull/metadata`,
    async () => ({
      status: 200,
      json: {
        environmentId,
        currentEpoch: 1,
        statement,
        variables,
        deletedVariables: [],
        manifest: await manifestFor({
          projectId: chain.projectId,
          environmentId,
          epoch: 1,
          issuer: owner,
          head: headOf(chain, headSeq),
          envStatement: statement,
          statements: variables,
        }),
      },
    }),
  );
}

async function startEnv(
  handlers: readonly MockHandler[],
  /** 同期のたびに配布するチェーンの長さ(既定は常に全長)。 */
  chainHeads: readonly number[] = [chain.entries.length],
): Promise<TestEnv & { origin: string }> {
  const server = await MockServer.start([chainHandlerOf(chainHeads), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: chain.projectId });
  return Object.assign(env, { origin: server.origin });
}

/** 直近に起動したモックサーバー(assert 用)。 */
function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/**
 * 値を運ぶ経路へ 1 度も触れていないこと。`/pull/metadata` は値も DEK も
 * 返さないので、末尾一致で値 pull(`/pull`)と区別できる。
 */
function expectNoValueFetches(): void {
  const valuePaths = lastServer()
    .requests.map((request) => request.path)
    .filter((path) => path.endsWith("/pull") || path.endsWith("/deks"));
  expect(valuePaths).toEqual([]);
}

/** 名前だけを与えて 2 環境ぶんのメタデータ pull ハンドラを組む。 */
async function handlersFor(
  devNames: readonly string[],
  prodNames: readonly string[],
): Promise<readonly MockHandler[]> {
  const dev = await Promise.all(
    devNames.map((name, index) => variableOf(DEV, `var-dev-${index}`, name)),
  );
  const prod = await Promise.all(
    prodNames.map((name, index) => variableOf(PROD, `var-prod-${index}`, name)),
  );
  return [
    pullMetadataHandlerOf(DEV, devStatement, dev),
    pullMetadataHandlerOf(PROD, prodStatement, prod),
  ];
}

describe("maruhi env diff", () => {
  it("片方にしか無い変数名を報告し、値の取得経路には触れない", async () => {
    const env = await startEnv(
      await handlersFor(["ZULU", "SHARED_ONE", "ALPHA", "MIKE"], ["PROD_ONLY", "SHARED_ONE"]),
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    // 差分の内容・件数と、名前でソートされた並び
    expect(env.logs).toEqual([
      `Synced and verified: environment ${DEV} = 4 variables / environment ${PROD} = 2 variables`,
      `Variables only in environment ${DEV}: 3`,
      "  ALPHA",
      "  MIKE",
      "  ZULU",
      `Variables only in environment ${PROD}: 1`,
      "  PROD_ONLY",
      "Variables in both: 1 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    ]);
    // 値 pull / DEK 配布は 1 度も叩かない(pullMetadata だけ)
    expectNoValueFetches();
    expect(
      lastServer().requests.filter((request) => request.path.endsWith("/pull/metadata")),
    ).toHaveLength(2);
    // 前段は 1 回だけ = チェーン同期も 1 回だけ(環境ごとに開くと §6.3 検証が
    // 2 度走り、食い違う 2 つの検証済みビューで比較しかねない)
    expect(lastServer().requests.filter((request) => request.path.endsWith("/chain"))).toHaveLength(
      1,
    );
  });

  it("標本のずれは差分の有無によらず注意書きする(stderr。助言だけ結論に合わせる)", async () => {
    // 2 環境は順に読むので、実行中の push は一時的に片側だけに見える = 偽の差分。
    // 真に受けた「修正」は取り消せない push なので、埋める前の再確認を促す
    const drifted = await startEnv(await handlersFor(["ONLY_DEV"], []));
    expect(await runCli(["env", "diff", DEV, PROD], drifted.layer)).toBe(0);
    const driftNotices = drifted.errors.filter((line) =>
      line.includes("read sequentially, not atomically"),
    );
    expect(driftNotices).toHaveLength(1);
    expect(driftNotices[0]).toContain(
      "run this again to confirm before filling them in with a push",
    );
    // 助言は stdout(差分一覧)へ混ぜない
    expect(drifted.logs.some((line) => line.includes("read sequentially, not atomically"))).toBe(
      false,
    );

    // **差分ゼロでも黙らない**: 1 つ目を読んだ後の削除は「両方にある」と報告
    // されて差分ゼロで終わる = 実在する差分の見落としになるため、その結論こそ
    // 覆されうる
    const clean = await startEnv(await handlersFor(["SAME"], ["SAME"]));
    expect(await runCli(["env", "diff", DEV, PROD], clean.layer)).toBe(0);
    const cleanNotices = clean.errors.filter((line) =>
      line.includes("read sequentially, not atomically"),
    );
    expect(cleanNotices).toHaveLength(1);
    expect(cleanNotices[0]).toContain(
      "Before treating zero differences as proof the environments are in sync",
    );
    expect(cleanNotices[0]).not.toContain("before filling them in with a push");
  });

  it("環境 ID も端末中和する(EnvironmentId はブランド付きではない)", async () => {
    // `EnvironmentId` は Schema.String.check の別名で、未検証の string がそのまま
    // 代入できる(型は検証を強制しない)。CLI 側は requireEnvironmentId を通すが、
    // 表示側がその不変条件に寄りかからないことを直接固定する
    const env = await makeTestEnv();
    await Effect.runPromise(
      reportEnvironmentDiff({
        firstEnvironmentId: "\u001b[2Kdev" as EnvironmentId,
        secondEnvironmentId: "prod\u0007" as EnvironmentId,
        onlyInFirst: ["ONLY_DEV"],
        onlyInSecond: [],
        shared: 0,
      }).pipe(Effect.provide(env.layer)),
    );
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    expect(env.logs).toContain("Variables only in environment \uFFFD[2Kdev: 1");
    expect(env.logs).toContain(
      "Synced and verified: environment \uFFFD[2Kdev = 1 variable / environment prod\uFFFD = 0 variables",
    );
  });

  it("警告はラベルの環境 ID も本文も端末中和する", async () => {
    const env = await makeTestEnv();
    await Effect.runPromise(
      // 環境 ID は EnvironmentId 型でも検証済みとは限らず、警告本文も将来の
      // 産出元が中和済みとは限らない — 組み立てた行を丸ごと通す
      reportEnvironmentWarnings("\u001b[2Kprod" as EnvironmentId, [
        "変数 v1\u0007 の名前が not NFC-normalized",
      ]).pipe(Effect.provide(env.layer)),
    );
    expect(env.errors).toEqual([
      "Warning: environment \uFFFD[2Kprod: 変数 v1\uFFFD の名前が not NFC-normalized",
    ]);
  });

  it("環境水準の床はコミットし、値床・規則 (c) の pull 基準は捏造しない(M1-A3)", async () => {
    const env = await startEnv(await handlersFor(["ONLY_DEV"], ["ONLY_PROD"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const floor = await loadFloor(env);
    expect(floor.chainHead).toEqual({
      seq: chain.entries.length,
      hashHex: chain.hashes[chain.entries.length - 1],
    });
    // 検証済みの環境水準観測(メタ・マニフェスト・座標 (ii))は join される
    // (§6.3 の記録規則 — 検証に成功した事実は必ず join する)
    const dev = floor.environments[DEV];
    expect(dev?.metaVersion).toBe(1);
    expect(dev?.manifest).toMatchObject({ manifestVersion: 1 });
    expect(dev?.observedEpoch).toBe(1);
    // 値を読んでいない以上、値床と pull 基準は捏造しない(規則 (c) の規範)
    expect(dev?.pullEpoch).toBe(0);
    expect(dev?.variables).toEqual({});
  });

  it("ワイヤの並びが変わっても出力は変わらない(名前でソートして安定させる)", async () => {
    const forward = await startEnv(await handlersFor(["ALPHA", "MIKE", "ZULU"], ["SHARED"]));
    expect(await runCli(["env", "diff", DEV, PROD], forward.layer)).toBe(0);

    const reversed = await startEnv(await handlersFor(["ZULU", "MIKE", "ALPHA"], ["SHARED"]));
    expect(await runCli(["env", "diff", DEV, PROD], reversed.layer)).toBe(0);

    expect(reversed.logs).toEqual(forward.logs);
    expect(forward.logs).toContain("  ALPHA");
  });

  it("差分が無い環境どうしでも 0 件として報告する(終了コードは 0 のまま)", async () => {
    const env = await startEnv(await handlersFor(["A", "B"], ["B", "A"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toEqual([
      `Synced and verified: environment ${DEV} = 2 variables / environment ${PROD} = 2 variables`,
      `Variables only in environment ${DEV}: 0`,
      `Variables only in environment ${PROD}: 0`,
      "Variables in both: 2 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    ]);
  });

  it("変数名の大文字小文字は区別する(byte-exact 照合 — AUTH_SPEC §12-1)", async () => {
    const env = await startEnv(await handlersFor(["API_KEY"], ["api_key"]));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  API_KEY");
    expect(env.logs).toContain("  api_key");
    expect(env.logs).toContain(
      "Variables in both: 0 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    );
  });

  it("変数名の ANSI / BEL / 改行を中和して表示する", async () => {
    const env = await startEnv(
      await handlersFor(["\u001b[31mEVIL\u0007", "LINE\nBREAK"], ["KEEP"]),
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  \uFFFD[31mEVIL\uFFFD");
    expect(env.logs).toContain("  LINE\uFFFDBREAK");
    // 生の制御文字がどの出力行にも残っていないこと
    expect(env.logs.some((line) => /\p{Cc}/u.test(line))).toBe(false);
  });

  it("視覚的に同名でも正規化形が違えば別の変数として報告する(NFC / NFD)", async () => {
    // 端末上は同じ「CAFÉ」に見えるが、byte-exact では別物。パリティチェックは
    // まさにここで誤解が起きやすいので、一致扱いにせず両側の差分として出し、
    // 非 NFC の側には §12-1 の SHOULD 警告を添える(検出は values.ts のまま)
    const nfc = "CAF\u00C9";
    const nfd = "CAFE\u0301";
    expect(nfd.normalize("NFC")).toBe(nfc);
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, [await variableOf(DEV, "var-dev-0", nfc)]),
      pullMetadataHandlerOf(PROD, prodStatement, [await variableOf(PROD, "var-prod-0", nfd)]),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain(`  ${nfc}`);
    expect(env.logs).toContain(`  ${nfd}`);
    expect(env.logs).toContain(
      "Variables in both: 0 (names match, nothing more — values were neither fetched nor decrypted, so whether the values match was not compared)",
    );
    // 警告が立つのは非 NFC を配布した側だけ
    const warnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: environment ${PROD}: `);
  });

  it("2 環境ぶんの警告は環境 ID でラベルする(同一文面が畳まれて消えない)", async () => {
    // 非 NFC 名(E + 合成アキュート)。同じ variableId・同じ名前を両環境に置くと
    // 警告の文面は完全に一致する — 集合で畳むと片方の事実が黙って消える形
    const nonNfc = "CAFE\u0301";
    const dev = [await variableOf(DEV, "var-nfc", nonNfc)];
    const prod = [await variableOf(PROD, "var-nfc", nonNfc)];
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, dev),
      pullMetadataHandlerOf(PROD, prodStatement, prod),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const warnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain(`Warning: environment ${DEV}: `);
    expect(warnings[1]).toContain(`Warning: environment ${PROD}: `);
  });

  it("1 つ目の pull が前進させたビューを 2 つ目の pull へ渡す", async () => {
    // チェーンは genesis(1)→ create dev(2)→ create prod(3)。同期時点では
    // 2 エントリしか配布されず、prod はまだ自ビューに存在しない
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const prod = [await variableOf(PROD, "var-prod-0", "ONLY_PROD")];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, prod),
      ],
      [2, 3],
    );

    // dev のステートメントは自ビューより先のヘッド(seq 3)へ束縛されているので、
    // 1 つ目の pull が §6.3-2b の有界再同期でビューを 3 エントリへ前進させる。
    // 2 つ目の pull にそのビューを渡さないと、prod は「チェーン上に存在しない」
    // 環境のまま照合され、比較が別々の履歴に対するものになる
    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.errors.some((line) => line.includes("does not exist on the chain"))).toBe(false);
    expect(env.logs).toContain("  ONLY_DEV");
    expect(env.logs).toContain("  ONLY_PROD");
    // 前進したヘッドは床へ残す。openProject 時点(seq 2)のままだと、その間への
    // 巻き戻しを次回以降に検出できない(pull / push は同じヘッドを書いている)
    const floor = await loadFloor(env);
    expect(floor.chainHead).toEqual({ seq: 3, hashHex: chain.hashes[2] });
    // 値を読んでいないので値床は作らない(環境水準の観測のみ — M1-A3)
    expect(floor.environments[DEV]?.pullEpoch).toBe(0);
    expect(floor.environments[DEV]?.variables).toEqual({});
  });

  it("床へ残すのは 2 つ目の pull まで含めた最終ビューのヘッド", async () => {
    // 2 回の pull がそれぞれ有界再同期を起こす: seq 2 →(dev)→ 3 →(prod)→ 4。
    // 1 つ目のビューで止めると、2 つ目が確立した前進を床に残し損ねる
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const prod = [await variableOf(PROD, "var-prod-0", "ONLY_PROD", 4)];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        pullMetadataHandlerOf(PROD, prodStatement, prod),
      ],
      [2, 3, 4],
    );

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    const floor = await loadFloor(env);
    expect(floor.chainHead).toEqual({ seq: 4, hashHex: chain.hashes[3] });
  });

  it("2 つ目の pull が失敗しても、1 つ目が確立した前進は床に残る", async () => {
    // pull / push は応答ごとに床へヘッドを書く。まとめて最後に書くと、
    // 2 つ目が落ちた実行で 1 つ目の有界再同期の成果を捨てることになる
    const dev = [await variableOf(DEV, "var-dev-0", "ONLY_DEV", 3)];
    const env = await startEnv(
      [
        pullMetadataHandlerOf(DEV, devStatement, dev),
        // 2 つ目の環境は取得できない(ネットワーク障害・認可失敗の代表)
        onRequest("GET", `/projects/${chain.projectId}/environments/${PROD}/pull/metadata`, () => ({
          status: 503,
          json: { error: "unavailable" },
        })),
      ],
      [2, 3],
    );

    // 実行そのものは失敗する(1)
    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(1);
    const floor = await loadFloor(env);
    // 1 つ目の pull で seq 3 まで前進したことは記録されている(openProject
    // 時点の seq 2 のままにしない)
    expect(floor.chainHead).toEqual({ seq: 3, hashHex: chain.hashes[2] });
  });

  it("2 つ目の pull が失敗しても、1 つ目で集めた警告は必ず吐く", async () => {
    // 警告を戻り値で持ち回って最後にまとめて出すと、失敗経路で黙って消える
    // (env-rotate が同じ形を明示的に避けている)
    const dev = [await variableOf(DEV, "var-dev-0", "CAFE\u0301")];
    const env = await startEnv([
      pullMetadataHandlerOf(DEV, devStatement, dev),
      onRequest("GET", `/projects/${chain.projectId}/environments/${PROD}/pull/metadata`, () => ({
        status: 503,
        json: { error: "unavailable" },
      })),
    ]);

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(1);
    const warnings = env.errors.filter((line) => line.includes("not NFC-normalized"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: environment ${DEV}: `);
  });

  it("master 鍵が無い端末でも実行できる(復号しないため要求しない)", async () => {
    const env = await startEnv(await handlersFor(["ONLY_DEV"], []));
    // セッションはあるが master 鍵はキーチェーンに無い状態(MARUHI_TOKEN 経由の
    // 実行や、鍵をまだ復元していない端末)
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));

    expect(await runCli(["env", "diff", DEV, PROD], env.layer)).toBe(0);
    expect(env.logs).toContain("  ONLY_DEV");
    expect(env.errors.some((line) => line.includes("No master key"))).toBe(false);
  });

  describe("書き方の誤り(usage エラー = 2)", () => {
    it("環境を 1 つしか書いていない実行を落とす(通信より前)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Missing positional argument other-environment-id",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("同じ環境 ID を 2 つ書いた実行を落とす(指定値は出さない)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, DEV], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: The same environment ID was written twice. Specify two different environments to compare",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("2 つ目の環境 ID にも形式検査を掛ける(指定値は出さない)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, "not a valid id"], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "maruhi: Invalid environment ID (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -. Example: maruhi env diff dev prod)",
      ]);
      expect(env.errors[0]).not.toContain("not a valid id");
      expect(lastServer().requests).toEqual([]);
    });

    it("create 専用の --name を diff で拒否する", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "diff", DEV, PROD, "--name", "x"], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("rotate 専用の --reason / --new-epoch を diff で拒否する", async () => {
      const withReason = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--reason", "x"], withReason.layer)).toBe(2);
      expect(withReason.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);

      const withEpoch = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--new-epoch"], withEpoch.layer)).toBe(2);
      expect(withEpoch.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);
      // 否定形(`--no-new-epoch`)も同じオプションの綴りとして拒否する
      const negated = await startEnv([]);
      expect(await runCli(["env", "diff", DEV, PROD, "--no-new-epoch"], negated.layer)).toBe(2);
      expect(negated.errors).toEqual([
        "Usage: maruhi env diff [flags] <environment-id> <other-environment-id>",
        "maruhi: Unknown flag (flags this command accepts: --server --project --help --version)",
      ]);
    });

    it("diff 専用の 3 つ目の位置引数は create / rotate では余分な引数になる", async () => {
      // create は effect/unstable/cli 側(ADR-0016 の第 1 段階)。入れ子の
      // サブコマンドなので「取る位置引数は environment-id だけ」と言える
      const created = await startEnv([]);
      expect(await runCli(["env", "create", DEV, PROD], created.layer)).toBe(2);
      expect(created.errors.join("\n")).toContain("Unexpected extra arguments (1");
      expect(created.errors.join("\n")).toContain(
        "maruhi env create only takes these positional arguments: environment-id",
      );

      // rotate は gunshi のまま(1 引数表なので 3 つ目は diff 専用として除く)
      const rotated = await startEnv([]);
      expect(await runCli(["env", "rotate", DEV, PROD], rotated.layer)).toBe(2);
      expect(rotated.errors.join("\n")).toContain("Unexpected extra arguments (1");
    });

    it("未知の操作では 3 つ目を除かない(操作名の誤りを先に報告する)", async () => {
      const env = await startEnv([]);

      expect(await runCli(["env", "bogus", DEV, PROD], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env <subcommand> [flags]",
        "maruhi: Unknown subcommand (expected one of: create | rotate | diff)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });

    it("未知の操作 + 空の位置引数は、操作名の誤りを先に報告する(usage エラー = 2)", async () => {
      const env = await startEnv([]);

      // effect/unstable/cli への移行(ADR-0016)後は、サブコマンドの解決が
      // 位置引数の検査より先に走るため、未知の操作がまず報告される
      // (直して再実行すれば空の位置引数の誤りが出る)。終了コードは同じ 2
      expect(await runCli(["env", "bogus", DEV, " "], env.layer)).toBe(2);
      expect(env.errors).toEqual([
        "Usage: maruhi env <subcommand> [flags]",
        "maruhi: Unknown subcommand (expected one of: create | rotate | diff)",
      ]);
      expect(lastServer().requests).toEqual([]);
    });
  });
});
