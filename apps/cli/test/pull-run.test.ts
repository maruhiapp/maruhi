// pull(§5.1 配布時検証 + §12-7 全エポック DEK)と run(メモリ注入)、
// AI エージェント検出の線引き(値表示は拒否 / run は許可)のテスト。

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";

interface Fixture {
  readonly owner: TestUser;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly wraps: readonly WireRecipientDek[];
  readonly valueAlpha: WireDistributedValue;
  readonly valueBeta: WireDistributedValue;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entryAlpha: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  };
  readonly entryBeta: {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  };
}

let fixture: Fixture;
let servers: MockServer[] = [];

/** genesis をヘッドにした宣言(seq 1 の entry hash = projectId — どの延長ビューにも実在)。 */
function genesisHead(projectId: string): { seq: number; hashHex: string } {
  return { seq: 1, hashHex: projectId };
}

/**
 * pull 応答の 1 変数(検証済みステートメント + 値 — §12-7 のワイヤ形)。
 * ステートメントの宣言ヘッドは genesis(メタはエポックアンカーを持たないため、
 * author が member 以上ならどのビューでも検証を通る — §4.2)。
 */
async function pullEntry(
  projectId: string,
  variableId: string,
  name: string,
  value: WireDistributedValue,
  author?: TestUser,
  environmentId = ENV_ID,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}> {
  return {
    variableId,
    statement: await statementFor({
      projectId,
      environmentId,
      variableId,
      name,
      author: author ?? fixture.owner,
      head: genesisHead(projectId),
    }),
    value,
  };
}

/** pull 応答の環境ステートメント(active・metaVersion 1・genesis ヘッド)。 */
async function pullEnvStatement(
  projectId: string,
  author?: TestUser,
  environmentId = ENV_ID,
): Promise<WireDistributedEnvironmentStatement> {
  return environmentStatementFor({
    projectId,
    environmentId,
    name: environmentId,
    author: author ?? fixture.owner,
    head: genesisHead(projectId),
  });
}

beforeAll(async () => {
  const owner = await makeTestUser("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  // チェーンには実 DEK のコミットメントが載る(§5.2 — pull の照合まで実データ)
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
  ];
  // 最新バージョンのエポックは変数ごとに異なる(§12-7): ALPHA は epoch 2、
  // BETA はローテーション後も再暗号化されていない epoch 1 のまま。
  // 値署名(§4.1)の宣言ヘッドは各エポックが現エポックだった位置(inclusive):
  // ALPHA = seq 3(rotate)、BETA = seq 2(create)
  const valueAlpha = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
    writer: owner,
    head: headOf(built, 2),
  });
  const envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const entryAlpha = {
    variableId: "va",
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    }),
    value: valueAlpha,
  };
  const entryBeta = {
    variableId: "vb",
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    }),
    value: valueBeta,
  };
  fixture = {
    owner,
    built,
    dek1,
    dek2,
    wraps,
    valueAlpha,
    valueBeta,
    envStatement,
    entryAlpha,
    entryBeta,
  };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(): MockHandler {
  const { built } = fixture;
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

function pullHandler(overrides?: {
  readonly deks?: readonly unknown[];
  readonly variables?: readonly unknown[];
  readonly deletedVariables?: readonly unknown[];
  readonly statement?: unknown;
}): MockHandler {
  const { built, wraps, entryAlpha, entryBeta, envStatement } = fixture;
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: 2,
      statement: overrides?.statement ?? envStatement,
      variables: overrides?.variables ?? [entryAlpha, entryBeta],
      deletedVariables: overrides?.deletedVariables ?? [],
      deks: overrides?.deks ?? wraps,
    },
  }));
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, fixture.owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: fixture.built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

describe("maruhi pull", () => {
  it("同期 + §5.1 検証 + 復号し、メタデータのみ表示する(値は出さない)", async () => {
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

  it("自分宛ラップの欠けエポックを警告する(§7 の全エポック配布との差分 — B2 の本人側検出)", async () => {
    // 全アクティブ値は epoch 2 = 復号は成功する(現在値だけでは永遠に顕在化
    // しない静かな欠け)。epoch 1 の自分宛ラップが無いことを SHOULD 警告する
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [fixture.entryAlpha], deks: [fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("自分宛の DEK ラップがエポック 1 に存在しません");
    expect(errors).toContain("maruhi member add の再実行");

    // 全エポックが揃っていれば警告しない(誤検知なし)
    const complete = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], complete.layer)).toBe(0);
    expect(complete.errors.join("\n")).not.toContain("自分宛の DEK ラップがエポック");
  });

  it("--show は人間には値を表示する", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    expect(env.logs).toContain("ALPHA=alpha-value");
    expect(env.logs).toContain("BETA=beta-value");
  });

  it("コマンドの出力は CliIo だけを通る(実 fd を直に叩く経路を作らない)", async () => {
    // 引数層を移した先(effect/unstable/cli)は出力を `Console` / `Stdio` の
    // サービス経由で行うが、上流が描画経路を増やしたときに実 fd へ素通りする
    // 穴ができうる。**復号した値**が現れる唯一のコマンドで安全網を張る
    const env = await startEnv([chainHandler(), pullHandler()]);
    const bypassed: string[] = [];
    // 束縛ラッパーではなく元のメソッドそのものを控える(戻すたびに 1 段積まない)
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
    // 窓には vitest のレポータ出力も混ざるので、**maruhi の語**で判定する
    const written = bypassed.join("");
    expect(written).not.toContain("alpha-value");
    expect(written).not.toContain("beta-value");
    expect(written).not.toContain("同期・検証 OK");
  });

  it("--show=false / --show false は**書いたとおり**に読まれ、値を表示しない", async () => {
    // gunshi は boolean のインライン値を読まずに true にし、空白区切りの値も
    // 消費しなかった(= 表示しないと書いた実行が全シークレットを出す)。
    // effect/unstable/cli は両方とも false として読む — 拒否ではなく**正しく
    // 読まれる**ことが直り方(直前のテストが、この配布データで --show が
    // 実際に値を出すことを示す)
    const inline = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show=false"], inline.layer)).toBe(0);
    expect(inline.logs.join("\n")).not.toContain("alpha-value");
    expect(inline.logs.join("\n")).toContain("同期・検証 OK");

    const spaced = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "false"], spaced.layer)).toBe(0);
    expect(spaced.logs.join("\n")).not.toContain("alpha-value");
  });

  it("`--no-show --show` のような重複指定は値を表示せずに落ちる", async () => {
    // gunshi は最後の指定で解決するため、明示した `--no-show` が黙って捨てられて
    // 全シークレットが端末へ出る(`maruhi pull --no-show $FLAGS` の形)。
    // effect の素の Flag.boolean は first-wins で沈黙するので、どちらにしても
    // **打った順で結果が変わる**。Flag.atMost(1) が順序に依らず落とす
    const later = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["pull", "--no-show", "--show"], later.layer)).toBe(2);
    expect(later.logs.join("\n")).not.toContain("alpha-value");
    expect(later.errors.join("\n")).toContain("--show を複数回指定しています");
    // 検査は通信より前(復号する平文をそもそも作らない)
    expect(server?.requests).toHaveLength(0);

    // 逆順(最後が --no-show)も同じ扱い。「結果が安全な向きなら通す」に
    // すると、書いた指定が捨てられていること自体が伝わらない
    const earlier = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "--no-show"], earlier.layer)).toBe(2);
    expect(earlier.errors.join("\n")).toContain("--show を複数回指定しています");

    // 同じ綴りの重複も落ちる(`--show --show`)
    const same = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show", "--show"], same.layer)).toBe(2);
    expect(same.logs.join("\n")).not.toContain("alpha-value");

    // 単独の `--no-show` は書いたとおり false として通る(拒否するのは重複だけ)
    const single = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--no-show"], single.layer)).toBe(0);
    expect(single.logs.join("\n")).not.toContain("alpha-value");
  });

  it("--show は値の ANSI/制御シーケンスを中和し、改行は保持する", async () => {
    // 悪意ある共同編集者が保存した値(ESC + BEL)+ 正当な複数行(PEM 風)
    const evil = "sk-\u001b[31mFAKE\u0007\nline2";
    const value = await encryptValueFor({
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
    // ESC / BEL は端末へ生で流れない
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    // 改行は保持(複数行シークレットが壊れない)。ただし 2 行目以降は印を付けて
    // 出力する: 素で流すと値の側で `NAME=value` の行を偽造できる
    expect(output).toContain("SECRET= (2 行の値");
    expect(output).toContain("| sk-\uFFFD[31mFAKE\uFFFD\n| line2");
  });

  it("不正 UTF-8 の値があると --show は失敗し、正常な値も一切出力しない", async () => {
    // 不正 UTF-8 バイト列(0xff/0xfe は UTF-8 に現れない)を平文とする値
    const binary = await encryptValueFor({
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
    expect(env.errors.join("\n")).toContain("UTF-8 として不正のため表示できません");
    // all-or-nothing: 先に並ぶ ALPHA(正常デコード可)も部分出力しない
    expect(env.logs.join("\n")).not.toContain("ALPHA=alpha-value");
  });

  it("AI エージェント検出時、--show は拒否される(run を迂回策として勧めない)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("AI エージェント環境を検出");
    // 値表示の迂回になる run を勧めない(エージェントに迂回レシピを渡さない)
    expect(errors).not.toContain("maruhi run");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
    // 拒否はコマンド入口(復号前)で確定する: 同期・復号・メタデータ表示に進まない
    expect(env.logs.join("\n")).not.toContain("同期・検証 OK");
  });

  it("**未知**のエージェントでも --show は拒否される(TTY が一次境界 = fail-closed)", async () => {
    // deny-list(既知の環境変数)では素通りしていた形。stdout がパイプ・
    // リダイレクトなら、検出リストに無くても値は見せない
    // (`maruhi pull --show > secrets.txt` が拒否されるのも同じ判定)
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("値の表示は対話端末でのみ許可されます");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
    // 復号より前に確定する(平文をそもそも作らない)
    expect(env.logs.join("\n")).not.toContain("同期・検証 OK");
  });

  it("stdin が端末でない実行(CI・ヒアドキュメント)も拒否される", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setTerminal({ stdin: false });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("値の表示は対話端末でのみ許可されます");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
  });

  it("値を表示しない pull は端末でなくても通る(拒否は --show だけ)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("同期・検証 OK");
  });

  it("署名者を偽装したラップ(signerUserId の虚偽申告)を拒否する", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const spoofed = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    // サーバーが signer を owner と虚偽申告する(署名は stranger のまま)
    const lying = {
      ...spoofed,
      signerUserId: fixture.owner.userId,
      signerKeyFingerprintHex: fixture.owner.fingerprintHex,
    };
    const env = await startEnv([chainHandler(), pullHandler({ deks: [lying, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("登録署名が検証できません");
  });

  it("チェーン履歴に存在しない署名者のラップを拒否する", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const foreign = await wrapDekFor({
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
    expect(env.errors.join("\n")).toContain("署名者がチェーン履歴に存在しません");
  });

  it("署名 bit 反転を拒否する", async () => {
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
    expect(env.errors.join("\n")).toContain("登録署名が検証できません");
  });

  it("申告エポックの DEK が配布されていない変数はエラーになる", async () => {
    const env = await startEnv([chainHandler(), pullHandler({ deks: [fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("DEK が配布されていません");
  });

  it("別変数の暗号文の差し替え(メタデータと AAD の不一致)は復号より前に拒否される", async () => {
    // BETA の暗号文を ALPHA のスロットで配る。値署名の検証(§6.3-5 の座標整合)が
    // 復号より前に申告 AAD と外側メタデータの不一致を検出する(旧実装では
    // 復号失敗まで進んでいた — 検出が前段化した)
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "va", "ALPHA", fixture.valueBeta)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("申告 AAD 座標が要求文脈と一致しません");
  });

  it("チェーン現エポックを超えるラップ(ファントムエポック)を拒否する", async () => {
    // 正規メンバー(owner)署名でも、チェーンに rotate_epoch がない epoch 3 の
    // ラップは受理しない(§12-6 のクライアント側 — サーバー不信の本線)
    const phantom = await wrapDekFor({
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
    expect(env.errors.join("\n")).toContain("現エポック(2)を超えるエポック 3");
  });

  it("チェーン現エポックを超える申告エポックの変数を拒否する", async () => {
    // チェーンに存在しないエポック(3)は、どのヘッドを宣言しても「ヘッド時点の
    // 現エポック」と一致しない — 値署名の検証(§6.3-4)が復号より前に拒否する
    const phantomValue = await encryptValueFor({
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

  it("チェーン上のコミットメントと一致しない DEK(毒ラップ = 偽 DEK 注入)を拒否する(§5.2)", async () => {
    // 正規メンバー(owner)が §5.1 署名した実在エポック宛のラップでも、中身が
    // チェーン掲載のコミットメントと一致しない DEK なら使用前に拒否する
    // (悪意サーバー + チェーン履歴上の鍵保持者の共謀による偽 DEK 注入の遮断 —
    // CRYPTO_SPEC §14.2-1。セッション 11 の既知残余を閉じる本 PR の本丸)
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([chainHandler(), pullHandler({ deks: [poison, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("コミットメントと一致しません");
  });

  it("push 前(listMine 経由)でもコミットメント不一致の DEK を拒否する(§5.2 の機密性側)", async () => {
    // §5.2 の (2): 偽 DEK での暗号化(攻撃者が読める push)の誘導を、DEK 使用前の
    // 照合で遮断する。listMine の配布に毒ラップを混ぜる
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      // GAMMA は未存在 → create 経路の名前解決はメタデータのみ pull(§12-7)、
      // DEK は listMine で 1 回だけ取得される(その配布に毒ラップを混ぜる)
      onRequest(
        "GET",
        `/projects/${fixture.built.projectId}/environments/${ENV_ID}/pull/metadata`,
        () => ({
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 2,
            statement: fixture.envStatement,
            variables: [fixture.entryAlpha.statement, fixture.entryBeta.statement],
            deletedVariables: [],
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
    expect(env.errors.join("\n")).toContain("コミットメントと一致しません");
  });

  it("チェーンに create_environment がない環境(ファントム環境)の配布を拒否する", async () => {
    // 「未観測なら epoch 1」の既定値は廃止(§6.2): チェーンが知らない環境の値は
    // 値署名の検証(§6.3-4 — 環境作成前ヘッドの拒否)が復号より前に落とす
    const ghostValue = await encryptValueFor({
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
    const ghostWrap = await wrapDekFor({
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
      onRequest("GET", `/projects/${fixture.built.projectId}/environments/ghost/pull`, () => ({
        status: 200,
        json: {
          environmentId: "ghost",
          currentEpoch: 1,
          // メタステートメントは環境の存在を検査しない(§12-4 の非対称)ため
          // ghost 環境のステートメント自体は検証を通り、値署名(§6.3-4)が落とす
          statement: ghostEnvStatement,
          variables: [ghostEntry],
          deletedVariables: [],
          deks: [ghostWrap],
        },
      })),
    ]);
    expect(await runCli(["pull", "--env", "ghost"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=environment-not-created-at-head");
  });

  it("署名者 FP がチェーン履歴のどの鍵とも一致しないラップを拒否する", async () => {
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
    expect(env.errors.join("\n")).toContain("署名者がチェーン履歴に存在しません");
  });

  it("同一エポックの DEK ラップの重複を拒否する", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [fixture.wraps[0], fixture.wraps[0], fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("重複しています");
  });

  it("別環境の座標で暗号化された暗号文の差し替えは復号より前に拒否される", async () => {
    // environmentId だけ他所(other-env)の値を prod として配布 → 申告 AAD の
    // 座標整合(§6.3-5)が復号より前に検出する(値署名の導入で前段化)
    const crossEnv = await encryptValueFor({
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
    expect(env.errors.join("\n")).toContain("申告 AAD 座標が要求文脈と一致しません");
  });

  it("削除→新鍵で再追加されたメンバーの過去署名は当時の鍵で検証できる(§5.1)", async () => {
    // signer は在籍当時の鍵一式(keysetA)で署名し、その後削除 → 同一 user_id が
    // 新鍵(keysetB)で再追加された。keyHistory は 2 束縛を持ち、FP 一致で
    // 当時の鍵が選ばれる(チェーンは append-only — CRYPTO_SPEC §5.1)
    const oldKeys = await makeTestUser("user-rotated-5555");
    const newKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(newKeys, "member") },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: oldKeys,
    });
    // 値も当時の鍵で署名(§4.1): 宣言ヘッドは在籍区間内(seq 3 = 自身の
    // create_environment エントリ)— 削除後の全チェーンでも検証できる(§6.3-1)
    const value = await encryptValueFor({
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
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await pullEnvStatement(built.projectId, owner),
      variables: [await pullEntry(built.projectId, "vr", "HISTORIC", value, owner)],
      deletedVariables: [],
      deks: [wrap],
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
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

  it("トークン・秘密鍵素材は出力に現れない", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("maruhi_pat_");
    expect(output).not.toContain(fixture.owner.encSkHex);
    expect(output).not.toContain(fixture.owner.sigSkSeedHex);
  });

  it("変数名の制御文字(ANSI・改行)は端末出力でサニタイズされる", async () => {
    const evilName = "EVIL\u001b[2J\nNAME";
    const value = await encryptValueFor({
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
    // 生の ESC がそのまま端末へ流れない(制御文字は置換される)
    expect(output).not.toContain("\u001b");
    expect(output).toContain("EVIL\uFFFD[2J\uFFFDNAME");
  });

  it("変数名の重複(サーバー応答の不整合)を拒否する", async () => {
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
    expect(env.errors.join("\n")).toContain("同名の active ステートメント");
  });

  it("値署名の bit 反転を復号より前に拒否する(§4.1)", async () => {
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

  it("writer の虚偽申告(署名は別人のまま)を拒否する(§4.1 の帰属)", async () => {
    // 署名は owner のまま、writer を別 user_id + 別 FP と申告 → チェーン履歴に
    // その束縛が存在せず検証鍵を選択できない
    const stranger = await makeTestUser("user-stranger-9999");
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

  it("削除済み writer が削除後のヘッドを宣言した値を拒否する(§6.3-3)", async () => {
    // oldKeys は seq 4 で削除。head 5(削除後)を宣言する値は、署名が有効でも
    // 「宣言ヘッド時点の在籍」で拒否される(削除済みメンバーの鍵による新規注入)
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(await makeTestUser("user-other-7777"), "member") },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const forged = await encryptValueFor({
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
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await pullEnvStatement(built.projectId, owner),
      variables: [await pullEntry(built.projectId, "vf", "FORGED", forged, owner)],
      deletedVariables: [],
      deks: [wrap],
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
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

  it("同一応答内の variableId 重複を拒否する(equivocation の運搬形)", async () => {
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
    expect(env.errors.join("\n")).toContain("変数 ID が同一応答内で重複");
  });

  it("未同期区間で追加された新規メンバーが書いた値は有界再同期を経て受理する(レビューループ 1 [低])", async () => {
    // 旧ビュー = genesis のみ(seq 1)。新メンバーを seq 2 で追加し、その新メンバーが
    // seq 3 で環境作成 + 値を書く。旧ビューでは writer が未知(writer-unknown)だが
    // 宣言 seq が自ヘッドより先なので即時拒否せず再同期して受理する
    const owner = fixture.owner;
    const newcomer = await makeTestUser("user-newcomer-2222");
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const shortBuilt = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const fullBuilt = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(newcomer, "member") },
      { actor: newcomer, operation: createEnvironmentOp(ENV_ID, dek) },
    ]);
    expect(shortBuilt.projectId).toBe(fullBuilt.projectId);
    const wrap = await wrapDekFor({
      projectId: fullBuilt.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: newcomer,
    });
    const value = await encryptValueFor({
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
    const newcomerPullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await pullEnvStatement(fullBuilt.projectId, owner),
      variables: [await pullEntry(fullBuilt.projectId, "vn", "NEWCOMER", value, owner)],
      deletedVariables: [],
      deks: [wrap],
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

  it("future head(自ビューより先の宣言 seq)は有界再同期の延長検査を経て受理する(§6.3-2b)", async () => {
    // 旧ビュー = seq 2 まで(rotate 未観測)。値は seq 3(rotate)をヘッドに宣言。
    // 初回検証は chain-head-future → 再同期で 3 エントリの延長が見え、再検証で受理
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
    // 初回同期 + future head の再同期でチェーンは 2 回取得される
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("ALPHA");
  });

  it("future head の再同期が旧ビューの延長でなければ拒否する(別整合チェーンの差し替え)", async () => {
    // 旧ビュー = 正規 3 エントリ。値は seq 4 を宣言 → 再同期で「同じ genesis から
    // 分岐した別の 4 エントリチェーン」が返る = 旧 head(seq 3)のハッシュが不一致
    const { built, owner } = fixture;
    const forkDek = crypto.getRandomValues(new Uint8Array(32));
    const forked = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, fixture.dek1) },
      // 正規チェーンの seq 3(rotate epoch 2)と異なるエントリ = 分岐
      { actor: owner, operation: createEnvironmentOp("side", forkDek) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, fixture.dek2) },
    ]);
    expect(forked.projectId).toBe(built.projectId);
    const futureValue = await encryptValueFor({
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
    expect(env.errors.join("\n")).toContain("延長ではありません");
  });

  it("seq が自ビュー以下でハッシュが一致しないヘッドの宣言は即時拒否する(§6.3-2a)", async () => {
    const bogus = await encryptValueFor({
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

describe("メタステートメントの配布時検証(§4.2 / §6.3)", () => {
  it("ステートメント署名の bit 反転を復号より前に拒否する", async () => {
    const statement = fixture.entryAlpha.statement;
    const flipped = `${statement.signatureHex.slice(0, -1)}${
      statement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: { ...statement, signatureHex: flipped } }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("メタステートメント の検証に失敗");
  });

  it("名前の付け替え(name だけ差し替えたステートメント)を拒否する(name-swap の運搬形)", async () => {
    // 署名は正規のまま name フィールドだけ書き換える = byte-exact 署名で落ちる
    const swapped = { ...fixture.entryAlpha.statement, name: "DEBUG_ENDPOINT" };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: swapped }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });

  it("別変数のステートメントの移植(variableId 不一致)を拒否する", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: fixture.entryBeta.statement }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("ステートメント座標が要求文脈と一致しません");
  });

  it("author の虚偽申告(署名は別人のまま)を拒否する(§4.2 の帰属)", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const lying = {
      ...fixture.entryAlpha.statement,
      authorUserId: stranger.userId,
      authorKeyFingerprintHex: stranger.fingerprintHex,
    };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ ...fixture.entryAlpha, statement: lying }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=author-unknown");
  });

  it("環境ステートメントの改竄・deleted 配布を拒否する", async () => {
    // 署名 bit 反転
    const flipped = `${fixture.envStatement.signatureHex.slice(0, -1)}${
      fixture.envStatement.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ statement: { ...fixture.envStatement, signatureHex: flipped } }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("メタステートメント の検証に失敗");

    // deleted ステートメントの配布(削除済み環境の pull はサーバーでは 404 のはず)
    const deletedStatement = await pullEnvStatement(fixture.built.projectId);
    const deleted = await startEnv([
      chainHandler(),
      pullHandler({
        statement: {
          ...(await environmentStatementFor({
            projectId: fixture.built.projectId,
            environmentId: ENV_ID,
            name: ENV_ID,
            author: fixture.owner,
            head: genesisHead(fixture.built.projectId),
            status: "deleted",
            metaVersion: 2,
          })),
        },
      }),
    ]);
    void deletedStatement;
    expect(await runCli(["pull"], deleted.layer)).toBe(1);
    expect(deleted.errors.join("\n")).toContain("deleted ステートメントが配布されました");
  });

  it("削除済み変数の tombstone は検証され、active との併置(無断復活の運搬形)は拒否する", async () => {
    // 正常系: deleted ステートメントのみの配布は受理され、値には現れない
    const tombstone = await statementFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      variableId: "v-deleted",
      name: "RETIRED_KEY",
      author: fixture.owner,
      head: genesisHead(fixture.built.projectId),
      status: "deleted",
      metaVersion: 2,
    });
    const ok = await startEnv([chainHandler(), pullHandler({ deletedVariables: [tombstone] })]);
    expect(await runCli(["pull"], ok.layer)).toBe(0);
    expect(ok.logs.join("\n")).not.toContain("RETIRED_KEY");

    // 同一 variableId が active と deleted の両方で配布される = 拒否
    const revived = { ...tombstone, variableId: fixture.entryAlpha.variableId };
    const conflict = await startEnv([chainHandler(), pullHandler({ deletedVariables: [revived] })]);
    expect(await runCli(["pull"], conflict.layer)).toBe(1);
    expect(conflict.errors.join("\n")).toContain("active と deleted の両方で配布されました");

    // tombstone の署名改竄も拒否(配布し続ける以上、検証もし続ける)
    const flipped = `${tombstone.signatureHex.slice(0, -1)}${
      tombstone.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const tampered = await startEnv([
      chainHandler(),
      pullHandler({ deletedVariables: [{ ...tombstone, signatureHex: flipped }] }),
    ]);
    expect(await runCli(["pull"], tampered.layer)).toBe(1);
    expect(tampered.errors.join("\n")).toContain("メタステートメント の検証に失敗");
  });

  it("非 NFC 名の配布は警告される(SHOULD — §12-1。処理は継続する)", async () => {
    const nfdName = "CAFE\u0301_URL";
    expect(nfdName.normalize("NFC")).not.toBe(nfdName);
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vnfd",
      version: 1,
      plaintext: "v",
      writer: fixture.owner,
      head: headOf(fixture.built, 3),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [await pullEntry(fixture.built.projectId, "vnfd", nfdName, value)],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("NFC 正規形ではありません");
  });

  it("削除済み author のステートメントは在籍中ヘッドで検証できる(§6.3-1 の対)", async () => {
    // author(oldKeys)は seq 4 で削除済み。宣言ヘッド seq 3(在籍中)の
    // ステートメントは削除後の全チェーンでも当時の鍵で検証できる
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vh",
      version: 1,
      plaintext: "historic",
      writer: oldKeys,
      head: headOf(built, 3),
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await environmentStatementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: oldKeys,
        head: headOf(built, 3),
      }),
      variables: [
        {
          variableId: "vh",
          statement: await statementFor({
            projectId: built.projectId,
            environmentId: ENV_ID,
            variableId: "vh",
            name: "HISTORIC",
            author: oldKeys,
            head: headOf(built, 3),
          }),
          value,
        },
      ],
      deletedVariables: [],
      deks: [wrap],
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
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

  it("削除済み author が削除後のヘッドを宣言したステートメントを拒否する", async () => {
    const oldKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: owner,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vf",
      version: 1,
      plaintext: "v",
      writer: owner,
      head: headOf(built, 3),
    });
    // メタの前進注入のうち「削除後ヘッドの宣言」は在籍検査で落ちる(§6.3-3。
    // 在籍中ヘッドを宣言する前進注入はエポックアンカーがなく v1 未検出 — §14.3-5)
    const forgedStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vf",
      name: "FORGED_NAME",
      author: oldKeys,
      head: headOf(built, 4),
      metaVersion: 2,
    });
    const pullJson = {
      environmentId: ENV_ID,
      currentEpoch: 1,
      statement: await environmentStatementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(built, 1),
      }),
      variables: [{ variableId: "vf", statement: forgedStatement, value }],
      deletedVariables: [],
      deks: [wrap],
    };
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
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
    expect(env.errors.join("\n")).toContain("reason=author-not-member-at-head");
  });

  it("ステートメントの future head も有界再同期を経て受理する(値と同じ機構の流用 — §6.3-2b)", async () => {
    // 旧ビュー = seq 2 まで。ステートメントは seq 3(rotate)をヘッドに宣言。
    // 初回検証は chain-head-future → 再同期で延長が見え、再検証で受理
    const { built } = fixture;
    const futureStatement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: fixture.owner,
      head: headOf(built, 3),
    });
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
        },
      };
    });
    const env = await startEnv([
      progressiveChain,
      pullHandler({
        variables: [{ ...fixture.entryAlpha, statement: futureStatement }],
        deks: fixture.wraps,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBe(2);
    expect(env.logs.join("\n")).toContain("ALPHA");
  });
});

describe("maruhi run", () => {
  it("復号した値を子プロセス環境変数としてメモリ注入する", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv).toEqual({
      ALPHA: "alpha-value",
      BETA: "beta-value",
    });
  });

  it("AI エージェント検出時でも run は許可される(線引き)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    // 端末でなくても通す(CI / パイプ)。run は値を**見せる**経路ではなく、
    // 子プロセスの環境変数へ注入する消費経路なので TTY 境界の対象外
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("値は子プロセス環境のみに現れ、端末出力には出ない", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
  });

  it("子プロセスの終了コードを伝播する", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setRunnerExitCode(3);
    expect(await runCli(["run", "--", "false"], env.layer)).toBe(3);
  });

  it("コマンド未指定は pull も復号もせずにエラーになる", async () => {
    // 実行対象が無い実行は書き方の誤り(usage エラー)。ここを通すと配布の
    // 取得と全変数の復号まで進んでから同じことを言う = 使われない平文を作る
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("`--` の後に指定");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("`--` だけで実行対象が無い場合も同じ", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "--"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("`--` の後に指定");
    expect(server?.requests).toHaveLength(0);
  });

  it("`--` の後ろの空文字列の引数も落とさずに渡す", async () => {
    // gunshi の ctx.rest は値が truthy のものしか入れないため、空文字列の
    // 引数は rest から落ちて positionals へ紛れ込む。素直に使うと子プロセスの
    // 引数が黙って 1 つ減り、引数検査も誤爆する(トークンから組み直している)
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "", "ALPHA"]);
  });

  it("`--` の前の空の引数は、子プロセス側に空白の引数があっても拾う", async () => {
    // `--` の前後は 1 つの配列に混ざる(上流のパーサ)ので、先頭の空文字列が
    // 実行対象の位置に来る。`Argument.filter` が「実行対象が空」として落とす
    // — 子プロセスの空白だけの引数(`" "`)は落とさない(2 つ目以降はそのまま渡す)
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "", "--", "printenv", " "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("実行するコマンドを `--` の後に指定してください");
    expect(server?.requests).toHaveLength(0);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("`--` の**前**に置いた実行対象は子プロセスにならない(`--` の後ろだけを取る)", async () => {
    // 上流のパーサは `--` の前後の位置引数を 1 つの配列にまとめるため、宣言だけ
    // では `maruhi run stray -- printenv` が **stray の実行**に化ける。
    // `Stdio.args` の `--` 位置と個数を突き合わせて落とす(ADR-0016 決定 8)
    const env = await startEnv([chainHandler(), pullHandler()]);
    const server = servers[servers.length - 1];
    expect(await runCli(["run", "stray", "--", "printenv"], env.layer)).toBe(2);
    const errors = env.errors.join("\n");
    expect(errors).toContain("余分な引数です(1 個");
    expect(errors).toContain("`--` の後に並べてください");
    // 中身は出さない(位置引数には平文が書かれうる)
    expect(errors).not.toContain("stray");
    expect(env.runnerCalls).toHaveLength(0);
    expect(server?.requests).toHaveLength(0);
  });

  it("入れ子の `--`(`npm test -- --watch`)も子プロセスへそのまま渡る", async () => {
    // args-tokens が出す option-terminator は先頭の 1 つだけで、内側の `--` は
    // 位置引数トークンになる。restArguments はそれを落とさない(落とすと
    // npm / cargo / docker 形式の引数転送が壊れる)
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "npm", "test", "--", "--watch"], env.layer)).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["npm", "test", "--", "--watch"]);
  });

  it("`--` の後ろは maruhi の引数検査を通らず、子プロセスへそのまま渡る", async () => {
    // 引数の書き方の検査(args.ts / strict)が子プロセスの引数に及ぶと、
    // `maruhi run -- <cmd>` は任意のコマンドを実行できなくなる。`--` 以降は
    // 位置引数トークンとして ctx.rest にだけ入る(ctx.positionals にも
    // オプショントークンにも現れない)ため、検査の対象にならない
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(
      await runCli(["run", "--", "printenv", "--show=false", "--shwo", "extra"], env.layer),
    ).toBe(0);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "--show=false", "--shwo", "extra"]);
  });
});
