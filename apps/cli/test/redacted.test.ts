// 秘密素材を `Redacted` で包んだことの回帰(ADR-0016 の値表示ゲートに続く 4 層目)。
//
// display.ts(端末中和)・failure.ts(エラー写像)・内部エラーの型名のみ、に続く
// 4 層目として、トークン類は型の上で `Redacted` を剥がさないと生値が得られない。
// ここで固定するのは 3 つ:
//
//  1. うっかり `toString` / `JSON.stringify` / テンプレート展開した場合に伏字になる
//  2. キーチェーン往復(保存 → 読み戻し → 実使用)が伏字保存で壊れていない
//     (`Redacted.toJSON()` は "<redacted>" を返すため、レコードをそのまま
//      stringify すると型エラーにならないまま伏字が保存される — 最大の罠)
//  3. 剥がす箇所(`Redacted.value`)が数えられる状態に保たれている
//
// 3 が本命に近い: 伏字そのものより「剥がす箇所が増えていないこと」が効く。

import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Effect, Exit, Layer, Redacted, Stdio } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { afterEach, describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { makeApiClient } from "../src/api.ts";
import { runCli } from "../src/cli.ts";
import { type DisplayableVariable, formatPulledLine, showValues } from "../src/display.ts";
import { buildInviteLink, parseInviteAcceptInput } from "../src/invite-link.ts";
import { CliIo } from "../src/io.ts";
import { parseStoredToken, serializeStoredToken, tokenEntryName } from "../src/keychain.ts";
import { resolveSession } from "../src/session.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

// ---------------------------------------------------------------------------
// 1. うっかり出力しても伏字になる
// ---------------------------------------------------------------------------

describe("秘密は素朴な出力経路で伏字になる", () => {
  const SECRET = "maruhi_pat_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9x123";

  it("toString / テンプレート展開 / String() が生値を出さない", () => {
    const token = Redacted.make(SECRET, { label: "maruhi-token" });
    expect(token.toString()).toBe("<redacted:maruhi-token>");
    expect(`${token}`).toBe("<redacted:maruhi-token>");
    expect(String(token)).toBe("<redacted:maruhi-token>");
    expect(`${token}`).not.toContain(SECRET);
  });

  it("JSON.stringify が生値を出さない(レコードに埋まっていても)", () => {
    const record = {
      token: Redacted.make(SECRET, { label: "maruhi-token" }),
      userId: "u1",
      tokenId: "t1",
    };
    const json = JSON.stringify(record);
    expect(json).not.toContain(SECRET);
    expect(JSON.parse(json)).toEqual({
      token: "<redacted:maruhi-token>",
      userId: "u1",
      tokenId: "t1",
    });
  });

  it("招待リンク(トークンを内包する)も包んだまま出力すると伏字になる", () => {
    const link = buildInviteLink({
      origin: "https://maruhi.example",
      token: Redacted.make("maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01", {
        label: "invite-token",
      }),
      projectId: "ab".repeat(32),
      headHashHex: "cd".repeat(32),
      headSeq: 1,
      inviterUserId: "user-inviter-11",
      inviterKeyFingerprintHex: "ef".repeat(16),
      role: "member",
    });
    expect(`${link}`).toBe("<redacted:invite-link>");
    expect(JSON.stringify({ link })).not.toContain("maruhi_inv_");
    // 剥がせば本物のリンクが得られる(伏字が機能を壊していないこと)
    expect(Redacted.value(link)).toContain("maruhi_inv_");
  });

  it("復号値(Uint8Array)も伏字になる — pull の結果をうっかり出力しても漏れない", () => {
    const value = Redacted.make(new TextEncoder().encode("plaintext-value"), {
      label: "variable-value",
    });
    const variable = { variableId: "v1", name: "SECRET", version: 1, epoch: 1, value };
    expect(`${value}`).toBe("<redacted:variable-value>");
    expect(JSON.stringify(variable)).not.toContain("plaintext-value");
    expect(JSON.stringify(variable)).toContain("<redacted:variable-value>");
    // 一覧行はバイト長だけを載せる(値そのものは出さない)
    const line = formatPulledLine(variable);
    expect(line).toContain("(15 bytes)");
    expect(line).not.toContain("plaintext-value");
  });

  it("解釈したリンク・生トークンの token も包まれている", () => {
    const raw = Redacted.value(
      buildInviteLink({
        origin: "https://maruhi.example",
        token: Redacted.make("maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01"),
        projectId: "ab".repeat(32),
        headHashHex: "cd".repeat(32),
        headSeq: 1,
        inviterUserId: "user-inviter-11",
        inviterKeyFingerprintHex: "ef".repeat(16),
        role: "member",
      }),
    );
    const parsed = parseInviteAcceptInput(raw);
    if (parsed.kind !== "link") throw new Error(`expected link, got ${parsed.kind}`);
    expect(`${parsed.link.token}`).toBe("<redacted:invite-token>");
    expect(JSON.stringify(parsed.link)).not.toContain("maruhi_inv_");
  });
});

// ---------------------------------------------------------------------------
// 2. キーチェーン往復(保存 → 読み戻し → 実使用)
// ---------------------------------------------------------------------------

describe("キーチェーン往復は伏字保存で壊れていない", () => {
  it("serializeStoredToken は生値を書く(JSON.stringify の伏字保存を踏んでいない)", () => {
    const record = parseStoredToken(
      JSON.stringify({ token: "maruhi_pat_real", userId: "u1", tokenId: "t1" }),
    );
    if (record === null) throw new Error("expected a parsed record");
    const serialized = serializeStoredToken(record);
    expect(serialized).toContain("maruhi_pat_real");
    expect(serialized).not.toContain("<redacted");
  });

  it("login の保存 → resolveSession の読み戻し → Bearer ヘッダーでの実使用", async () => {
    // 3 段を 1 本で通す。どこかで伏字が混ざれば「保存はできたのに認証に失敗する」
    // 形で必ずここが落ちる(型検査では捕まらない経路)
    const githubServer = await start([
      onRequest("POST", "/login/device/code", () => ({
        status: 200,
        json: {
          device_code: "dev-code-0001",
          user_code: "ABCD-1234",
          verification_uri: "https://github.example/login/device",
          interval: 0,
          expires_in: 900,
        },
      })),
      onRequest("POST", "/login/oauth/access_token", () => ({
        status: 200,
        json: { access_token: "gho_github_token_value" },
      })),
    ]);
    const authorizations: (string | undefined)[] = [];
    const maruhi = await start([
      onRequest("POST", "/auth/device/exchange", () => ({
        status: 200,
        json: { token: "maruhi_pat_issued_real", tokenId: "tok_1", userId: "user-0001" },
      })),
      onRequest("GET", "/auth/me", (request) => {
        const header = request.headers["authorization"];
        authorizations.push(typeof header === "string" ? header : undefined);
        return { status: 200, json: { userId: "user-0001", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    await seedConfig(env, { server: maruhi.origin, githubClientId: "Iv1.testclient" });

    // (a) 保存: login がキーチェーンへ書く
    const code = await runCli(
      ["login", "--github-base-url", githubServer.origin, "--github-poll-interval", "0"],
      env.layer,
    );
    expect(code).toBe(0);
    const stored = env.keychain.get(tokenEntryName(maruhi.origin));
    expect(stored).toBeDefined();
    // 伏字が保存されていない = 次回認証が死んでいない
    expect(stored).toContain("maruhi_pat_issued_real");
    expect(stored).not.toContain("<redacted");

    // (b) 読み戻し: resolveSession がキーチェーンから復元する
    const session = await Effect.runPromise(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    expect(Redacted.value(session.token)).toBe("maruhi_pat_issued_real");

    // (c) 実使用: 復元したトークンが Bearer ヘッダーとして実際に送られる
    await Effect.runPromise(
      Effect.gen(function* () {
        const client = yield* makeApiClient({ baseUrl: maruhi.origin, token: session.token });
        return yield* client.auth.me({});
      }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    expect(authorizations).toEqual(["Bearer maruhi_pat_issued_real"]);
  });

  it("MARUHI_TOKEN 経路のトークンも包まれ、生値のまま送られる", async () => {
    const authorizations: (string | undefined)[] = [];
    const maruhi = await start([
      onRequest("GET", "/auth/me", (request) => {
        const header = request.headers["authorization"];
        authorizations.push(typeof header === "string" ? header : undefined);
        return { status: 200, json: { userId: "user-env", orgs: [] } };
      }),
    ]);
    const env = await makeTestEnv();
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env_real");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", maruhi.origin);
    const session = await Effect.runPromise(
      resolveSession(maruhi.origin).pipe(Effect.provide(env.layer)),
    );
    // env から来た素の string が包まれている(起点での wrap)
    expect(`${session.token}`).toBe("<redacted:maruhi-token>");
    expect(Redacted.value(session.token)).toBe("maruhi_pat_env_real");
    expect(authorizations).toEqual(["Bearer maruhi_pat_env_real"]);
  });
});

// ---------------------------------------------------------------------------
// 2b. 復号値は表示ゲートの「後ろ」でしか剥がされない
// ---------------------------------------------------------------------------

/**
 * 剥がしを**観測可能**にした変数を 1 つ作る。
 *
 * `Redacted.wipeUnsafe` 後の `Redacted.value` は defect を投げる(上流仕様)。
 * これを利用すると「剥がしたかどうか」を外から判定できる: ゲートで拒否される
 * なら型付きエラー(CliError)で落ち、ゲートを通ったなら defect で落ちる。
 * ゼロ化ではなくハンドル無効化としてテスト内でのみ使う(本番コードは
 * wipeUnsafe を使わない — defect 経路を自分で作らないため)。
 */
function wipedVariable(): DisplayableVariable {
  const value = Redacted.make(new TextEncoder().encode("plaintext-value"), {
    label: "variable-value",
  });
  Redacted.wipeUnsafe(value);
  return { name: "SECRET", version: 1, epoch: 1, value };
}

describe("復号値の剥がしは値表示ゲートの後ろにある", () => {
  /** 出力を捨てる CliIo(ここでは「表示に至らないこと」だけを見る)。 */
  const silentIo = Layer.succeed(CliIo, {
    log: () => Effect.void,
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array(0)),
    promptLine: () => Effect.succeed(""),
    envVar: () => undefined,
    agentProfile: () => ({ isAgent: false }),
  });

  const showWiped = (input: {
    readonly isAgent: boolean;
    readonly stdinIsTerminal: boolean;
    readonly stdoutIsTerminal: boolean;
  }) =>
    Effect.runPromiseExit(
      showValues([wipedVariable()]).pipe(
        Effect.provide(
          Layer.mergeAll(
            silentIo,
            Layer.succeed(AgentProfileRef, { isAgent: input.isAgent }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(input.stdinIsTerminal),
              stdoutIsTerminal: Effect.succeed(input.stdoutIsTerminal),
            }),
          ),
        ),
      ),
    );

  it("非 TTY / 既知エージェントでは、剥がす前に型付きエラーで落ちる", async () => {
    // 剥がしていれば defect(Unable to get redacted value)になるはず。
    // そうならず CliError で落ちる = 判定がゲートの手前で確定している
    for (const rejected of [
      { isAgent: false, stdinIsTerminal: true, stdoutIsTerminal: false },
      { isAgent: false, stdinIsTerminal: false, stdoutIsTerminal: true },
      { isAgent: true, stdinIsTerminal: true, stdoutIsTerminal: true },
    ]) {
      const exit = await showWiped(rejected);
      expect(Exit.isFailure(exit)).toBe(true);
      const dump = JSON.stringify(exit);
      // 型付きエラー(Fail)で落ちる = ゲートで確定した。剥がしに到達して
      // いれば wipe 済みハンドルが defect(Die)を投げるのでここが変わる
      expect(dump).toContain('"_tag":"Fail"');
      expect(dump).not.toContain('"_tag":"Die"');
      expect(dump).not.toContain("plaintext-value");
    }
  });

  it("人間の対話端末でだけ剥がしに到達する(ゲートが空振りしていない陽性対照)", async () => {
    // 同じ入力でゲートを通すと、今度は剥がしに到達して defect になる。
    // これが無いと上のテストは「そもそも剥がさない実装」でも通ってしまう
    const exit = await showWiped({
      isAgent: false,
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(exit)).toBe(true);
    // wipe 済みハンドルの剥がしに到達した証拠(defect = Die)
    expect(JSON.stringify(exit)).toContain('"_tag":"Die"');
  });
});

// ---------------------------------------------------------------------------
// 3. 剥がす箇所の棚卸し
// ---------------------------------------------------------------------------

/**
 * `Redacted.value(` の呼び出し箇所(ファイル → 件数)。
 *
 * **この表を増やす変更はレビューの対象**。伏字そのものより「剥がす箇所が
 * 数えられる状態」を保つことが効く(棚卸し — notes §7)。増やすときは
 * 「なぜここで剥がすか」を実装側のコメントに残し、この表を更新すること。
 */
const EXPECTED_UNWRAP_SITES: Readonly<Record<string, number>> = {
  // 一覧行のバイト長(値は載せない)+ --show の表示(ゲート通過後)
  "display.ts": 2,
  // ワイヤ境界: 招待受諾要求 / 受諾署名のハッシュ入力 / リンクの表示
  "invite.ts": 3,
  // リンク文字列の組み立て(結果は再び包む)
  "invite-link.ts": 1,
  // キーチェーンへの直列化(唯一の永続化経路)
  "keychain.ts": 1,
  // device exchange のワイヤ境界(GitHub トークン)
  "login.ts": 1,
  // 暗号境界(平文 → 暗号文)
  "push.ts": 1,
  // 子プロセス env への注入直前
  "run.ts": 1,
};

async function collectUnwrapSites(): Promise<Record<string, number>> {
  const files = (await readdir(SRC_DIR)).filter((name) => name.endsWith(".ts")).toSorted();
  const counts: Record<string, number> = {};
  for (const name of files) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    const matches = source.match(/Redacted\.value\(/g);
    if (matches !== null) {
      counts[name] = matches.length;
    }
  }
  return counts;
}

describe("Redacted を剥がす箇所の棚卸し", () => {
  it("剥がす箇所が増えていない(増やすなら EXPECTED_UNWRAP_SITES を更新する)", async () => {
    expect(await collectUnwrapSites()).toEqual(EXPECTED_UNWRAP_SITES);
  });

  it("トークンを Bearer に載せるのに剥がしていない(上流の bearerToken を使う)", async () => {
    const source = await readFile(join(SRC_DIR, "api.ts"), "utf8");
    expect(source).not.toContain("Redacted.value");
    // 手書きのヘッダー組み立て(テンプレート展開)は伏字を送ってしまう形 —
    // 使っていないこと
    expect(source).not.toMatch(/Bearer \$\{/);
  });
});
