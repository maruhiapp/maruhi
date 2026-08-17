// 細部のユニットテスト: device flow のポーリング規則(RFC 8628 §3.5)、
// キーチェーンレコードの codec、run の注入検証、stdin 正規化、
// MARUHI_TOKEN 環境変数経路、サーバー URL 解決、操作専用オプションの適用可否。

import { ProjectNotFoundError } from "@maruhi/api-schema";
import { Cause, Effect, Exit, Layer, Redacted, Schema, Stdio } from "effect";
import { HttpClientError, HttpClientRequest } from "effect/unstable/http";
import { afterEach, describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { optionRestrictedTo, runCli } from "../src/cli.ts";
import { pollDeviceFlow, startDeviceFlow } from "../src/device-flow.ts";
import { decodeValueText, showValues } from "../src/display.ts";
import { toCliError } from "../src/failure.ts";
import { CliIo } from "../src/io.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  serializeStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import type { DecryptedVariable } from "../src/pull.ts";
import { normalizeStdinValue } from "../src/push.ts";
import { buildInjectionEnv, ProcessRunner, runOp } from "../src/run.ts";
import {
  cryptoBackendUsable,
  resolveServerOrigin,
  unsupportedCryptoCause,
  unsupportedCryptoMessage,
} from "../src/session.ts";
import { makeTestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig } from "./support/env.ts";
import { MockServer, onRequest } from "./support/server.ts";

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

describe("pollDeviceFlow", () => {
  it("slow_down は待ち時間を増やして続行する", async () => {
    let polls = 0;
    const server = await MockServer.start([
      onRequest("POST", "/login/oauth/access_token", () => {
        polls += 1;
        if (polls === 1) {
          return { status: 200, json: { error: "slow_down" } };
        }
        return { status: 200, json: { access_token: "gho_x" } };
      }),
    ]);
    servers.push(server);
    const token = await Effect.runPromise(
      pollDeviceFlow({
        clientId: "c",
        githubBaseUrl: server.origin,
        slowDownExtraSeconds: 0.01,
        authorization: {
          deviceCode: "d",
          userCode: "u",
          verificationUri: "v",
          intervalSeconds: 0,
          expiresInSeconds: 60,
        },
      }),
    );
    expect(Redacted.value(token)).toBe("gho_x");
    expect(polls).toBe(2);
  });

  it("expired_token(サーバー申告)で中断する。RFC 準拠の 400 + error ボディも分類できる", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/oauth/access_token", () => ({
        // RFC 8628 準拠実装の形(GitHub 実サーバーは 200 + error)
        status: 400,
        json: { error: "expired_token" },
      })),
    ]);
    servers.push(server);
    const exit = await Effect.runPromiseExit(
      pollDeviceFlow({
        clientId: "c",
        githubBaseUrl: server.origin,
        authorization: {
          deviceCode: "d",
          userCode: "u",
          verificationUri: "v",
          intervalSeconds: 0,
          expiresInSeconds: 60,
        },
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("authorization code expired");
  });

  it("device flow 開始応答の欠損(device_code なし)を検出する", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/device/code", () => ({ status: 200, json: { interval: 5 } })),
    ]);
    servers.push(server);
    const exit = await Effect.runPromiseExit(
      startDeviceFlow({ clientId: "c", githubBaseUrl: server.origin }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("device-flow start response");
  });

  it("サーバーが interval 0 を返しても下限(既定 5 秒)に丸める(ビジースピン防止)", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/device/code", () => ({
        status: 200,
        json: {
          device_code: "d",
          user_code: "U",
          verification_uri: "https://github.example/device",
          interval: 0,
          expires_in: 900,
        },
      })),
    ]);
    servers.push(server);
    const auth = await Effect.runPromise(
      startDeviceFlow({ clientId: "c", githubBaseUrl: server.origin }),
    );
    expect(auth.intervalSeconds).toBe(5);
  });

  it("minIntervalSeconds を渡すと下限を上書きできる(テスト用)", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/device/code", () => ({
        status: 200,
        json: {
          device_code: "d",
          user_code: "U",
          verification_uri: "https://github.example/device",
          interval: 0,
          expires_in: 900,
        },
      })),
    ]);
    servers.push(server);
    const auth = await Effect.runPromise(
      startDeviceFlow({ clientId: "c", githubBaseUrl: server.origin, minIntervalSeconds: 0 }),
    );
    expect(auth.intervalSeconds).toBe(0);
  });

  it("期限切れ(deadline 超過)で中断する", async () => {
    const server = await MockServer.start([
      onRequest("POST", "/login/oauth/access_token", () => ({
        status: 200,
        json: { error: "authorization_pending" },
      })),
    ]);
    servers.push(server);
    const exit = await Effect.runPromiseExit(
      pollDeviceFlow({
        clientId: "c",
        githubBaseUrl: server.origin,
        authorization: {
          deviceCode: "d",
          userCode: "u",
          verificationUri: "v",
          intervalSeconds: 0.01,
          expiresInSeconds: 0.02,
        },
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("authorization code expired");
  });
});

describe("keychain record codecs", () => {
  it("トークン・master 鍵レコードの往復と破損検出", () => {
    const token = { token: "maruhi_pat_x", userId: "u1", tokenId: "t1" };
    const parsed = parseStoredToken(JSON.stringify(token));
    if (parsed === null) throw new Error("expected a parsed token record");
    // 生値の突合は必ず剥がして行う(包んだままの toEqual は中身を見ない)
    expect(Redacted.value(parsed.token)).toBe("maruhi_pat_x");
    expect({ userId: parsed.userId, tokenId: parsed.tokenId }).toEqual({
      userId: "u1",
      tokenId: "t1",
    });
    // 保存側との往復: serializeStoredToken → parseStoredToken で生値が戻る
    // (直列化が伏字を書いていればここで落ちる)
    const reparsed = parseStoredToken(serializeStoredToken(parsed));
    if (reparsed === null) throw new Error("expected a reparsed token record");
    expect(Redacted.value(reparsed.token)).toBe("maruhi_pat_x");
    expect(parseStoredToken("not json")).toBeNull();
    expect(parseStoredToken(JSON.stringify({ token: "x" }))).toBeNull();
    expect(parseStoredMasterKey(JSON.stringify({ suite: "maruhi/v1" }))).toBeNull();
  });

  it("キーチェーン名はサーバー origin(と userId)でスコープされる", () => {
    expect(tokenEntryName("https://a.example")).not.toBe(tokenEntryName("https://b.example"));
    expect(masterKeyEntryName("https://a.example", "u1")).not.toBe(
      masterKeyEntryName("https://a.example", "u2"),
    );
  });
});

describe("resolveServerOrigin", () => {
  it("フラグ → config の順に解決し、origin へ正規化する", async () => {
    const origin = await Effect.runPromise(
      resolveServerOrigin("https://maruhi.example/some/path", {}),
    );
    expect(origin).toBe("https://maruhi.example");
    const fromConfig = await Effect.runPromise(
      resolveServerOrigin(undefined, { server: "http://localhost:8787" }),
    );
    expect(fromConfig).toBe("http://localhost:8787");
  });

  it("未設定・不正 URL はエラー", async () => {
    const missing = await Effect.runPromiseExit(resolveServerOrigin(undefined, {}));
    expect(Exit.isFailure(missing)).toBe(true);
    const invalid = await Effect.runPromiseExit(resolveServerOrigin("not-a-url", {}));
    expect(Exit.isFailure(invalid)).toBe(true);
  });

  it("http: は loopback のみ許可する(平文送信の遮断)", async () => {
    const loopback = await Effect.runPromise(resolveServerOrigin("http://localhost:8787", {}));
    expect(loopback).toBe("http://localhost:8787");
    const remote = await Effect.runPromiseExit(resolveServerOrigin("http://maruhi.example", {}));
    expect(Exit.isFailure(remote)).toBe(true);
    expect(JSON.stringify(remote)).toContain("loopback");
  });
});

function variable(name: string, value: string | Uint8Array): DecryptedVariable {
  return {
    variableId: "v1",
    name,
    version: 1,
    epoch: 1,
    value: Redacted.make(typeof value === "string" ? new TextEncoder().encode(value) : value, {
      label: "variable-value",
    }),
  };
}

describe("runOp", () => {
  /** 子プロセスを起動しないランナー(起動まで到達したら分かるようにする)。 */
  const spawnedNothing = Layer.succeed(ProcessRunner, {
    run: () => Effect.succeed(0),
  });

  it("実行対象が空白だけでも子プロセスを起動しない(入口の検査と同じ判定)", async () => {
    const exit = await Effect.runPromiseExit(
      runOp({ command: ["  "], variables: [] }).pipe(Effect.provide(spawnedNothing)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("Specify the command to run after `--`");
  });

  it("実行対象が空文字列だけなら子プロセスを起動しない", async () => {
    // 入口の引数検査(cli.ts)と同じ判定をここでも持つ(直接呼び出し向けの
    // 防衛線)。`[""]` は「1 要素あるが実行できない」形
    const exit = await Effect.runPromiseExit(
      runOp({ command: [""], variables: [] }).pipe(Effect.provide(spawnedNothing)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("Specify the command to run after `--`");
    // 書き方の誤りは入口と同じ usage エラー(終了コード 2)として立てる
    expect(JSON.stringify(exit)).toContain('"usage":true');
  });
});

describe("showValues(復号後の防衛線)", () => {
  /** 出力を捨てる CliIo(この検査は「表示に至らないこと」だけを見る)。 */
  const silentIo = Layer.succeed(CliIo, {
    log: () => Effect.void,
    logError: () => Effect.void,
    readStdin: Effect.succeed(new Uint8Array(0)),
    promptLine: () => Effect.succeed(""),
    envVar: () => undefined,
    agentProfile: () => ({ isAgent: false }),
  });

  const showOne = (input: {
    readonly agent?: { readonly isAgent: boolean; readonly name?: string };
    readonly stdinIsTerminal: boolean;
    readonly stdoutIsTerminal: boolean;
  }) =>
    Effect.runPromiseExit(
      showValues([variable("SECRET", "plaintext-value")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            silentIo,
            Layer.succeed(AgentProfileRef, input.agent ?? { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(input.stdinIsTerminal),
              stdoutIsTerminal: Effect.succeed(input.stdoutIsTerminal),
            }),
          ),
        ),
      ),
    );

  it("入口の検査を通らない直接呼び出しでも、端末以外では表示しない", async () => {
    // 本線は pull の入口(復号前)。ここは showValues を直接呼ぶ将来の経路が
    // 入口検査を欠いても表示に至らせない防衛線で、**両層とも同じ判定**
    // (一次 = TTY / 二次 = エージェント検出)であることを固定する
    const piped = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: false });
    expect(Exit.isFailure(piped)).toBe(true);
    expect(JSON.stringify(piped)).toContain("対話端末でのみ許可されます");
    expect(JSON.stringify(piped)).not.toContain("plaintext-value");

    const headless = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: true });
    expect(Exit.isFailure(headless)).toBe(true);

    const agent = await showOne({
      agent: { isAgent: true, name: "claude" },
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(agent)).toBe(true);
    expect(JSON.stringify(agent)).toContain("AI エージェント環境を検出");
  });

  it("人間の対話端末では表示する(検査が空振りしていない陽性対照)", async () => {
    const allowed = await showOne({ stdinIsTerminal: true, stdoutIsTerminal: true });
    expect(Exit.isSuccess(allowed)).toBe(true);
  });

  it("値の改行で `NAME=value` の行を偽造できない", async () => {
    // 値は共同編集者が書ける。改行をそのまま流すと、存在しない変数の行を
    // 画面に作れる(pull --show を見て貼る利用者を騙せる)
    const logs: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "x\nDATABASE_URL=postgres://attacker/")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    // 偽造された行は `NAME=value` の形では出ない(印が付く)
    expect(logs).not.toContain("DATABASE_URL=postgres://attacker/");
    expect(logs).toContain("| DATABASE_URL=postgres://attacker/");
  });

  it("末尾の改行は行数を増やさず、あることだけを述べる", async () => {
    // "a\nb\n" は 2 行 + 末尾改行。素朴な split は空の 3 行目を作り、
    // 行数の申告も 1 つずれる(改行の有無は値の一部なので捨てもしない)
    const logs: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: () => Effect.void,
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "a\nb\n")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(logs[0]).toContain("2 行の値。末尾に改行あり");
    expect(logs).toEqual([logs[0], "| a", "| b"]);
  });

  it("表示する値でも並び順を壊す文字は中和する(名前側と同じ扱い)", async () => {
    // 値は共同編集者が書くので、悪意ある値で他メンバーの端末表示を偽装できる。
    // ANSI だけ潰しても双方向上書き・ゼロ幅は残るため、名前側(displayText)と
    // 同じ一覧で中和されることを固定する — 片方だけ足された状態を作らない
    const logs: string[] = [];
    const errors: string[] = [];
    const capturingIo = Layer.succeed(CliIo, {
      log: (line: string) => {
        logs.push(line);
        return Effect.void;
      },
      logError: (line: string) => {
        errors.push(line);
        return Effect.void;
      },
      readStdin: Effect.succeed(new Uint8Array(0)),
      promptLine: () => Effect.succeed(""),
      envVar: () => undefined,
      agentProfile: () => ({ isAgent: false }),
    });
    const exit = await Effect.runPromiseExit(
      showValues([variable("SECRET", "a\u202Eb\u200Bc\u2028d\u200Ce\nf")]).pipe(
        Effect.provide(
          Layer.mergeAll(
            capturingIo,
            Layer.succeed(AgentProfileRef, { isAgent: false }),
            Stdio.layerTest({
              stdinIsTerminal: Effect.succeed(true),
              stdoutIsTerminal: Effect.succeed(true),
            }),
          ),
        ),
      ),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    // ZWNJ(綴りに要る)と改行(PEM 等の正当な値)は残す。改行を含む値は
    // 2 行目以降に印を付けて出す(値の側で `NAME=value` の行を偽造させない)
    expect(logs).toEqual([
      'SECRET= (2 行の値。以下の各行の先頭 "| " は maruhi が付けた印です)',
      "| a\uFFFDb\uFFFDc\uFFFDd\u200Ce",
      "| f",
    ]);
    // 中和したことは黙らない: 表示と実際の値が別物であることを名指しする
    // (値そのものは警告に載せない)
    expect(errors.join("\n")).toContain("SECRET");
    expect(errors.join("\n")).toContain("実際の値と一致しない");
  });
});

describe("buildInjectionEnv", () => {
  it("名前・値を検証して env map を作る", async () => {
    const env = await Effect.runPromise(
      buildInjectionEnv([variable("A", "1"), variable("B_2", "two")]),
    );
    expect(env).toEqual({ A: "1", B_2: "two" });
  });

  it("`=` を含む名前・NUL を含む値・不正 UTF-8 を拒否する(値はエラーに出さない)", async () => {
    const badName = await Effect.runPromiseExit(buildInjectionEnv([variable("A=B", "x")]));
    expect(Exit.isFailure(badName)).toBe(true);
    const nulName = await Effect.runPromiseExit(buildInjectionEnv([variable("A\0B", "x")]));
    expect(Exit.isFailure(nulName)).toBe(true);
    const withNul = await Effect.runPromiseExit(buildInjectionEnv([variable("SECRET_A", "a\0b")]));
    expect(Exit.isFailure(withNul)).toBe(true);
    expect(JSON.stringify(withNul)).not.toContain("a\\u0000b");
    const invalidUtf8 = await Effect.runPromiseExit(
      buildInjectionEnv([variable("SECRET_B", new Uint8Array([0xff, 0xfe]))]),
    );
    expect(Exit.isFailure(invalidUtf8)).toBe(true);
  });

  it("bash 関数インポート名(BASH_FUNC_x%% / x())を拒否する(shellshock 系)", async () => {
    for (const name of ["BASH_FUNC_ls%%", "evil()", "a b", "my-secret", "1abc"]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("英数字と _ のみ");
    }
  });

  it("大文字小文字の違いだけの名前の衝突を拒否する(Windows の非区別対策)", async () => {
    const exit = await Effect.runPromiseExit(
      buildInjectionEnv([variable("Secret_A", "x"), variable("SECRET_A", "y")]),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("大文字小文字の違い");
  });

  it("実行制御系の環境変数名(PATH / LD_* / NODE_OPTIONS 等)への注入を拒否する", async () => {
    // "Path" は Windows の大文字小文字非区別への防衛(大文字化して比較)
    for (const name of [
      "PATH",
      "Path",
      "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
      "NODE_OPTIONS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "SSLKEYLOGFILE",
      "BUN_OPTIONS",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("実行制御系");
    }
  });
});

const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("decodeValueText(値デコード方針の一本化)", () => {
  it("有効な UTF-8(改行・タブ込み)はそのまま返し、不正 UTF-8 は null を返す", () => {
    expect(decodeValueText(new TextEncoder().encode("multi\nline\tvalue"))).toBe(
      "multi\nline\tvalue",
    );
    // --show / run 共通の fatal 方針: 置換文字で偽装せず、呼び出し側が明示エラーにする
    expect(decodeValueText(new Uint8Array([0xff, 0xfe]))).toBeNull();
  });
});

describe("toCliError(サーバー由来文字列の端末中和)", () => {
  it("エラー Schema の自由文字列 ID を中和する", () => {
    // ワイヤ上無制約の Schema.String 列(悪意あるサーバーが ANSI/改行を埋められる)
    const notFound = toCliError(
      new ProjectNotFoundError({ projectId: "x\u001b[31mred\u001b[0m\nfake" }),
    );
    expect(notFound.message).not.toContain("\u001b");
    expect(notFound.message).not.toContain("\n");
    expect(notFound.message).toContain("x\uFFFD[31mred\uFFFD[0m\uFFFDfake");
  });

  it("宣言を尽くした先の未知エラーは message を出さず、型の名前だけを添える", () => {
    // 型付きクライアントの失敗 3 種(宣言済みエラー / HttpClientError /
    // SchemaError)はすべて写像済みなので、ここへ来るのは本当の未知だけ。
    // message は応答本文の断片を含みうるため、中和ではなく**出さない**
    const unknown = toCliError(new Error("boom sk-live-SUPER-SECRET \u001b]0;pwned\u0007"));
    expect(unknown.message).toBe("予期しないエラー(Error)");
    expect(unknown.message).not.toContain("sk-live-SUPER-SECRET");
    expect(unknown.message).not.toContain("\u001b");
  });

  it("接続失敗は専用の写像が受け持つ(未知へ落ちない)", () => {
    // 「未知 fallback を絞ると接続失敗の手掛かりが消える」ことにならない根拠:
    // 転送レベルの失敗は HttpClientError の写像が名前付きで説明する
    const transport = new HttpClientError.HttpClientError({
      reason: new HttpClientError.TransportError({
        request: HttpClientRequest.get("https://maruhi.example/chain"),
        cause: new Error("connect ECONNREFUSED 127.0.0.1:9"),
      }),
    });
    const rendered = toCliError(transport);
    expect(rendered.message).toContain("サーバーへの接続に失敗しました");
    expect(rendered.message).not.toContain("予期しないエラー");
    // 下位の cause の文面(ホスト・ポート等)は素通ししない
    expect(rendered.message).not.toContain("ECONNREFUSED");
  });

  it("応答のスキーマ不一致は「場所と期待」だけを出す(値は出さない)", async () => {
    // 上流(effect rc.109)の整形は期待した型と場所しか出さない。応答本文には
    // 変数名も暗号文も載るので、**値を含む整形に変わったらここが落ちる**
    const Payload = Schema.Struct({ version: Schema.Number });
    const exit = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(Payload)({ version: "sk-live-SUPER-SECRET" }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    if (!Exit.isFailure(exit)) return;
    const rendered = toCliError(Cause.squash(exit.cause));
    expect(rendered.message).toContain("スキーマと一致しないデータがあります");
    expect(rendered.message).toContain("Expected number");
    expect(rendered.message).toContain('["version"]');
    expect(rendered.message).not.toContain("sk-live-SUPER-SECRET");
    // 同じチャネルにリクエストの encode 失敗も流れてくる(向きは型から分からない)
    // ので、誘導先は両向きを並べる。サーバー原因への一方的な誘導へ戻ったら落ちる
    expect(rendered.message).toContain("指定した値");
    // 改行は 1 行へ畳んでから中和する(置換文字で読めなくならない)
    expect(rendered.message).not.toContain("\uFFFD");
  });
});

describe("normalizeStdinValue", () => {
  it("末尾の改行 1 つ(LF / CRLF)のみ除去する", () => {
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\r\n")))).toBe("v");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v\n\n")))).toBe("v\n");
    expect(decode(normalizeStdinValue(new TextEncoder().encode("v")))).toBe("v");
  });
});

describe("cryptoBackendUsable", () => {
  it("動く環境では true(破損の診断を環境のせいにしない)", async () => {
    // この判定は「鍵が読めない」原因が鍵か環境かを分ける。動く環境で false を
    // 返すと、本当に壊れたレコードの診断まで「環境が非対応です・消さないで
    // ください」に化け、唯一の復旧手順(手で消す)へ辿り着けなくなる
    expect(await Effect.runPromise(cryptoBackendUsable())).toBe(true);
  });

  it("環境起因の共通文言は「何が無事か」を含まない(経路ごとに違うため)", () => {
    // 保存済みの鍵を指せるのはキーチェーン経路だけ。recover / generate は
    // まだ何も保存していないので、共通部分がここまで書くと無い物を指す
    expect(unsupportedCryptoCause).not.toContain("消さないで");
    expect(unsupportedCryptoCause).not.toContain("保存");
    // キーチェーン経路の文言だけが「消さないでください」を持つ
    expect(unsupportedCryptoMessage).toContain("消さないでください");
  });
});

describe("MARUHI_TOKEN 環境変数経路", () => {
  it("キーチェーンなしでも /auth/me で userId を解決して動く", async () => {
    const user = await makeTestUser("user-env-0001");
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        expect(request.headers["authorization"]).toBe("Bearer maruhi_pat_env");
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    // key show は session 解決 + master 鍵を要求する。master 鍵がないため
    // エラーになるが、セッション解決(/auth/me)自体は通ることを検証する
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("master 鍵がありません");
  });

  it("環境変数がキーチェーンより優先される", async () => {
    const user = await makeTestUser("user-env-0001");
    let presented = "";
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", (request) => {
        presented = String(request.headers["authorization"]);
        return { status: 200, json: { userId: user.userId, orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_keychain", userId: user.userId, tokenId: "tok_1" }),
    );
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(presented).toBe("Bearer maruhi_pat_env");
  });

  it("/auth/me が 401 なら案内メッセージで失敗する", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 401, json: { _tag: "Unauthorized" } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN での認証に失敗");
  });

  it("空白だけの MARUHI_TOKEN は未設定として扱う(空トークンで往復させない)", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    // 判定を trim 後の値で行わないと、`Bearer `(空)を送ってから 401 になり、
    // 「失効・スコープ・接続先を確認してください」という別原因の案内へ落ちる
    env.setEnvVar("MARUHI_TOKEN", " \n");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(hit).toBe(false);
    expect(env.errors.join("\n")).toContain("ログインしていません");
  });

  it("MARUHI_TOKEN_ORIGIN 未指定なら MARUHI_TOKEN を使わず案内する", async () => {
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({ status: 200, json: { userId: "u", orgs: [] } })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("MARUHI_TOKEN_ORIGIN で対象サーバー origin を指定");
  });

  it("MARUHI_TOKEN_ORIGIN の形式が不正なら実行の失敗(1)として直し先を示す", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // 環境変数の値はコマンドラインの打ち間違いではないので usage(2)にせず、
    // 直す先(環境変数)を言って 1 で終わる
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "notaurl");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    const text = env.errors.join("\n");
    expect(text).toContain("MARUHI_TOKEN_ORIGIN 環境変数 を直してください");
    // 値そのものは返さない(認証情報が埋まった URL を書かれる形もある)
    expect(text).not.toContain("notaurl");
    expect(hit).toBe(false);
  });

  it("MARUHI_TOKEN_ORIGIN が接続先と一致しなければトークンを送らない", async () => {
    let hit = false;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => {
        hit = true;
        return { status: 200, json: { userId: "u", orgs: [] } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", "https://other.example");
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("一致しません");
    // トークンは接続先へ送信されない
    expect(hit).toBe(false);
  });
});

describe("入力検証と defect の扱い", () => {
  it("不正なプロジェクト ID / 環境 ID は早期にエラーになる", async () => {
    const env = await makeTestEnv();
    await seedConfig(env, { server: "https://maruhi.example", defaultEnvironment: "dev" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // 書き方の誤りは usage エラー(2)。指定値そのものは返さない
    expect(await runCli(["pull", "--project", "not-hex"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("プロジェクト ID の形式が正しくありません");
    expect(env.errors.join("\n")).not.toContain("not-hex");
    const env2 = await makeTestEnv();
    await seedConfig(env2, {
      server: "https://maruhi.example",
      defaultProject: "ab".repeat(32),
    });
    env2.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // 環境 ID の形式検証はネットワークアクセス(セッション解決)より先に走る
    expect(await runCli(["pull", "--env", "!bad"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("環境 ID の形式が正しくありません");
    expect(env2.errors.join("\n")).not.toContain("!bad");
  });

  it("config 由来の不正な ID は打ち間違いではなく、直す先を示して 1 で落ちる", async () => {
    const env = await makeTestEnv();
    // コマンドラインには何も書いていないので、2(書き方の誤り)で報告すると
    // 「直す場所が無いのに usage エラー」になる
    await seedConfig(env, { server: "https://maruhi.example", defaultProject: "not-hex" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["pull", "--env", "dev"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("config の defaultProject を直してください");
  });

  it("defect(バグ由来の throw)は usage エラー(2)でなく 1 で報告される", async () => {
    const env = await makeTestEnv();
    env.breakConfigLoadWithDefect();
    expect(await runCli(["config", "get", "server"], env.layer)).toBe(1);
    // 型の名前だけを添える形を**厳密に**固定する(部分一致だけだと
    // `internal error: <上流の message>` に戻しても通ってしまい、規律の歯が無くなる)
    expect(env.errors.join("\n")).toContain("maruhi: internal error (Error)");
    // defect の message は出さない — 打たれた値を埋め込んだ文面でも到達しうる
    expect(env.errors.join("\n")).not.toContain("config load defect");
  });
});

describe("操作専用オプションの適用可否(optionRestrictedTo)", () => {
  // 実際の ENV_ACTION_FLAGS は互いに素なので、**共有**の形はコマンドラインから
  // 到達できない。表を差し替えてここで固定する(将来オプションを共有させた
  // ときに、共有元のどちらでも拒否される回帰を止める)
  const ACTIONS = ["create", "rotate", "diff"] as const;
  const FLAGS = {
    create: new Set(["name"]),
    // `name` は create と rotate が**共有**する想定の表
    rotate: new Set(["reason", "name"]),
    diff: new Set<string>(),
  };

  it("どの操作にも属さないオプションは全操作で使える(--server / --project の形)", () => {
    expect(optionRestrictedTo(ACTIONS, FLAGS, "diff", "server")).toBeNull();
  });

  it("その操作自身が持つオプションは使える", () => {
    expect(optionRestrictedTo(ACTIONS, FLAGS, "rotate", "reason")).toBeNull();
  });

  it("持たない操作では、使える操作の一覧を返す(診断で名指しするため)", () => {
    expect(optionRestrictedTo(ACTIONS, FLAGS, "diff", "reason")).toEqual(["rotate"]);
    expect(optionRestrictedTo(ACTIONS, FLAGS, "create", "reason")).toEqual(["rotate"]);
  });

  it("複数の操作が共有するオプションは、共有元のどちらでも使える", () => {
    // 「**他の**操作の分」だけを数えると、共有元の両方でこれが非 null になり、
    // 宣言したとおりに使えないオプションが生まれる
    expect(optionRestrictedTo(ACTIONS, FLAGS, "create", "name")).toBeNull();
    expect(optionRestrictedTo(ACTIONS, FLAGS, "rotate", "name")).toBeNull();
    // 共有していない操作では、持ち主がすべて挙がる
    expect(optionRestrictedTo(ACTIONS, FLAGS, "diff", "name")).toEqual(["create", "rotate"]);
  });
});
