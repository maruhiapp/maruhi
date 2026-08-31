// 細部のユニットテスト: キーチェーンレコードの codec、run の注入検証、
// stdin 正規化、MARUHI_TOKEN 環境変数経路、サーバー URL 解決。
// (CLI ログインのポーリング規則は login.test.ts — AUTH_SPEC §4)

import { ProjectNotFoundError, UnauthorizedError } from "@maruhi/api-schema";
import { Cause, Effect, Exit, Layer, Redacted, Schema, Stdio } from "effect";
import { HttpClientError, HttpClientRequest } from "effect/unstable/http";
import { afterEach, describe, expect, it } from "vitest";

import { AgentProfileRef } from "../src/agent-gate.ts";
import { runCli } from "../src/cli.ts";
import {
  decodeValueText,
  formatUtcDate,
  formatUtcMinutes,
  formatUtcSeconds,
  showValues,
} from "../src/display.ts";
import { toCliError } from "../src/failure.ts";
import { CliIo } from "../src/io.ts";
import {
  Keychain,
  masterKeyEntryName,
  parseStoredMasterKey,
  parseStoredToken,
  serializeStoredToken,
  tokenEntryName,
} from "../src/keychain.ts";
import type { DecryptedVariable } from "../src/pull.ts";
import { normalizeStdinValue } from "../src/push.ts";
import { buildChildEnvironment, buildInjectionEnv, ProcessRunner, runOp } from "../src/run.ts";
import {
  cryptoBackendUsable,
  resolveServerOrigin,
  storeMasterKeyGuarded,
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

describe("total timestamp formatters", () => {
  it("Date 範囲外・非有限でも RangeError にせず明示表示へ劣化する(B1/B4/B5)", () => {
    expect(formatUtcSeconds(0)).toBe("1970-01-01 00:00:00 UTC");
    expect(formatUtcMinutes(0)).toBe("1970-01-01 00:00 UTC");
    expect(formatUtcDate(0)).toBe("1970-01-01");
    // Date 範囲内でも年 0〜9999 の外(toISOString が拡張年形式を返す領域)は
    // 固定 slice が黙って別位置を切るため、明示劣化に倒す(レビューループ 1)
    expect(formatUtcSeconds(Date.UTC(9999, 11, 31, 23, 59, 59))).toBe("9999-12-31 23:59:59 UTC");
    for (const bad of [
      253_402_300_800_000, // 年 10000
      -62_167_219_200_001, // 年 -1
      8_640_000_000_000_000,
      -1e300,
      Number.POSITIVE_INFINITY,
      Number.NaN,
    ]) {
      expect(formatUtcSeconds(bad)).toContain("invalid timestamp");
      expect(formatUtcMinutes(bad)).toContain("invalid timestamp");
      expect(formatUtcDate(bad)).toContain("invalid timestamp");
    }
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

describe("storeMasterKeyGuarded(上書き検出つき保存 — deepsec R2)", () => {
  const ENTRY = masterKeyEntryName("https://maruhi.test", "user-1");

  /**
   * 並行実行を模す Keychain: `onSet` で「自分の書き込みの前後に他プロセスが
   * 書いた」状況を注入する。OS キーチェーンに条件付き書き込みが無い以上、
   * 固定できるのは「後勝ちを検出して失敗すること」である
   */
  const fakeKeychain = (input: {
    readonly initial?: string;
    readonly onSet?: (store: Map<string, string>) => void;
  }) => {
    const store = new Map<string, string>();
    if (input.initial !== undefined) {
      store.set(ENTRY, input.initial);
    }
    return {
      store,
      layer: Layer.succeed(Keychain, {
        get: (name: string) => Effect.sync(() => store.get(name) ?? null),
        set: (name: string, value: string) =>
          Effect.sync(() => {
            store.set(name, value);
            input.onSet?.(store);
          }),
        remove: (name: string) => Effect.sync(() => void store.delete(name)),
      }),
    };
  };

  it("空のエントリへは保存できる", async () => {
    const keychain = fakeKeychain({});
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(keychain.store.get(ENTRY)).toBe("record-mine");
  });

  it("判定と書き込みの間に現れたレコードは上書きしない", async () => {
    // ensureNoStoredMasterKey の後で他プロセスが書いた形。素の set は
    // 後勝ちで相手の鍵を黙って消していた
    const keychain = fakeKeychain({ initial: "record-other" });
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("at the same time");
    expect(keychain.store.get(ENTRY)).toBe("record-other");
  });

  it("書き込み直後に上書きされたら失敗する(リカバリー発行へ進ませない)", async () => {
    // 自分の書き込みの直後に他プロセスが書いた形。読み戻しが自分のレコードで
    // ないことを検出し、破棄された鍵のリカバリーブロブ登録を防ぐ
    const keychain = fakeKeychain({
      onSet: (store) => store.set(ENTRY, "record-other"),
    });
    const exit = await Effect.runPromiseExit(
      storeMasterKeyGuarded(ENTRY, "record-mine").pipe(Effect.provide(keychain.layer)),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("no recovery code was issued");
  });
});

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
    stderrIsTerminal: () => true,
    openBrowser: () => Effect.succeed(false),
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
    expect(JSON.stringify(piped)).toContain("only allowed on an interactive terminal");
    expect(JSON.stringify(piped)).not.toContain("plaintext-value");

    const headless = await showOne({ stdinIsTerminal: false, stdoutIsTerminal: true });
    expect(Exit.isFailure(headless)).toBe(true);

    const agent = await showOne({
      agent: { isAgent: true, name: "claude" },
      stdinIsTerminal: true,
      stdoutIsTerminal: true,
    });
    expect(Exit.isFailure(agent)).toBe(true);
    expect(JSON.stringify(agent)).toContain("AI agent environment was detected");
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
      stderrIsTerminal: () => true,
      openBrowser: () => Effect.succeed(false),
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
      stderrIsTerminal: () => true,
      openBrowser: () => Effect.succeed(false),
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
    expect(logs[0]).toContain("2-line value with a trailing newline");
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
      stderrIsTerminal: () => true,
      openBrowser: () => Effect.succeed(false),
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
      'SECRET= (a 2-line value; the leading "| " on each line below is a marker added by maruhi)',
      "| a\uFFFDb\uFFFDc\uFFFDd\u200Ce",
      "| f",
    ]);
    // 中和したことは黙らない: 表示と実際の値が別物であることを名指しする
    // (値そのものは警告に載せない)
    expect(errors.join("\n")).toContain("SECRET");
    expect(errors.join("\n")).toContain("do not match the actual values");
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
      expect(JSON.stringify(exit)).toContain("only alphanumerics and _");
    }
  });

  it("大文字小文字の違いだけの名前の衝突を拒否する(Windows の非区別対策)", async () => {
    const exit = await Effect.runPromiseExit(
      buildInjectionEnv([variable("Secret_A", "x"), variable("SECRET_A", "y")]),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("differing only by letter case");
  });

  it("execution-controlの環境変数名(PATH / LD_* / NODE_OPTIONS 等)への注入を拒否する", async () => {
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
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
  });

  it("M2 で追加した POSIX / Windows の実行制御名への注入も拒否する", async () => {
    for (const name of [
      // POSIX: rc / 設定ディレクトリの差し替えとプロンプト評価
      "HOME",
      "home", // 大文字化比較(Windows の非区別)への防衛
      "USERPROFILE",
      "XDG_CONFIG_HOME",
      "XDG_DATA_HOME",
      "PROMPT_COMMAND",
      "PS1",
      "PS4",
      "SHELLOPTS",
      "BASHOPTS",
      "NODE_REPL_EXTERNAL_MODULE",
      "PYTHONINSPECT",
      // Windows: 実行解決の差し替え
      "PATHEXT",
      "COMSPEC",
      "SYSTEMROOT",
      "SystemRoot",
      "WINDIR",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
  });

  it("R3 で追加した「別プログラムを起動する」名前への注入も拒否する", async () => {
    for (const name of [
      // 子プロセスが起動する先(pager / editor / browser / askpass)
      "LESSOPEN",
      "LESSCLOSE",
      "PAGER",
      "MANPAGER",
      "EDITOR",
      "VISUAL",
      "BROWSER",
      "SSH_ASKPASS",
      "SUDO_ASKPASS",
      // インタプリタの初期化フックとモジュール探索
      "LUA_INIT",
      "LUA_PATH",
      "LUA_CPATH",
      "PSModulePath", // 大文字化比較(Windows の非区別)への防衛
      // ローダ・補助データの探索先
      "GLIBC_TUNABLES",
      "MALLOC_CONF",
      "LOCPATH",
      "NLSPATH",
      "TERMINFO",
      "TERMCAP",
      // shell autoload / TLS trust / Python user-site (08-27 follow-up)
      "FPATH",
      "KSH_ENV",
      "SSL_CERT_FILE",
      "SSL_CERT_DIR",
      "CURL_CA_BUNDLE",
      "REQUESTS_CA_BUNDLE",
      "AWS_CA_BUNDLE",
      "PYTHONUSERBASE",
      "PYTHONWARNINGS",
      // Windows home/config・shell探索・npm設定(08-27追加再検証)
      "HOMEDRIVE",
      "HOMEPATH",
      "APPDATA",
      "LOCALAPPDATA",
      "CDPATH",
      "TERMINFO_DIRS",
      "NPM_CONFIG_USERCONFIG",
      "NPM_CONFIG_GLOBALCONFIG",
      "npm_config_script_shell", // individual name + case-insensitive
      "NPM_CONFIG_SHELL",
      "NPM_CONFIG_NODE_OPTIONS",
      "NPM_CONFIG_PREFIX",
      "NPM_CONFIG_CAFILE",
      "NPM_CONFIG_IGNORE_SCRIPTS",
      "NPM_CONFIG_NODE_GYP",
      "npm_config_python",
      "NPM_CONFIG_INIT_MODULE",
      "NPM_CONFIG_EDITOR",
      "NPM_CONFIG_VIEWER",
      "NPM_CONFIG_STRICT_SSL",
      "NPM_CONFIG_CA",
      "NPM_CONFIG_GIT",
      // interpreter / runtime hooks that do not need an attacker-controlled rc file
      "PYTHONBREAKPOINT",
      "PYTHONEXECUTABLE",
      "PYTHON",
      "NODE_GYP_FORCE_PYTHON",
      "JDK_JAVA_OPTIONS",
      "DOTNET_STARTUP_HOOKS",
      "GEM_HOME",
      "GEM_PATH",
      "HOSTALIASES",
      "CORECLR_ENABLE_PROFILING",
      "COR_PROFILER_PATH",
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
    // 包括 prefix 拒否は採らない裁定(M2)の固定: NODE_ENV 等の正当な変数は通る
    const allowed = await Effect.runPromise(
      buildInjectionEnv([
        variable("NODE_ENV", "production"),
        variable("BUN_INSTALL", "x"),
        // npm registry auth は maruhi run の正当な secret 注入用途。
        // NPM_CONFIG_ 全体を拒否せず、上の実行制御キーだけを個別拒否する
        variable("NPM_CONFIG__AUTH", "credential"),
        variable("NPM_CONFIG__AUTHTOKEN", "credential"),
        variable("NPM_CONFIG_REGISTRY", "https://registry.example"),
      ]),
    );
    expect(Object.keys(allowed).toSorted()).toEqual([
      "BUN_INSTALL",
      "NODE_ENV",
      "NPM_CONFIG_REGISTRY",
      "NPM_CONFIG__AUTH",
      "NPM_CONFIG__AUTHTOKEN",
    ]);
  });

  it("maruhi 自身の名前空間(MARUHI_*)への注入を拒否する(deepsec S3)", async () => {
    // resolveSession は MARUHI_TOKEN をキーチェーンより先に見るため、この名前の
    // 変数を作れる共同メンバーは、被害者の `maruhi run -- make deploy` の中の
    // 入れ子 `maruhi` を自分のトークンで認証させられる。予約名前空間なので
    // 個別名ではなく prefix ごと塞ぐ(将来 MARUHI_* を増やしても穴が再発しない)
    for (const name of [
      "MARUHI_TOKEN",
      "MARUHI_TOKEN_ORIGIN",
      "maruhi_token", // 大文字化比較(Windows の非区別)への防衛
      "MARUHI_FUTURE_KNOB", // 未知の MARUHI_* も prefix で覆う
    ]) {
      const exit = await Effect.runPromiseExit(buildInjectionEnv([variable(name, "x")]));
      expect(Exit.isFailure(exit)).toBe(true);
      expect(JSON.stringify(exit)).toContain("execution-control");
    }
    // 予約名前空間の外は通る(MARUHI で始まるだけの別名を巻き込まない)
    const allowed = await Effect.runPromise(
      buildInjectionEnv([variable("MARUHISECRET", "x"), variable("APP_MARUHI_TOKEN", "y")]),
    );
    expect(Object.keys(allowed).toSorted()).toEqual(["APP_MARUHI_TOKEN", "MARUHISECRET"]);
  });
});

describe("buildChildEnvironment(deepsec S6)", () => {
  it("親・追加envのMARUHI_*だけをcase-insensitiveに除外する", () => {
    expect(
      buildChildEnvironment(
        {
          PATH: "/usr/bin",
          MARUHI_TOKEN: "maruhi_pat_parent",
          maruhi_token_origin: "https://maruhi.test",
          MARUHI_FUTURE_AUTH: "reserved",
          APP_MARUHI_TOKEN: "application-value",
          UNDEFINED_VALUE: undefined,
        },
        {
          SECRET: "injected-value",
          MARUHI_TOKEN: "must-not-pass-even-from-extra-env",
        },
      ),
    ).toEqual({
      PATH: "/usr/bin",
      APP_MARUHI_TOKEN: "application-value",
      SECRET: "injected-value",
    });
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
  it("401 は期限切れ・失効の両方の可能性と再ログインを案内する(AUTH_SPEC §6 — W3a)", () => {
    // 期限切れは失効と同じ 401 に畳まれる(区別はワイヤに出ない)ため、
    // 案内は両方の可能性を言い、次の一手(再ログイン)を示す
    const rendered = toCliError(new UnauthorizedError());
    expect(rendered.message).toContain("expired or revoked");
    expect(rendered.message).toContain("maruhi login");
  });

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
    expect(unknown.message).toBe("Unexpected error (Error)");
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
    expect(rendered.message).toContain("Failed to connect to the server");
    expect(rendered.message).not.toContain("Unexpected error");
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
    expect(rendered.message).toContain("does not match the schema");
    expect(rendered.message).toContain("Expected number");
    expect(rendered.message).toContain('["version"]');
    expect(rendered.message).not.toContain("sk-live-SUPER-SECRET");
    // 同じチャネルにリクエストの encode 失敗も流れてくる(向きは型から分からない)
    // ので、誘導先は両向きを並べる。サーバー原因への一方的な誘導へ戻ったら落ちる
    expect(rendered.message).toContain("values you provided");
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
    // 返すと、本当に壊れたレコードの診断まで「環境が非対応です・do not delete
    // ください」に化け、唯一の復旧手順(手で消す)へ辿り着けなくなる
    expect(await Effect.runPromise(cryptoBackendUsable())).toBe(true);
  });

  it("環境起因の共通文言は「何が無事か」を含まない(経路ごとに違うため)", () => {
    // 保存済みの鍵を指せるのはキーチェーン経路だけ。recover / generate は
    // まだ何も保存していないので、共通部分がここまで書くと無い物を指す
    expect(unsupportedCryptoCause).not.toContain("do not delete");
    expect(unsupportedCryptoCause).not.toContain("stored");
    // キーチェーン経路の文言だけが「do not delete it」を持つ
    expect(unsupportedCryptoMessage).toContain("do not delete it");
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
    expect(env.errors.join("\n")).toContain("No master key");
  });

  it("期限が 14 日以内なら stderr へ事前警告する(裁定 CL — 環境変数経路は /auth/me の自己開示から)", async () => {
    const user = await makeTestUser("user-env-0001");
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: user.userId, orgs: [], tokenExpiresAtMs: Date.now() + 5 * DAY_MS },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Warning: the maruhi token expires on");
    expect(errors).toContain("days left");
    expect(errors).toContain("--show-token");
  });

  it("期限が窓の外なら警告しない(環境変数経路)", async () => {
    const user = await makeTestUser("user-env-0001");
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([
      onRequest("GET", "/auth/me", () => ({
        status: 200,
        json: { userId: user.userId, orgs: [], tokenExpiresAtMs: Date.now() + 60 * DAY_MS },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    await seedConfig(env, { server: server.origin });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    await runCli(["key", "show"], env.layer);
    expect(env.errors.join("\n")).not.toContain("Warning: the maruhi token expires");
  });

  it("キーチェーン経路はレコード保存の期限から無通信で警告し、旧レコード(期限なし)は従来どおり", async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const server = await MockServer.start([]);
    servers.push(server);

    const nearEnv = await makeTestEnv();
    await seedConfig(nearEnv, { server: server.origin });
    nearEnv.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({
        token: "maruhi_pat_keychain",
        userId: "user-0001",
        tokenId: "tok_1",
        expiresAtMs: Date.now() + 3 * DAY_MS,
      }),
    );
    await runCli(["key", "show"], nearEnv.layer);
    const nearErrors = nearEnv.errors.join("\n");
    expect(nearErrors).toContain("Warning: the maruhi token expires on");
    expect(nearErrors).toContain("Re-login with `maruhi login`");
    // 警告は判定に通信を要しない(サーバーへ 1 リクエストも飛ばない)
    expect(server.requests).toHaveLength(0);

    // W3a 前のログインが書いた旧レコード(expiresAtMs なし)は警告なしで動く
    const legacyEnv = await makeTestEnv();
    await seedConfig(legacyEnv, { server: server.origin });
    legacyEnv.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_keychain", userId: "user-0001", tokenId: "tok_1" }),
    );
    await runCli(["key", "show"], legacyEnv.layer);
    expect(legacyEnv.errors.join("\n")).not.toContain("Warning: the maruhi token expires");
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
    const errors = env.errors.join("\n");
    expect(errors).toContain("Authentication with MARUHI_TOKEN failed");
    // W3a 以降、無人環境のこの 401 の最有力原因は期限切れ(裁定 CJ)。
    // 直し先は env 差し替えであることまで案内する(`maruhi login` 単独の
    // キーチェーン向け案内へ退行させない)
    expect(errors).toContain("expired or revoked");
    expect(errors).toContain("update the MARUHI_TOKEN value");
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
    // 「期限切れ・失効かもしれません」という別原因の案内(session.ts の
    // 認証失敗文言)へ落ちる
    env.setEnvVar("MARUHI_TOKEN", " \n");
    env.setEnvVar("MARUHI_TOKEN_ORIGIN", server.origin);
    expect(await runCli(["key", "show"], env.layer)).toBe(1);
    expect(hit).toBe(false);
    expect(env.errors.join("\n")).toContain("Not logged in");
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
    expect(env.errors.join("\n")).toContain(
      "requires MARUHI_TOKEN_ORIGIN to name the target server origin",
    );
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
    expect(text).toContain("fix the MARUHI_TOKEN_ORIGIN env var");
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
    expect(env.errors.join("\n")).toContain("does not match the connection target");
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
    expect(env.errors.join("\n")).toContain("Invalid project ID");
    expect(env.errors.join("\n")).not.toContain("not-hex");
    const env2 = await makeTestEnv();
    await seedConfig(env2, {
      server: "https://maruhi.example",
      defaultProject: "ab".repeat(32),
    });
    env2.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    // 環境 ID の形式検証はネットワークアクセス(セッション解決)より先に走る
    expect(await runCli(["pull", "--env", "!bad"], env2.layer)).toBe(2);
    expect(env2.errors.join("\n")).toContain("Invalid environment ID");
    expect(env2.errors.join("\n")).not.toContain("!bad");
  });

  it("config 由来の不正な ID は打ち間違いではなく、直す先を示して 1 で落ちる", async () => {
    const env = await makeTestEnv();
    // コマンドラインには何も書いていないので、2(書き方の誤り)で報告すると
    // 「直す場所が無いのに usage エラー」になる
    await seedConfig(env, { server: "https://maruhi.example", defaultProject: "not-hex" });
    env.setEnvVar("MARUHI_TOKEN", "maruhi_pat_env");
    expect(await runCli(["pull", "--env", "dev"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("fix defaultProject in your config");
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
