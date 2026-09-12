// `maruhi agent` — セッション内メモリ鍵保持(KL2。ssh-agent 型)。
//
// OS キーチェーンが無い環境(Codespaces / devcontainer / WSL / 素の Linux)で、
// maruhi トークンと master 秘密鍵を**このプロセスのメモリにだけ**持つ。
// `maruhi agent -- <command>` は子(通常はシェル)を起動し、その子とその子孫の
// maruhi は unix ドメインソケット越しにこのプロセスへ読み書きする。子が終われば
// メモリを捨ててソケットを消し、子の終了コードで終わる(ssh-agent の
// `ssh-agent <command>` 形。デタッチして残る形は採らない — 親を失った常駐は
// 生存期間の上限が無い漏れ方になる。KL1 のレシピ `dbus-run-session -- bash` と
// 同じ入れ子シェルの形に揃える)。
//
// 設計裁定(integration-options.md 補足 12 の L2 + L3):
// - **Keychain サービスの差し替え**として実装する。`MARUHI_AGENT_SOCK` が
//   あれば live 層は OS キーチェーンの代わりに {@link makeAgentKeychain} を
//   採用する(live.ts)。よって login / key generate / key recover / pull /
//   run / push は無変更でこのメモリへ着地する — 「取得 → 復号 → L2 のメモリへ」
//   は recovery.ts を変えずに配線される。既存の制約(リカバリーブロブ取得の
//   レート制限・コード入力は人間の対話端末のみ)もそのまま効く
// - **ディスクに書かない**: 置くのはソケット(inode であってデータではない)
//   だけ。ソケットは `$XDG_RUNTIME_DIR`(無ければ os.tmpdir())配下の
//   mkdtemp ディレクトリ(0700)+ `agent.sock`(0600)。権限境界は同一ユーザー
//   = OS キーチェーン(Secret Service も同一ユーザーの D-Bus)と同等で、
//   これより強い境界はこの層には無い(同一ユーザーのプロセスは本プロセスの
//   メモリも読める)
// - **暗号操作を足さない**: ソケットを流れるのは Keychain サービスと同じ
//   レコード文字列。ローカル・同一ユーザー・ディスクを通らない経路なので、
//   仕様(CRYPTO_SPEC)に無い封緘を発明しない
// - **生存期間 = 子の寿命**。TTL フラグは付けない(`key recover` の取得制限
//   〔1 時間 5 回〕と衝突して再復元を強いる)。失効はシェルを抜ける
//   (メモリごと消える)か `maruhi logout`(agent から消し、サーバーで失効)
// - **エージェント環境(ADR-0016 決定 7)のゲートは足さない**: agent は保持
//   機構であって値の表示経路ではない。表示・儀式のゲートは各コマンド側に
//   据え置く。`maruhi run` の子が `MARUHI_*` を受け取らない既存規則
//   (run.ts)により `MARUHI_AGENT_SOCK` も子へ渡らない(決定 5 と同じ帰結)
//
// プロトコル(1 接続 1 要求。改行区切り JSON):
//   要求  {"v":1,"op":"get"|"remove","name":"…"} / {"v":1,"op":"set","name":"…","value":"…"}
//         {"v":1,"op":"list"}(保持しているエントリ名 — `maruhi agent status` 用。値は運ばない)
//   応答  {"ok":true,"value":"…"|null} / {"ok":true,"names":[…]} / {"ok":false,"error":"…"}
// 版が合わない・壊れた要求は `ok:false` で返す(黙って解釈しない)。
//
// ソケットは node:net(Bun / Node の両方で unix ソケットの listen / connect が
// 動くことを実測)。vitest(Node)でサーバーとクライアントを実ソケットで
// 検査できる。判定材料(環境変数)は CliIo 経由で受け取る。

import { chmod, lstat, mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { KeychainShape } from "./keychain.ts";
import { logWarning } from "./notice.ts";
import { ProcessRunner } from "./run.ts";

/** Environment variable that carries the agent socket path to the session's commands. */
export const AGENT_SOCKET_ENV = "MARUHI_AGENT_SOCK";

/** Wire protocol version (a mismatch is refused, never reinterpreted). */
const AGENT_PROTOCOL_VERSION = 1;

/**
 * 1 要求 / 1 応答の上限。運ぶのはキーチェーンのレコード(トークン ≈ 200 B、
 * master 鍵 ≈ 500 B)なので桁で余裕がある。上限が無いと壊れた相手に
 * メモリを食い潰される。
 */
const MAX_MESSAGE_BYTES = 64 * 1024;

/** 接続・応答待ちの上限(応答しない agent で CLI をハングさせない)。 */
const IO_TIMEOUT_MS = 5_000;

const SOCKET_FILE_NAME = "agent.sock";

/** One request to the agent (mirrors {@link KeychainShape}, plus `list` for status). */
export type AgentRequest =
  | { readonly v: 1; readonly op: "get" | "remove"; readonly name: string }
  | { readonly v: 1; readonly op: "set"; readonly name: string; readonly value: string }
  | { readonly v: 1; readonly op: "list" };

/** One response from the agent. */
export type AgentResponse =
  | { readonly ok: true; readonly value: string | null }
  | { readonly ok: true; readonly names: readonly string[] }
  | { readonly ok: false; readonly error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parses one request line; null when malformed or of another protocol version. */
export function parseAgentRequest(line: string): AgentRequest | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== AGENT_PROTOCOL_VERSION) {
    return null;
  }
  if (value["op"] === "list") {
    return { v: 1, op: "list" };
  }
  const name = value["name"];
  if (typeof name !== "string" || name.length === 0) {
    return null;
  }
  const op = value["op"];
  if (op === "get" || op === "remove") {
    return { v: 1, op, name };
  }
  if (op === "set" && typeof value["value"] === "string") {
    return { v: 1, op, name, value: value["value"] };
  }
  return null;
}

/** Parses one response line; null when malformed. */
export function parseAgentResponse(line: string): AgentResponse | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value)) {
    return null;
  }
  if (value["ok"] === true && (typeof value["value"] === "string" || value["value"] === null)) {
    return { ok: true, value: value["value"] };
  }
  const names = value["names"];
  if (
    value["ok"] === true &&
    Array.isArray(names) &&
    names.every((name) => typeof name === "string")
  ) {
    return { ok: true, names: names as string[] };
  }
  if (value["ok"] === false && typeof value["error"] === "string") {
    return { ok: false, error: value["error"] };
  }
  return null;
}

/** Encodes a request as one line (the wire form). */
export function encodeAgentRequest(request: AgentRequest): string {
  return `${JSON.stringify(request)}\n`;
}

/** Encodes a response as one line (the wire form). */
function encodeAgentResponse(response: AgentResponse): string {
  return `${JSON.stringify(response)}\n`;
}

/**
 * Applies one request to the in-memory store. 純関数に切り出してあるのは、
 * ソケットの都合(分割到着・切断)と意味論を分けて検査するため。
 */
export function handleAgentRequest(
  store: Map<string, string>,
  request: AgentRequest,
): AgentResponse {
  switch (request.op) {
    case "get":
      return { ok: true, value: store.get(request.name) ?? null };
    case "set":
      store.set(request.name, request.value);
      return { ok: true, value: null };
    case "remove":
      store.delete(request.name);
      return { ok: true, value: null };
    case "list":
      // 名前だけ(`token::<origin>` / `master::<origin>::<userId>`)。値は運ばない
      return { ok: true, names: [...store.keys()] };
  }
}

/* -------------------------------------------------------------------------- */
/* サーバー(agent プロセス側)                                                 */
/* -------------------------------------------------------------------------- */

/** A running agent socket. */
export interface AgentServer {
  readonly socketPath: string;
  /** Stops listening, drops every held record, and removes the socket. */
  readonly close: () => Promise<void>;
}

/**
 * 1 接続を 1 要求として処理し、応答して閉じる。
 *
 * 要求の 1 行が揃わないまま黙る相手は {@link IO_TIMEOUT_MS} で切る: 切らないと
 * `server.close()`(全接続の終了を待つ)が戻らず、子が終わっても agent が
 * 残る(後始末が走らず、子の終了コードも返せない)。
 */
function serveConnection(store: Map<string, string>, socket: Socket): void {
  let buffered = "";
  let answered = false;
  const answer = (response: AgentResponse): void => {
    answered = true;
    socket.end(encodeAgentResponse(response));
  };
  socket.setEncoding("utf8");
  socket.setTimeout(IO_TIMEOUT_MS, () => {
    socket.destroy();
  });
  socket.on("data", (chunk: string) => {
    if (answered) {
      return;
    }
    buffered += chunk;
    if (Buffer.byteLength(buffered) > MAX_MESSAGE_BYTES) {
      answer({ ok: false, error: "request too large" });
      return;
    }
    const newline = buffered.indexOf("\n");
    if (newline < 0) {
      return;
    }
    const request = parseAgentRequest(buffered.slice(0, newline));
    answer(
      request === null
        ? { ok: false, error: "malformed request (protocol version mismatch?)" }
        : handleAgentRequest(store, request),
    );
  });
  // 相手側(CLI)の切断・書き込み失敗。報告先が無い: 失敗したのは相手の要求で
  // あり、相手は自分の側の失敗を自分で報告する(makeAgentKeychain)。agent の
  // stderr は子シェルと共有する端末なので、ここで書くと利用者の画面を汚す
  // だけになる。無視ではなく「相手が報告する」ので、リスナーは接続を閉じる
  // ことだけを担う
  socket.on("error", () => {
    socket.destroy();
  });
}

/**
 * Starts listening on `<dir>/agent.sock` (mode 0600) with an empty in-memory
 * store. `dir` must already exist and be private to the user (0700).
 */
export function startAgentServer(dir: string): Promise<AgentServer> {
  const socketPath = join(dir, SOCKET_FILE_NAME);
  const store = new Map<string, string>();
  // 開いている接続の台帳。close はこれを切ってから server.close を待つ
  // (server.close は自然に閉じるのを待つだけで、切ってはくれない)
  const connections = new Set<Socket>();
  const server: Server = createServer({ allowHalfOpen: false }, (socket) => {
    connections.add(socket);
    socket.once("close", () => {
      connections.delete(socket);
    });
    serveConnection(store, socket);
  });
  return new Promise<AgentServer>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      // listen の直後に絞る(umask に依存しない)。ディレクトリが 0700 なので
      // この間に他ユーザーが接続できる窓は無い
      chmod(socketPath, 0o600).then(
        () =>
          resolve({
            socketPath,
            close: () =>
              new Promise<void>((done) => {
                // 保持していた記録を先に捨てる(以降の接続は空を見る)。JS の
                // 文字列はゼロ化できないので、参照を切ることが上限
                store.clear();
                server.close(() => {
                  done();
                });
                // 待たずに切る: 終了は子の退出で決まっており、途中の要求を
                // 完了させる義務は無い(相手は自分の側の失敗を自分で報告する)
                for (const socket of connections) {
                  socket.destroy();
                }
              }),
          }),
        (error: unknown) => {
          server.close();
          reject(error);
        },
      );
    });
  });
}

/* -------------------------------------------------------------------------- */
/* クライアント(セッション内の CLI 側 = Keychain サービスの実装)              */
/* -------------------------------------------------------------------------- */

/** 接続はできたが会話が成立しない(応答なし・壊れた応答・版違い)。 */
class AgentProtocolError extends Error {}

/** ソケットが無い・誰も聞いていない(セッションが終わっている)。 */
class AgentGoneError extends Error {}

/** 環境変数が指す先が、自分の agent が作った形をしていない(使わない)。 */
class AgentSocketRejectedError extends Error {}

const GONE_CODES = new Set(["ENOENT", "ECONNREFUSED", "ENOTSOCK", "EACCES"]);

/**
 * 接続する前に、環境変数が指す先を疑う。`MARUHI_AGENT_SOCK` は誰でも
 * (`devcontainer.json` の remoteEnv・`.envrc`・Makefile)差し込めるので、
 * 素直に信じるとトークンと master 鍵の平文をその宛先へ書いてしまう。
 * 自分の agent が作るソケットは「ソケット・自分の所有・0600」で必ず通り、
 * 他ユーザーの物・誰でも触れる物・ただのファイルはここで止まる
 * (同一ユーザーの攻撃者は止められない — OS キーチェーンと同じ境界)。
 */
async function assertTrustedSocket(socketPath: string): Promise<void> {
  let stat: Awaited<ReturnType<typeof lstat>>;
  try {
    stat = await lstat(socketPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? "lstat";
    // 接続側と同じ分類: 無い・辿れない(EACCES 等)は「セッションが終わった」、
    // それ以外は会話が成立しない側。同じ状態が経路で違う話にならないように
    throw GONE_CODES.has(code) ? new AgentGoneError(code) : new AgentProtocolError(code);
  }
  if (!stat.isSocket()) {
    throw new AgentSocketRejectedError("it is not a socket");
  }
  // 自分の uid は `process.getuid`(システムコールのみ)で取る。`os.userInfo()` は
  // passwd を引くので、数値 uid だけのコンテナ(まさにこの機能の対象環境)では
  // 例外になり、本物のソケットまで拒んでしまう。uid を持たないプラットフォーム
  // (Windows は getuid 自体が無い)では所有者の検査を飛ばす — agent の起動は
  // win32 を拒むが、環境変数だけ持ち込まれた場合は live.ts がどの OS でも
  // この実装を選ぶので、ここは到達しうる。`process.*` を読むのは判定材料
  // (端末・エージェント — ADR-0016 決定 7)ではなく所有者の同一性なので、
  // サービス経由にせずここで読む
  const uid = process.getuid?.() ?? -1;
  if (uid >= 0 && stat.uid !== uid) {
    throw new AgentSocketRejectedError("it is not owned by you");
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new AgentSocketRejectedError("other users can access it");
  }
}

async function sendAgentRequest(socketPath: string, request: AgentRequest): Promise<AgentResponse> {
  await assertTrustedSocket(socketPath);
  return new Promise((resolve, reject) => {
    let buffered = "";
    let settled = false;
    const socket = createConnection(socketPath);
    const settle = (outcome: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      outcome();
    };
    const timer = setTimeout(
      () => settle(() => reject(new AgentProtocolError("timeout"))),
      IO_TIMEOUT_MS,
    );
    socket.setEncoding("utf8");
    socket.once("connect", () => {
      socket.write(encodeAgentRequest(request));
    });
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      if (Buffer.byteLength(buffered) > MAX_MESSAGE_BYTES) {
        settle(() => reject(new AgentProtocolError("response too large")));
        return;
      }
      const newline = buffered.indexOf("\n");
      if (newline < 0) {
        return;
      }
      const response = parseAgentResponse(buffered.slice(0, newline));
      settle(() =>
        response === null
          ? reject(new AgentProtocolError("malformed response"))
          : resolve(response),
      );
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      settle(() =>
        reject(
          error.code !== undefined && GONE_CODES.has(error.code)
            ? new AgentGoneError(error.code)
            : new AgentProtocolError(error.code ?? "socket error"),
        ),
      );
    });
    // 応答行の前に閉じられた(agent が落ちた等)
    socket.once("close", () => settle(() => reject(new AgentProtocolError("closed"))));
  });
}

const agentGoneMessage =
  `Cannot connect to the maruhi agent (${AGENT_SOCKET_ENV} points to a socket nobody is listening on). The agent session has ended — start a new one with \`maruhi agent -- <shell>\`, or unset ${AGENT_SOCKET_ENV} to use the OS keychain` as const;

const agentProtocolMessage =
  "The maruhi agent did not answer as expected (a different maruhi version may be running it). Exit the agent session and start a new one with `maruhi agent -- <shell>` using this version" as const;

function agentRequestError(error: unknown): CliError {
  if (error instanceof AgentGoneError) {
    return cliError(agentGoneMessage);
  }
  if (error instanceof AgentSocketRejectedError) {
    return cliError(
      `Refusing to use the agent socket named by ${AGENT_SOCKET_ENV}: ${error.message}. Unset ${AGENT_SOCKET_ENV}, or start a new session with \`maruhi agent -- <shell>\``,
    );
  }
  return cliError(agentProtocolMessage);
}

/**
 * 環境変数が指す agent が生きているか(入れ子判定用)。ソケットが無い・誰も
 * 聞いていないは「終わったセッションの残骸」= 新しく作ってよい。それ以外の
 * 失敗(信用できない宛先・版違い)は理由ごと利用者へ返す。
 */
function probeAgent(socketPath: string): Effect.Effect<"live" | "gone", CliError> {
  return Effect.tryPromise({
    try: () => sendAgentRequest(socketPath, { v: 1, op: "list" }),
    catch: (error) => error,
  }).pipe(
    Effect.map((): "live" => "live"),
    Effect.catch((error) =>
      error instanceof AgentGoneError
        ? Effect.succeed("gone" as const)
        : Effect.fail(agentRequestError(error)),
    ),
  );
}

/** 1 要求を送り、`ok:false`(agent が拒んだ = 版違い)も型付きの失敗に写す。 */
function askAgent(
  socketPath: string,
  request: AgentRequest,
): Effect.Effect<Exclude<AgentResponse, { readonly ok: false }>, CliError> {
  return Effect.tryPromise({
    try: () => sendAgentRequest(socketPath, request),
    catch: agentRequestError,
  }).pipe(
    Effect.flatMap((response) =>
      // agent が拒む要求はこの実装からは出ない(版違いの agent だけ)
      response.ok ? Effect.succeed(response) : Effect.fail(cliError(agentProtocolMessage)),
    ),
  );
}

/**
 * Keychain implementation backed by a running `maruhi agent`. Selected by the
 * production layer when {@link AGENT_SOCKET_ENV} is set (live.ts).
 */
export function makeAgentKeychain(socketPath: string): KeychainShape {
  const ask = (request: AgentRequest): Effect.Effect<string | null, CliError> =>
    askAgent(socketPath, request).pipe(
      Effect.flatMap((response) =>
        "value" in response
          ? Effect.succeed(response.value)
          : // 値の応答以外(names)はこの要求には来ない = 版違いの agent
            Effect.fail(cliError(agentProtocolMessage)),
      ),
    );
  return {
    kind: "agent",
    get: (name) => ask({ v: 1, op: "get", name }),
    set: (name, value) => Effect.asVoid(ask({ v: 1, op: "set", name, value })),
    remove: (name) => Effect.asVoid(ask({ v: 1, op: "remove", name })),
  };
}

/* -------------------------------------------------------------------------- */
/* コマンド本体                                                                 */
/* -------------------------------------------------------------------------- */

/** `maruhi agent` に実行対象が無い(書き方の誤り)。 */
export const AGENT_COMMAND_REQUIRED =
  "Write the command to run inside the agent session after `--` (example: `maruhi agent -- bash`)";

/**
 * ソケットの置き場の親。`$XDG_RUNTIME_DIR` はユーザー専用の tmpfs(0700・
 * ログアウトで消える)なので最適。無ければ os.tmpdir() — 作るディレクトリ
 * 自体を 0700 にするので、共有 /tmp でも他ユーザーからは見えない。
 */
function socketBaseDir(envVar: (name: string) => string | undefined): string {
  const runtime = envVar("XDG_RUNTIME_DIR");
  return runtime !== undefined && runtime.length > 0 ? runtime : tmpdir();
}

/**
 * `maruhi agent -- <command>`: start the socket, run the command with
 * {@link AGENT_SOCKET_ENV} set, and tear everything down when it exits.
 * Returns the command's exit code.
 */
export function agentOp(input: {
  readonly command: readonly string[];
}): Effect.Effect<number, CliError, CliIo | ProcessRunner> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const runner = yield* ProcessRunner;
    // run と同じ: 「引数が 1 つある」ことと「実行対象がある」ことは別
    if (input.command.length === 0 || (input.command[0] ?? "").trim() === "") {
      return yield* Effect.fail(usageError(AGENT_COMMAND_REQUIRED));
    }
    if (platform() === "win32") {
      return yield* Effect.fail(
        cliError(
          "`maruhi agent` is not available on Windows (it needs a Unix domain socket). The Windows Credential Manager needs no setup — use it instead",
        ),
      );
    }
    // 入れ子は拒む: 外側の agent が既に鍵を持っており、内側を作っても空の
    // 保持先が 1 つ増えて「どちらに入ったか」が分からなくなるだけ。ただし
    // **生きている agent だけ**を入れ子とみなす: 親が先に死んでシェルだけ残る
    // (端末多重化・再親化)と環境変数は残骸になり、「新しく始めろ」と
    // 「入れ子は拒む」で行き止まりになる。残骸なら新しく始めてよい
    const existing = io.envVar(AGENT_SOCKET_ENV);
    if (existing !== undefined && existing.length > 0) {
      const state = yield* probeAgent(existing);
      if (state === "live") {
        return yield* Effect.fail(
          cliError(
            `Already inside an agent session (${AGENT_SOCKET_ENV} points to a running agent). Nested agents are refused — use this session, or exit it first`,
          ),
        );
      }
      yield* logWarning(
        `${AGENT_SOCKET_ENV} pointed to an agent session that has already ended; starting a new one (the new value replaces it for this command's children)`,
      );
    }
    const dir = yield* Effect.tryPromise({
      try: () => mkdtemp(join(socketBaseDir(io.envVar), "maruhi-agent-")),
      catch: () =>
        cliError(
          "Cannot create a private directory for the agent socket (under XDG_RUNTIME_DIR, or the temp directory when it is unset)",
        ),
    });
    // 消せなくてもセッションの結果(子の終了コード)は捨てない: ディレクトリは
    // 空か、ソケットの inode だけ(値は入っていない)。無言では飲まず警告する
    const removeDir = Effect.tryPromise({
      try: () => rm(dir, { recursive: true, force: true }),
      catch: () =>
        cliError(`could not remove the agent socket directory (${dir}) — remove it by hand`),
    }).pipe(Effect.catch((error) => logWarning(error.message)));
    return yield* Effect.acquireUseRelease(
      Effect.tryPromise({
        try: () => startAgentServer(dir),
        catch: (error) =>
          cliError(
            `Cannot listen on the agent socket${errnoSuffix(error)}. Nothing was stored; check that the directory is on a filesystem that supports Unix domain sockets`,
          ),
      }).pipe(Effect.onError(() => removeDir)),
      (server) =>
        Effect.gen(function* () {
          // 案内は stderr(子の stdout を汚さない — `maruhi agent -- make` の
          // ような使い方でも出力が混ざらない)
          yield* io.logError(
            "Agent session started: tokens and keys you sign in with or recover here stay in memory only, and are discarded when the command exits",
          );
          return yield* runner.runSession({
            command: input.command,
            env: { [AGENT_SOCKET_ENV]: server.socketPath },
          });
        }),
      (server) => Effect.promise(() => server.close()).pipe(Effect.andThen(removeDir)),
    );
  });
}

/**
 * `maruhi agent status`: この agent セッションが何を保持しているかを名前で示す
 * (値は運ばない・出さない)。セッションの外では失敗し、古い
 * `MARUHI_AGENT_SOCK` はクライアントの終了メッセージがそのまま出る。
 */
export function agentStatusOp(): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const socketPath = io.envVar(AGENT_SOCKET_ENV);
    if (socketPath === undefined || socketPath.length === 0) {
      return yield* Effect.fail(
        cliError(
          `Not inside an agent session (${AGENT_SOCKET_ENV} is not set). Start one with \`maruhi agent -- <shell>\``,
        ),
      );
    }
    const response = yield* askAgent(socketPath, { v: 1, op: "list" });
    if (!("names" in response)) {
      return yield* Effect.fail(cliError(agentProtocolMessage));
    }
    // パスは自分のプロセスが作った物だが、環境変数経由なので表示前に中和する
    yield* io.log(`socket:      ${displayText(socketPath)}`);
    if (response.names.length === 0) {
      yield* io.log("holding:     nothing yet (run `maruhi login` in this session)");
      return;
    }
    for (const name of response.names.toSorted()) {
      yield* io.log(describeEntryName(name));
    }
  });
}

/**
 * エントリ名(keychain.ts の tokenEntryName / masterKeyEntryName)を読める形に
 * する。origin と userId はサーバー由来の自由文字列なので中和して出す。
 */
function describeEntryName(name: string): string {
  const token = /^token::(.+)$/.exec(name);
  if (token !== null) {
    return `token:       ${displayText(token[1] ?? "")}`;
  }
  // 区切りは**最後の** `::`(origin は `http://[::1]:8787` のように `::` を含みうる。
  // userId はサーバー発行の識別子で `::` を含まない)
  const master = /^master::(.+)::(.+)$/.exec(name);
  if (master !== null) {
    return `master key:  ${displayText(master[1] ?? "")} (user ${displayText(master[2] ?? "")})`;
  }
  return `entry:       ${displayText(name)}`;
}

function errnoSuffix(error: unknown): string {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === undefined ? "" : ` (${code})`;
}
