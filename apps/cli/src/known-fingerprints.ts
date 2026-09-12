// 検証済み指紋帳(KF — ROADMAP / integration-options.md §3 補足 17 第 A 巡)。
//
// maruhi の鍵は**ユーザー単位**(1 人 1 master 鍵)なので、一度 12 語の儀式で
// 帯域外確認した相手の指紋は、その鍵が変わらない限り有効であり続ける。CLI が
// 「自分が確認した (origin, user_id) → 指紋」を非機密設定として保持すれば
// (SSH の known_hosts と同じ発想)、同じ相手が関わる次の儀式では 12 語の
// 帯域外読み上げの**再実施**を免除できる。ただし帳の一致は「以前この鍵を
// 確認した」ことしか意味せず、**この受諾・付与への人間の同意を代替しない**:
// ヒット時も受諾単位の明示確認(yes 入力)を残し、エージェント環境では帳を
// auto-pass に使わない(フラグ必須のまま)。さらに帳を使えるのは stdin /
// stdout が対話端末のときだけ(ADR-0016 決定 7 の一次境界と同じ allow-list —
// yes 確認は 12 語儀式と違い盲目的なパイプで通るため、パイプ・CI・未検出
// エージェントでは帳を無効化して完全な儀式へ戻す)。招待リンクは無記名
// (bearer)で受諾者の同一性を運ばないため、帳の一致だけで付与まで自動化
// しない(CRYPTO_SPEC §6.5 の相互確認 UX の範囲内に留める)。
//
// - 内容は公開情報(鍵フィンガープリント)のみ — ディスクレス不変条件と両立
// - **不一致は絶対に自動で通さない**(警告 + 通常の儀式へフォールバック)。
//   鍵の正当な再生成(`maruhi key generate`)があり得るため自動失敗にもしない
// - プロジェクト単位の pins(invites/<projectId>.json)と違い、ユーザー単位・
//   プロジェクト横断が目的なので単一ファイル(<config dir>/known-fingerprints.json)
// - fail-open: ファイル不在 = 記録なし、破損 = 記録なし + 区別可能な警告
//   (呼び出し側が出す)。記録の書き込み失敗も儀式の成立を妨げない(SHOULD 水準)。
//   ローカル状態を消せる攻撃者は帳の守備範囲外(消えても儀式へ戻るだけで
//   fail-closed — pins より安全側)

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { Context, Effect, Stdio } from "effect";

import { describeNonTerminal } from "./agent-gate.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";

/** 帯域外で検証済みの相手 1 人分の記録。 */
export interface KnownFingerprint {
  /** ユーザー鍵 FP(16 バイト hex 32 文字 — CRYPTO_SPEC §3)。 */
  readonly fingerprintHex: string;
  /** 人間が帯域外確認を行った時刻(ヒットでは更新しない — 検証の事実の記録)。 */
  readonly verifiedAtMs: number;
}

/** ファイル全体(known-fingerprints.json)。キーは origin → user_id。 */
interface FingerprintBookFile {
  readonly v: 1;
  readonly known: Readonly<Record<string, Readonly<Record<string, KnownFingerprint>>>>;
}

/** 参照結果。corrupt は miss と区別する(呼び出し側が警告を出す)。 */
export type FingerprintLookup =
  | { readonly state: "hit"; readonly entry: KnownFingerprint }
  | { readonly state: "miss" }
  | { readonly state: "corrupt" };

/** Lookup / record boundary for the verified-fingerprint book. */
export interface FingerprintBookShape {
  /** 表示用のファイルパス(エントリ削除で儀式を強制再実行できる導線)。 */
  readonly filePath: string;
  readonly lookup: (origin: string, userId: string) => Effect.Effect<FingerprintLookup, CliError>;
  /** read-merge-write の追記(同一キーは上書き — 正当な鍵更新の反映)。 */
  readonly record: (
    origin: string,
    userId: string,
    fingerprintHex: string,
  ) => Effect.Effect<void, CliError>;
}

export class FingerprintBook extends Context.Service<FingerprintBook, FingerprintBookShape>()(
  "cli/FingerprintBook",
) {}

/** 帳の置き場所(設定と同系: <config.json の親>/known-fingerprints.json)。 */
export function fingerprintBookPathOf(configPath: string): string {
  return join(dirname(configPath), "known-fingerprints.json");
}

/** 儀式前の照会の結果(呼び出し側の分岐材料)。 */
export interface FingerprintBookConsult {
  /**
   * 帳の一致エントリ(null = ヒットなし・不一致・破損 = 従来どおり儀式か
   * フラグが必要)。ヒットは confirmKnownFingerprint(受諾単位の明示確認)へ
   * 渡す。フラグ(明示指定)が帳より優先される規律・エージェント環境の拒否は
   * 呼び出し側が保つ(帳はどちらも迂回しない)。
   */
  readonly hit: KnownFingerprint | null;
  /** 表示用のファイルパス(エントリ削除で儀式を強制再実行できる導線)。 */
  readonly filePath: string;
  /**
   * 帳の記録と提示指紋の**不一致**の警告(一致・記録なしでは no-op)。フラグ
   * 経路の判定**後**に呼ぶ — フラグが提示指紋と一致していて帳だけが古い場合
   * (正当な鍵更新の直後にフラグで回す等)に「the out-of-band check is
   * required again」がフラグ成功と矛盾して出るのを避けるため。
   */
  readonly warnIfChanged: Effect.Effect<void, never, CliIo>;
  /**
   * 儀式 / フラグ照合の**成功後**に呼ぶ追記。書き込み失敗は警告に落とす
   * (fail-open — 帳は SHOULD 水準で、儀式の成立を妨げない)。
   */
  readonly record: Effect.Effect<void, never, CliIo>;
}

/**
 * 儀式前の帳の照会(member add の受諾鍵確認・invite accept の招待者確認の共有):
 * 一致 = 12 語の帯域外読み上げの再実施を免除できる(受諾単位の明示確認は
 * confirmKnownFingerprint が要求する)、不一致 = 警告して儀式へフォールバック
 * (**自動失敗にしない** — `maruhi key generate` による正当な鍵更新があり得る)、
 * 破損 = 警告して記録なしとして扱う。
 */
export function consultFingerprintBook(input: {
  readonly origin: string;
  readonly userId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<FingerprintBookConsult, CliError, FingerprintBook | CliIo> {
  return Effect.gen(function* () {
    const book = yield* FingerprintBook;
    const looked = yield* book.lookup(input.origin, input.userId);
    if (looked.state === "corrupt") {
      yield* logWarning(
        `the verified-fingerprint book is corrupt and was ignored: ${book.filePath} — inspect it, and delete it if the change was not intentional`,
      );
    }
    const warnIfChanged =
      looked.state === "hit" && looked.entry.fingerprintHex !== input.fingerprintHex
        ? logWarning(
            `this fingerprint differs from the one verified for ${displayText(input.userId)} on this machine on ${formatUtcMinutes(looked.entry.verifiedAtMs)}. The person may have legitimately rebuilt their key (\`maruhi key generate\`), or this is not their key — the out-of-band check is required again`,
          )
        : Effect.void;
    const record = book.record(input.origin, input.userId, input.fingerprintHex).pipe(
      Effect.flatMap(() =>
        logNote(
          `recorded the verified fingerprint for ${displayText(input.userId)} — future ceremonies with this person skip the 12-word read-out while their key is unchanged (delete the entry in ${book.filePath} to force the full ceremony again)`,
        ),
      ),
      Effect.catch((error) =>
        logWarning(
          `could not record the verified fingerprint (${error.message}). The next ceremony with this person will require the full read-out again`,
        ),
      ),
    );
    const hit =
      looked.state === "hit" && looked.entry.fingerprintHex === input.fingerprintHex
        ? looked.entry
        : null;
    return { hit, filePath: book.filePath, warnIfChanged, record };
  });
}

/**
 * 帳のヒットを実際に使えるか(フラグなし + 非エージェント + stdin / stdout が
 * 対話端末)を判定し、使えるヒットだけを返す。端末条件だけで使えない場合は
 * その旨を note で説明する(完全な儀式へ戻る理由の提示)。
 *
 * 端末条件を課す理由(ADR-0016 決定 7 の一次境界と同じ allow-list): 12 語
 * 儀式は実行ごとの最終語再入力が要るため盲目的なパイプでは通らないが、yes
 * 確認はそうではない。パイプ・CI・未検出エージェントで帳が非対話の成立条件を
 * フラグ専用から緩めない(fail-closed — 非端末は帳なしと同じ挙動に戻る)。
 */
export function usableBookHit(input: {
  readonly book: FingerprintBookConsult;
  readonly flagProvided: boolean;
  readonly isAgent: boolean;
}): Effect.Effect<KnownFingerprint | null, never, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    if (input.book.hit === null || input.flagProvided || input.isAgent) {
      return null;
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      // 落ちた側を名指しする(DP5 追補 G の規律 — describeNonTerminal)
      yield* logNote(
        `the verified-fingerprint book was not used: ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })} — the full 12-word read-out is required here`,
      );
      return null;
    }
    return input.book.hit;
  });
}

/**
 * 帳のヒット時の受諾単位の明示確認: 12 語の帯域外読み上げの再実施は免除する
 * が、**この操作(付与 / 受諾)への同意そのものは省略しない** — 帳は「以前この
 * 鍵を帯域外確認した」記録であって、今回の操作の意図を代替しないため。
 * `prompt` は対象と操作を名指しする文言(呼び出し側が与える)。yes 以外は
 * 中止し、完全な儀式へ戻す導線(エントリ削除)を示す。
 */
export function confirmKnownFingerprint(input: {
  readonly entry: KnownFingerprint;
  readonly filePath: string;
  /** `: ` の直前までのプロンプト本文(例: "Type yes to add … as …")。 */
  readonly prompt: string;
  /** 中止時の先頭文(例: "add_member was cancelled.")。 */
  readonly cancelText: string;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `This fingerprint was verified out of band on this machine on ${formatUtcMinutes(input.entry.verifiedAtMs)} (the verified-fingerprint book), so the 12-word read-out is not required again`,
    );
    const answer = yield* io.promptLine({ prompt: `${input.prompt}: ` });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          `${input.cancelText} To run the full 12-word ceremony instead, delete this person's entry in ${input.filePath} and re-run`,
        ),
      );
    }
  });
}

const HEX_32 = /^[0-9a-f]{32}$/;
// レコードキー(origin / user_id)の規律: 先頭は英数字(pins.ts の招待 id と
// 同じく `__proto__` を構造的に排除)、空白を含まない。origin は正規化済みの
// URL(http(s)://…)、user_id はサーバー採番 — どちらも形式へは依存しない
const BOOK_KEY = /^[A-Za-z0-9]\S{0,1023}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeEntry(value: unknown): KnownFingerprint | null {
  if (!isRecord(value)) {
    return null;
  }
  const fingerprintHex = value["fingerprintHex"];
  const verifiedAtMs = value["verifiedAtMs"];
  if (
    typeof fingerprintHex !== "string" ||
    !HEX_32.test(fingerprintHex) ||
    typeof verifiedAtMs !== "number" ||
    !Number.isSafeInteger(verifiedAtMs) ||
    verifiedAtMs <= 0
  ) {
    return null;
  }
  return { fingerprintHex, verifiedAtMs };
}

/** 1 origin 分(user_id → エントリ)のデコード(1 件でも不正なら全体拒否)。 */
function decodeUsers(value: unknown): Record<string, KnownFingerprint> | null {
  if (!isRecord(value)) {
    return null;
  }
  const users: Record<string, KnownFingerprint> = {};
  for (const [userId, raw] of Object.entries(value)) {
    const entry = decodeEntry(raw);
    if (entry === null || !BOOK_KEY.test(userId)) {
      return null;
    }
    users[userId] = entry;
  }
  return users;
}

/** 厳格デコード。1 件でも不正なら全体を破損扱い(部分読みしない — pins と同じ)。 */
function decodeBook(json: string): FingerprintBookFile | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== 1 || !isRecord(value["known"])) {
    return null;
  }
  const known: Record<string, Record<string, KnownFingerprint>> = {};
  for (const [origin, rawUsers] of Object.entries(value["known"])) {
    const users = BOOK_KEY.test(origin) ? decodeUsers(rawUsers) : null;
    if (users === null) {
      return null;
    }
    known[origin] = users;
  }
  return { v: 1, known };
}

/** File-backed fingerprint book at `path` (used by both production and tests). */
export function makeFileFingerprintBook(path: string): FingerprintBookShape {
  const loadRaw = async (): Promise<
    | { readonly book: FingerprintBookFile; readonly state: "loaded" }
    | { readonly state: "missing" }
    | { readonly state: "corrupt" }
  > => {
    let json: string;
    try {
      json = await readFile(path, "utf8");
    } catch {
      return { state: "missing" };
    }
    const book = decodeBook(json);
    return book === null ? { state: "corrupt" } : { book, state: "loaded" };
  };

  const write = async (book: FingerprintBookFile): Promise<void> => {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, `${JSON.stringify(book, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  };

  return {
    filePath: path,
    lookup: (origin, userId) =>
      Effect.tryPromise({
        try: async (): Promise<FingerprintLookup> => {
          const loaded = await loadRaw();
          if (loaded.state === "missing") {
            return { state: "miss" };
          }
          if (loaded.state === "corrupt") {
            return { state: "corrupt" };
          }
          // own-property 参照(floor.ts の規律 — prototype 経由の値を拾わない)
          const users = floorRecordGet(loaded.book.known, origin);
          const entry = users === undefined ? undefined : floorRecordGet(users, userId);
          return entry === undefined ? { state: "miss" } : { state: "hit", entry };
        },
        catch: () => cliError(`Cannot read the verified-fingerprint book: ${path}`),
      }),
    record: (origin, userId, fingerprintHex) =>
      Effect.tryPromise({
        try: async () => {
          // 形式外キーを書くと次回ロードが全体破損になる(厳格デコード)ため
          // 手前で拒否する(呼び出し側は警告に落とす — fail-open)
          if (!BOOK_KEY.test(origin) || !BOOK_KEY.test(userId) || !HEX_32.test(fingerprintHex)) {
            throw new Error("key form");
          }
          const loaded = await loadRaw();
          if (loaded.state === "corrupt") {
            // 破損ファイルへの上書きは拒否(pins の merge と同じ規律 — 意図しない
            // 変更の痕跡を黙って消さない)
            throw new Error("corrupt");
          }
          const base: FingerprintBookFile =
            loaded.state === "missing" ? { v: 1, known: {} } : loaded.book;
          const users = floorRecordGet(base.known, origin) ?? {};
          await write({
            v: 1,
            known: {
              ...base.known,
              [origin]: { ...users, [userId]: { fingerprintHex, verifiedAtMs: Date.now() } },
            },
          });
        },
        catch: () =>
          cliError(
            `Cannot write the verified-fingerprint book (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
          ),
      }),
  };
}
