// 招待の非機密ピン留めの永続化層(CRYPTO_SPEC §6.3 帯域外アンカー (a) と、
// その招待者側の対応物 = 発行時ピン)。
//
// - **受諾側アンカー**: 招待リンクのフラグメントが運ぶ genesis(= projectId、
//   ファイル名が兼ねる)・招待者の検証済みヘッド(hash + seq)・招待者の
//   user_id + 鍵 FP。受諾時にピン留めし、同期時の機械照合(context.ts)が
//   「ヘッド包含 + 招待者 FP の在籍一致」を検査する(§6.3 (a) / §6.5)。
// - **発行側ピン**: `invite create` が控える 招待 id → (token_hash, role, 期限)。
//   member add 時に一覧応答(サーバー申告)と突合し、行のすり替え・role の
//   虚偽申告を機械検出する(受諾側アンカーと対称の防衛)。別デバイスで
//   member add する場合はピンが無く、儀式の表示照合のみに劣化する(SHOULD)。
//
// 内容はハッシュ・連番・user_id・FP・role のみで、平文値・鍵素材・トークン
// 生値を含まない(ディスクレス不変条件と両立)。置き場は床と同系
// (<config dir>/invites/<projectId>.json)。書き込みは temp + rename の
// read-merge-write(床と同じ規律)。
//
// fail-open: ファイル不在は「ピンなし」、破損は「ピンなし + 区別可能な警告」
// (呼び出し側が出す)。ローカル状態を消せる攻撃者はピンの守備範囲外
// (§14.3-3 の非保証に帰着 — 床と同じ線引き)。

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { Context, Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";

/** 受諾側の招待リンクアンカー(§6.3 (a))。 */
export interface InviteAnchor {
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly inviterUserId: string;
  /** ユーザー鍵 FP(16 バイト hex 32 文字 — §3)。 */
  readonly inviterKeyFingerprintHex: string;
  /** 初回機械照合が成功したときの自ビューの head seq(未照合 = null)。 */
  readonly verifiedAtSeq: number | null;
}

/** 発行側のピン(招待 id → 発行時に確定した内容)。 */
export interface IssuedInvitePin {
  readonly tokenHashHex: string;
  readonly role: "reader" | "member" | "admin";
  readonly expiresAtMs: number;
}

/** プロジェクト 1 つ分のピンファイル(invites/<projectId>.json)。 */
export interface InvitePins {
  readonly v: 1;
  readonly anchor: InviteAnchor | null;
  /** キーは招待 id。 */
  readonly issued: Readonly<Record<string, IssuedInvitePin>>;
}

/** 読み込み結果(fail-open — 呼び出し側が状態別の警告を出す)。 */
export interface PinsLoadResult {
  readonly pins: InvitePins | null;
  readonly state: "loaded" | "missing" | "corrupt";
}

/** Load / merge boundary for the invite pin files. */
export interface PinStoreShape {
  readonly load: (projectId: string) => Effect.Effect<PinsLoadResult, CliError>;
  /** アンカーの保存(read-merge-write。既存 issued ピンは保持)。 */
  readonly saveAnchor: (projectId: string, anchor: InviteAnchor) => Effect.Effect<void, CliError>;
  /** 発行ピンの追記(read-merge-write + 期限切れ長期経過分の掃除)。 */
  readonly saveIssuedPin: (
    projectId: string,
    inviteId: string,
    pin: IssuedInvitePin,
  ) => Effect.Effect<void, CliError>;
}

export class PinStore extends Context.Service<PinStore, PinStoreShape>()("cli/PinStore") {}

/** ピンディレクトリ(設定と同系の置き場: <config.json の親>/invites)。 */
export function pinsDirOf(configPath: string): string {
  return join(dirname(configPath), "invites");
}

/**
 * 発行ピンの保持窓: 期限切れからこの時間を過ぎた行は掃除する。受諾済み招待の
 * add_member は期限切れ後も可能(期限が縛るのは受諾のみ — AUTH_SPEC §15-1)な
 * ので、期限そのものでは消さない。窓を過ぎた member add はピンなし(表示照合
 * のみ)へ劣化する。
 */
const ISSUED_PIN_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_32 = /^[0-9a-f]{32}$/;
const ROLES = ["reader", "member", "admin"] as const;
// 招待 id はサーバー採番(ULID)だが形式へは依存しない(AUTH_SPEC §11-1 の
// ID 形式非依存と同じ姿勢)。先頭 `_` の禁止が `__proto__` を構造的に排除する
// (floor.ts のレコードキー規律)。参照側は floorRecordGet を使う
const INVITE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/** レコードの文字列フィールドをパターン検証して返す(不一致 = null)。 */
function patternField(
  record: Record<string, unknown>,
  key: string,
  pattern: RegExp,
): string | null {
  const value = record[key];
  return typeof value === "string" && pattern.test(value) ? value : null;
}

/** レコードの正整数フィールド(不一致 = null)。 */
function positiveIntField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return isPositiveInteger(value) ? value : null;
}

function decodeAnchor(value: unknown): InviteAnchor | null {
  if (!isRecord(value)) {
    return null;
  }
  const headSeq = positiveIntField(value, "headSeq");
  const headHashHex = patternField(value, "headHashHex", HEX_64);
  const inviterUserId = patternField(value, "inviterUserId", /^.{1,1024}$/s);
  const inviterKeyFingerprintHex = patternField(value, "inviterKeyFingerprintHex", HEX_32);
  const verifiedAtSeq =
    value["verifiedAtSeq"] === null ? null : positiveIntField(value, "verifiedAtSeq");
  if (
    headSeq === null ||
    headHashHex === null ||
    inviterUserId === null ||
    inviterKeyFingerprintHex === null ||
    (verifiedAtSeq === null && value["verifiedAtSeq"] !== null)
  ) {
    return null;
  }
  return { headSeq, headHashHex, inviterUserId, inviterKeyFingerprintHex, verifiedAtSeq };
}

function decodeIssuedPin(value: unknown): IssuedInvitePin | null {
  if (!isRecord(value)) {
    return null;
  }
  const tokenHashHex = patternField(value, "tokenHashHex", HEX_64);
  const role = ROLES.find((known) => known === value["role"]) ?? null;
  const expiresAtMs = positiveIntField(value, "expiresAtMs");
  if (tokenHashHex === null || role === null || expiresAtMs === null) {
    return null;
  }
  return { tokenHashHex, role, expiresAtMs };
}

/** 厳格デコード。スキーマ不一致は全体を破損扱い(部分読みしない — 床と同じ)。 */
/** issued レコード全体のデコード(1 件でも不正なら全体拒否)。 */
function decodeIssuedRecord(value: unknown): Record<string, IssuedInvitePin> | null {
  if (!isRecord(value)) {
    return null;
  }
  const issued: Record<string, IssuedInvitePin> = {};
  for (const [inviteId, raw] of Object.entries(value)) {
    const pin = decodeIssuedPin(raw);
    if (pin === null || !INVITE_ID.test(inviteId)) {
      return null;
    }
    issued[inviteId] = pin;
  }
  return issued;
}

function decodeInvitePins(json: string): InvitePins | null {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isRecord(value) || value["v"] !== 1) {
    return null;
  }
  const anchor = value["anchor"] === null ? null : decodeAnchor(value["anchor"]);
  if (value["anchor"] !== null && anchor === null) {
    return null;
  }
  const issued = decodeIssuedRecord(value["issued"]);
  if (issued === null) {
    return null;
  }
  return { v: 1, anchor, issued };
}

/** 発行ピンの参照(own-property — floor.ts の規律)。 */
export function issuedPinOf(
  pins: InvitePins | null,
  inviteId: string,
): IssuedInvitePin | undefined {
  return pins === null ? undefined : floorRecordGet(pins.issued, inviteId);
}

/** File-backed pin store at `dir` (used by both production and tests). */
export function makeFilePinStore(dir: string): PinStoreShape {
  const pathOf = (projectId: string) => join(dir, `${projectId}.json`);

  const loadRaw = async (projectId: string): Promise<PinsLoadResult> => {
    let json: string;
    try {
      json = await readFile(pathOf(projectId), "utf8");
    } catch {
      return { pins: null, state: "missing" };
    }
    const pins = decodeInvitePins(json);
    return pins === null ? { pins: null, state: "corrupt" } : { pins, state: "loaded" };
  };

  const write = async (projectId: string, pins: InvitePins): Promise<void> => {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const path = pathOf(projectId);
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, `${JSON.stringify(pins, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  };

  const merge = (
    projectId: string,
    apply: (pins: InvitePins) => InvitePins,
  ): Effect.Effect<void, CliError> =>
    Effect.tryPromise({
      try: async () => {
        const loaded = await loadRaw(projectId);
        // 破損は空からの再構築(fail-open — 読み手が警告を出す)
        const base: InvitePins = loaded.pins ?? { v: 1, anchor: null, issued: {} };
        await write(projectId, apply(base));
      },
      catch: () => cliError(`招待ピンファイルを書き込めません: ${pathOf(projectId)}`),
    });

  return {
    load: (projectId) =>
      Effect.tryPromise({
        try: () => loadRaw(projectId),
        catch: () => cliError(`招待ピンファイルを読み取れません: ${pathOf(projectId)}`),
      }),
    saveAnchor: (projectId, anchor) => merge(projectId, (pins) => ({ ...pins, anchor })),
    saveIssuedPin: (projectId, inviteId, pin) => {
      // 形式外 id を書くと次回ロードが全体破損になる(厳格デコード)ため手前で拒否
      if (!INVITE_ID.test(inviteId)) {
        return Effect.fail(
          cliError("サーバー応答の招待 id が想定形式ではないため、発行ピンを保存できません"),
        );
      }
      return merge(projectId, (pins) => {
        const now = Date.now();
        const kept = Object.entries(pins.issued).filter(
          ([, existing]) => existing.expiresAtMs + ISSUED_PIN_RETENTION_MS > now,
        );
        return { ...pins, issued: { ...Object.fromEntries(kept), [inviteId]: pin } };
      });
    },
  };
}
