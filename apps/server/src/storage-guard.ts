// DO ストレージ総量ガード(AUTH_SPEC §12-8 — 2026-09-02 H2。hosted-design.md §3-3 /
// §8 gap 3。旧「Phase 2 予告」の実装)。
//
// プロジェクト DO の SQLite 実測量(`SqlStorage.databaseSize`)に警告 / 拒否の
// 2 段の閾値(policy.ts — 起草値 8 GB / 9 GB)を置き、10 GB の SQLITE_FULL
// (読み取り可・書き込み不能の床)へ到達させない。監査ログの無期限保持
// (AUDIT_SPEC §5.3)を覆う唯一の防衛線。
//
// - 判定は純関数(storageGuardDecision — 8〜9 GB の実生成は非現実的なため、
//   ユニットテスト用に閾値を引数で受ける。quotas.ts の *Exceeded と同じ形)
// - 実測量の取得は StorageMeter サービス経由(テストは固定サイズの meter を
//   差し込み、受理経路の結線 — どの面が拒否され、どの面が拒否下でも通るか —
//   を実プログラムに対して固定する)
// - 拒否が効く面 = プロジェクト内容の成長面のみ(§12-8 の列挙): 値 push・変数の
//   作成 / activation / 改名 / スキーマ再発行・環境の改名・環境作成複合・DEK
//   ラップ登録・add_member / grant_server。読み取り(var.read の監査追記を伴う
//   一括 pull を含む — 退出経路)・削除系(解放手段)・失効 / 権限縮小系・
//   ローテーション複合・リース・ヘッド申告・standalone checkpoint・schemaPolicy /
//   dismiss は**呼ばない**(拒否下でも受理し続ける面 — 同節)。ensure* を呼ぶ
//   側の列挙がその契約であり、storage-guard.test.ts が両方向を固定する
// - 判定位置はメンバーシップ・role・存在(環境 / 変数)・レイアウトのサポート
//   範囲の検査の後(§11-2 — 非メンバーへプロジェクト状態を返さない。存在検査は
//   メンバー向けの 404 で、サポート範囲は「更新が必要」の正直なエラーを先に
//   立てる裁定 CR)・CAS / 署名検証 / 数量ポリシー等の意味論的検査の前(資源
//   保護は意味論に優先)
// - 警告(8 GB)は運用ログのみ(H3 の監視・アラートは未実装)。**静的メッセージ
//   のみ**(§11-5 / hosted-design.md §5-1 — プロジェクト ID = capability 等の
//   リクエスト由来識別子を書かない)。DO インスタンスの生存中に警告域・拒否域
//   それぞれ 1 回(毎受理で出すとログが書き込み計数器になる)。運営側の特定は
//   Workers Logs のイベント封筒(Durable Object id = idFromName の像)で行う

import { Context, Effect, Layer } from "effect";

import type { DataRejectedError } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import { DO_STORAGE_REJECT_BYTES, DO_STORAGE_WARN_BYTES } from "./policy.ts";

/** 実測量に対する判定(admit < warn < reject)。 */
export type StorageGuardDecision = "admit" | "warn" | "reject";

export interface StorageGuardThresholds {
  readonly warnBytes: number;
  readonly rejectBytes: number;
}

/** policy.ts の起草値(§12-8 — 10 進 GB)。 */
const STORAGE_GUARD_THRESHOLDS: StorageGuardThresholds = {
  warnBytes: DO_STORAGE_WARN_BYTES,
  rejectBytes: DO_STORAGE_REJECT_BYTES,
};

/**
 * §12-8: 実測量 → 判定の純関数。閾値は「以上」で判定する(拒否閾値ちょうどの
 * 実測は拒否 — 床へ近づく側に倒す)。
 */
export function storageGuardDecision(
  databaseSizeBytes: number,
  thresholds: StorageGuardThresholds = STORAGE_GUARD_THRESHOLDS,
): StorageGuardDecision {
  if (databaseSizeBytes >= thresholds.rejectBytes) {
    return "reject";
  }
  if (databaseSizeBytes >= thresholds.warnBytes) {
    return "warn";
  }
  return "admit";
}

/** 運用ログの段(DO インスタンスごと各 1 回)。 */
type StorageGuardLogLevel = "warn" | "reject";

interface StorageMeterShape {
  /** DO SQLite の実測量(バイト)。SqlStorage.databaseSize の即時値(I/O なし)。 */
  readonly databaseSizeBytes: () => number;
  /**
   * 運用ログの 1 回限りの発火記録。初回なら true(呼び出し側がログを出す)、
   * 既出なら false。DO インスタンスの生存(メモリ)に束縛され、退去 → 再起動で
   * リセットされる(再起動ごとに高々 1 回 — 監視の入力としては十分な密度)。
   */
  readonly noteLogged: (level: StorageGuardLogLevel) => boolean;
}

/**
 * 実測量の取得点(テストの注入点)。chain-do.ts が DO の SqlStorage で構成し、
 * storage-guard.test.ts は固定サイズの meter で実プログラムの結線を検査する。
 */
export class StorageMeter extends Context.Service<StorageMeter, StorageMeterShape>()(
  "StorageMeter",
) {}

/** meter の実体(SqlStorage 版・テストの固定サイズ版で共有する作り方)。 */
export function makeStorageMeter(databaseSizeBytes: () => number): StorageMeterShape {
  const logged = new Set<StorageGuardLogLevel>();
  return {
    databaseSizeBytes,
    noteLogged: (level) => {
      if (logged.has(level)) {
        return false;
      }
      logged.add(level);
      return true;
    },
  };
}

export const storageMeterLayer = (sql: SqlStorage): Layer.Layer<StorageMeter> =>
  Layer.sync(StorageMeter, () => makeStorageMeter(() => sql.databaseSize));

/**
 * 内容の成長面の受理プログラムが呼ぶガード(§12-8)。判定 = reject なら
 * limit-exceeded(resource `project-storage-bytes`、limit = 拒否閾値)で拒否し、
 * warn なら受理したまま運用ログを 1 回出す。呼ばない面(読み取り・削除・失効・
 * ローテーション等)の列挙は冒頭コメントと仕様の明示列挙。
 */
export const ensureStorageAdmitsGrowth: Effect.Effect<void, DataRejectedError, StorageMeter> =
  Effect.gen(function* () {
    const meter = yield* StorageMeter;
    const decision = storageGuardDecision(meter.databaseSizeBytes());
    if (decision === "admit") {
      return;
    }
    if (decision === "warn") {
      if (meter.noteLogged("warn")) {
        // 静的メッセージのみ(プロジェクト ID・サイズ等の可変値は書かない —
        // サイズは監視〔H3〕の領分。ここは「到達した」という事実の 1 行)
        console.warn(
          "project storage crossed the warning threshold (AUTH_SPEC §12-8 DO storage guard); growth writes are still accepted until the rejection threshold",
        );
      }
      return;
    }
    if (meter.noteLogged("reject")) {
      console.error(
        "project storage reached the rejection threshold (AUTH_SPEC §12-8 DO storage guard); growth writes are rejected until space is freed — reads, deletions, revocations and rotations remain accepted",
      );
    }
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "project-storage-bytes",
      limit: DO_STORAGE_REJECT_BYTES,
    });
  });
