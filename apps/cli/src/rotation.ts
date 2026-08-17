// `maruhi rotation list|dismiss`(AUDIT_SPEC §4.1 / §6 / §7 — Wave 2 B2)。
//
// - list: サーバーの導出ビュー(現在有効な rotation.recommended − 解消)を
//   取得して表示する。表示名はサーバー申告を信用せず、検証済みメタステート
//   メント(削除済み変数は tombstone — §4.2 の「deleted は直前 active 名を
//   保持」)から解決する(AUDIT_SPEC §7 の TCB 規律)。解決できない環境
//   (検証済み削除など)は識別子のまま表示する
// - dismiss: 取り下げ操作(サーバー側で rotation.dismissed を生成 — admin)。
//   フラグは上流 credential のローテーション + push(再暗号化マーカーなし)でも
//   解消される(§4.1-5)— dismiss は「ローテーションせずリスクを受容する」
//   明示宣言であり、削除済み変数(push できない)の唯一の解消経路
//
// フラグ集合は非機密メタデータ(識別子・根拠種別・対象)のみで、平文値・
// 鍵素材はこのモジュールを通らない。

import { RotationFlagNotFoundError } from "@maruhi/api-schema";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices, ProjectContextBase } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { pullVerifiedEnvironmentMetadata } from "./values.ts";

/** 導出ビューの 1 フラグ(api-schema の RotationFlagSchema の受信形)。 */
interface RotationFlagView {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
}

/** フラグビューの取得(表示・件数報告・dismiss 対象解決の共有入口)。 */
function fetchRotationFlags(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly RotationFlagView[], CliError> {
  return client.rotation.flags({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.flags),
  );
}

/** 変数名の解決結果(検証済みステートメント由来のみ — 解決不能は null)。 */
export type NameIndex = ReadonlyMap<string, string>;

/**
 * 一覧に現れる環境ごとに検証済みメタデータ(active + tombstone)を取得し、
 * variableId → 表示名の索引を作る。取得・検証に失敗した環境(検証済み削除
 * など)は索引なし = 識別子表示へ劣化する(警告つき — 表示は SHOULD であり
 * 一覧自体を止めない)。`maruhi audit` の表示名解決(同じ TCB 規律 —
 * AUDIT_SPEC §7)と共用する。
 */
export function resolveNames(
  context: ProjectContextBase,
  environmentIds: readonly string[],
): Effect.Effect<ReadonlyMap<string, NameIndex>, never, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const byEnvironment = new Map<string, NameIndex>();
    for (const environmentId of environmentIds) {
      const attempted = yield* Effect.gen(function* () {
        const floorHandle = yield* floorHandleFor(context, environmentId);
        return yield* pullVerifiedEnvironmentMetadata({
          client: context.client,
          verified: context.verified,
          environmentId,
          resync: context.resync,
          floor: floorHandle,
        });
      }).pipe(
        Effect.map((metadata) => ({ kind: "ok", metadata }) as const),
        Effect.catch((error) =>
          Effect.succeed({ kind: "failed", message: error.message } as const),
        ),
      );
      if (attempted.kind === "failed") {
        yield* io.logError(
          `Note: could not fetch verified metadata for environment ${displayText(environmentId)} (${attempted.message}) — variables are shown by identifier only`,
        );
        continue;
      }
      const names = new Map<string, string>();
      for (const statement of attempted.metadata.variables) {
        names.set(statement.variableId, statement.name);
      }
      for (const tombstone of attempted.metadata.tombstones) {
        names.set(tombstone.variableId, tombstone.name);
      }
      byEnvironment.set(environmentId, names);
    }
    return byEnvironment;
  });
}

function describeTarget(flag: RotationFlagView): string {
  if (flag.targetUserId !== undefined) {
    return `member:${displayText(flag.targetUserId)}`;
  }
  if (flag.targetServerKeyFingerprintHex !== undefined) {
    return `server:${flag.targetServerKeyFingerprintHex}`;
  }
  return "unknown";
}

function describeBasis(basis: "read" | "readable"): string {
  return basis === "read" ? "read (confirmed fetch)" : "readable (fetch was possible)";
}

/** `maruhi rotation list`: 現在有効なフラグの表示(全メンバー — クラス 1)。 */
export function rotationListOp(
  context: ProjectContextBase,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const flags = yield* fetchRotationFlags(context.client, context.projectId);
    if (flags.length === 0) {
      yield* io.log("No rotation flags are currently active");
      return 0;
    }
    const environmentIds = [...new Set(flags.map((flag) => flag.environmentId))].toSorted();
    const names = yield* resolveNames(context, environmentIds);
    yield* io.log(
      `Rotation flags: ${countNoun(flags.length, "active flag")} (upstream credential rotation recommended — AUDIT_SPEC §4.1)`,
    );
    for (const environmentId of environmentIds) {
      yield* io.log(`Environment ${displayText(environmentId)}:`);
      const index = names.get(environmentId);
      // 表示順は検出時刻 →(同一 sweep で同時刻の場合)variableId の安定ソート。
      // 監査 seq はワイヤに載らない(AUDIT_SPEC §7 — 序数の非漏洩)
      const rows = flags
        .filter((flag) => flag.environmentId === environmentId)
        .toSorted(
          (a, b) =>
            a.recommendedAtMs - b.recommendedAtMs || a.variableId.localeCompare(b.variableId),
        );
      for (const flag of rows) {
        const name = index?.get(flag.variableId);
        const label =
          name === undefined
            ? displayText(flag.variableId)
            : `${displayText(name)} (${displayText(flag.variableId)})`;
        yield* io.log(
          `  ${label}\tbasis=${describeBasis(flag.basis)}\ttarget=${describeTarget(flag)}\ttrigger seq=${flag.triggerChainSeq}`,
        );
      }
    }
    yield* io.log(
      "To resolve: rotate the upstream credential and save the new value with maruhi push (the mandated re-encryption alone does not resolve a flag). For pairs that cannot be pushed (e.g. deleted variables), dismiss the flag with maruhi rotation dismiss as an explicit acceptance of risk (admin)",
    );
    return 0;
  });
}

/** dismiss の対象解決の結果。 */
interface DismissTargets {
  readonly targets: readonly { readonly environmentId: string; readonly variableId: string }[];
}

/**
 * `--all` の対象解決: 現在有効な全フラグ(`--env` 指定時は当該環境のみ)を
 * 対単位に畳む(同一対の複数フラグ — 再削除など — は 1 対)。
 */
function resolveAllTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly environmentId: string | null;
}): Effect.Effect<DismissTargets, CliError> {
  return Effect.gen(function* () {
    const flags = yield* fetchRotationFlags(input.client, input.projectId);
    const scoped =
      input.environmentId === null
        ? flags
        : flags.filter((flag) => flag.environmentId === input.environmentId);
    const seen = new Set<string>();
    const targets: { environmentId: string; variableId: string }[] = [];
    for (const flag of scoped) {
      const key = `${flag.environmentId} ${flag.variableId}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      targets.push({ environmentId: flag.environmentId, variableId: flag.variableId });
    }
    if (targets.length === 0) {
      return yield* Effect.fail(
        cliError(
          input.environmentId === null
            ? "No rotation flags are currently active (nothing to dismiss)"
            : "No rotation flags are currently active in the specified environment (nothing to dismiss)",
        ),
      );
    }
    return { targets };
  });
}

/**
 * `maruhi rotation dismiss` の対象解決: `--all` は現在有効な全フラグ
 * (`--env` 指定時は当該環境のみ)、個別指定は (--env, variableId) の 1 対。
 */
export function resolveDismissTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly all: boolean;
  readonly environmentId: string | null;
  readonly variableId: string | null;
}): Effect.Effect<DismissTargets, CliError> {
  return Effect.gen(function* () {
    if (input.all) {
      if (input.variableId !== null) {
        return yield* Effect.fail(
          cliError("--all cannot be combined with a variableId (use one or the other)"),
        );
      }
      return yield* resolveAllTargets({
        client: input.client,
        projectId: input.projectId,
        environmentId: input.environmentId,
      });
    }
    if (input.environmentId === null || input.variableId === null) {
      return yield* Effect.fail(
        cliError(
          "Specify what to dismiss: maruhi rotation dismiss <variableId> --env <environmentId> (or --all for every flag)",
        ),
      );
    }
    return {
      targets: [{ environmentId: input.environmentId, variableId: input.variableId }],
    };
  });
}

/** `maruhi rotation dismiss`: 取り下げの実行(admin — サーバー側で権限検査)。 */
export function rotationDismissOp(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly targets: readonly { readonly environmentId: string; readonly variableId: string }[];
}): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.rotation
      .dismiss({ params: { projectId: input.projectId }, payload: { targets: input.targets } })
      .pipe(
        Effect.catch((error) =>
          Effect.fail(
            error instanceof RotationFlagNotFoundError
              ? cliError(
                  `No active flag for variable ${displayText(error.variableId)} in environment ${displayText(error.environmentId)} (the dismissal was aborted as a whole — check the current targets with maruhi rotation list)`,
                )
              : toCliError(error),
          ),
        ),
      );
    yield* io.log(
      `Dismissed ${countNoun(input.targets.length, "rotation flag")} (rotation.dismissed — recorded in the audit log)`,
    );
    return 0;
  });
}

/**
 * remove / revoke 完了時のフラグ件数報告(B2 裁定 — 導線)。対象(削除した
 * user_id / 失効したサーバー鍵 FP)宛の現在有効なフラグを数えて案内する。
 * 取得失敗でコマンドの成否を変えない(SHOULD 表示)。
 */
export function reportRotationFlagCount(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly target:
    | { readonly kind: "member"; readonly userId: string }
    | { readonly kind: "server"; readonly fingerprintHex: string };
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const flags = yield* fetchRotationFlags(input.client, input.projectId).pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* io.logError(
            `Note: failed to fetch rotation flags (${error.message}) — check with maruhi rotation list`,
          );
          return null;
        }),
      ),
    );
    if (flags === null) {
      return;
    }
    const count = flags.filter((flag) =>
      input.target.kind === "member"
        ? flag.targetUserId === input.target.userId
        : flag.targetServerKeyFingerprintHex === input.target.fingerprintHex,
    ).length;
    if (count === 0) {
      return;
    }
    yield* io.log(
      `Rotation flags: ${countNoun(count, "active flag")} targeting the removed party (encryption cannot revoke already-read values — rotating the upstream credentials is recommended. See maruhi rotation list)`,
    );
  });
}
