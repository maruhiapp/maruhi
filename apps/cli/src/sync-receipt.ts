// 同期レシート(integration-options.md §3 補足 13 W2 / 補足 15 X3 (a))。
//
// 「どの同期先に、どの変数の version まで届いたか」を、設定で指した環境
// (`receipts.environment`)の**普通の変数**として保存する: E2EE + §4.1 の
// 書き込み署名(改竄検出つき)で、仕様改訂なし。値由来のダイジェストは持たない
// (推測可能な値の漏洩経路になる — W2)。version 番号だけで足りる。
//
// 粒度: ターゲットごとに 1 変数(`sync-receipt:<target>`)。同期のたびに新
// version が積まれるので、変数あたり version 上限(AUTH_SPEC §12-8 — 1,000)に
// 近づいたら警告する(内容が変わらない apply は書かないので、書くのは
// 「同期先が実際に変わった回」だけ)。active 変数上限(1,000 / 環境)には
// ターゲット数ぶんしか当たらない。
//
// 読み = 値付き pull(pull.ts の pullVariables — レシート環境を復号する)、
// 書き = push.ts の pushVariable(人間の master 鍵で署名する。CI はこの鍵を
// 持たないので書けない)。
//
// 名前を `MARUHI_` で始めない理由: `run` は `MARUHI_*` の注入を拒否するので、
// レシート環境を誤って `run` に使うと失敗する — それ自体は
// 望ましいが、拒否文が「実行制御名」を言い読者を惑わせる。`:` を含む名前は
// POSIX 識別子でないため、`run` は「環境変数として注入できない名前」として
// 変数名だけを添えて止まる(同じ fail-closed で、文面が事実を言う)。

import type { EnvironmentId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { DekRecipient } from "./deks.ts";
import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { parseJsonRecord } from "./json-record.ts";
import { pullVariables } from "./pull.ts";
import { pushVariable } from "./push.ts";
import { PRESET_IDS, type PresetId } from "./sync-types.ts";
import type { VerifiedProject } from "./sync.ts";

/** What the last apply delivered to one target: variable name → version. */
export interface SyncReceipt {
  readonly version: 1;
  readonly target: string;
  readonly preset: PresetId;
  /** 最後に書いた時刻(書き手の時計。表示用 — 判定には使わない)。 */
  readonly syncedAt: string;
  readonly variables: Readonly<Record<string, number>>;
}

/** 変数あたりの version 上限(AUTH_SPEC §12-8 — apps/server/src/policy.ts の値)。 */
const RECEIPT_VERSION_LIMIT = 1_000;
/** この version から上限接近を警告する(残り 100 回の同期)。 */
const RECEIPT_VERSION_WARN_AT = 900;

/** The name of the receipt variable for a target. */
export function receiptVariableName(target: string): string {
  return `sync-receipt:${target}`;
}

/** レシート JSON の解釈(不正なら理由の文字列。値そのものは含めない)。 */
export function decodeReceipt(text: string, expectedTarget: string): SyncReceipt | string {
  const record = parseJsonRecord(text);
  if (typeof record === "string") {
    return record;
  }
  if (record["version"] !== 1) {
    return "unsupported receipt version (expected 1)";
  }
  if (record["target"] !== expectedTarget) {
    return "the receipt names a different target";
  }
  const preset = record["preset"];
  if (typeof preset !== "string" || !PRESET_IDS.includes(preset as PresetId)) {
    return "unknown preset";
  }
  const syncedAt = record["syncedAt"];
  if (typeof syncedAt !== "string") {
    return "syncedAt must be a string";
  }
  const variablesRaw = record["variables"];
  if (typeof variablesRaw !== "object" || variablesRaw === null || Array.isArray(variablesRaw)) {
    return "variables must be an object of { name: version }";
  }
  // null プロトタイプ: 変数名は任意の文字列なので、`__proto__` のような名前を
  // 継承プロパティに解決させない
  const variables: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const [name, version] of Object.entries(variablesRaw)) {
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) {
      return "variables must map names to positive integer versions";
    }
    variables[name] = version;
  }
  return { version: 1, target: expectedTarget, preset: preset as PresetId, syncedAt, variables };
}

/** レシートのファイル表現(決定論的: 名前の昇順 — 同じ内容は同じバイト列)。 */
export function encodeReceipt(receipt: SyncReceipt): Uint8Array {
  const variables: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const name of Object.keys(receipt.variables).toSorted()) {
    variables[name] = receipt.variables[name] as number;
  }
  return new TextEncoder().encode(
    JSON.stringify({
      version: 1,
      target: receipt.target,
      preset: receipt.preset,
      syncedAt: receipt.syncedAt,
      variables,
    }),
  );
}

/** The receipt as last stored, plus the coordinates needed to write the next one. */
export interface LoadedReceipt {
  /** null = このターゲットのレシートはまだ無い(初回同期)。 */
  readonly receipt: SyncReceipt | null;
  /** レシート変数の現在の version(無ければ 0)。上限接近の警告に使う。 */
  readonly variableVersion: number;
  /** 検証に使ったビュー(有界再同期で前進していることがある)。 */
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
}

/**
 * Reads the receipt for `target` from the receipts environment (a verified,
 * decrypted pull of that environment — the same path as `maruhi pull`).
 * A receipt written by another preset is refused: its deliveries describe a
 * different platform, so acting on it (deletes by name, versions treated as
 * delivered) would be wrong — reset the receipt instead.
 */
export function loadReceipt(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly target: string;
  /** ターゲットの現在の preset(レシートの書き手の preset と突合する)。 */
  readonly preset: PresetId;
}): Effect.Effect<LoadedReceipt, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVariables(input);
    const name = receiptVariableName(input.target);
    const variable = pulled.variables.find((entry) => entry.name === name);
    if (variable === undefined) {
      // 有界再同期で前進したビューを返す(後続の pull / push が引き継ぐ)
      return {
        receipt: null,
        variableVersion: 0,
        verified: pulled.verified,
        warnings: pulled.warnings,
      };
    }
    // 剥がす理由: レシート JSON の解釈(レシートは名前と version の写像で、秘密
    // 値ではない。産物は構造体のみで、文面には理由しか出さない)
    const text = decodeValueText(Redacted.value(variable.value));
    const decoded = text === null ? "not valid UTF-8" : decodeReceipt(text, input.target);
    if (typeof decoded === "string") {
      return yield* Effect.fail(
        cliError(
          `The receipt variable ${displayText(name)} in environment ${displayText(input.environmentId)} is not a valid sync receipt (${decoded}). Remove it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\` and apply again (the next apply rewrites every variable of the target)`,
        ),
      );
    }
    // preset が違うレシートの届け先は別のプラットフォーム: 名前で消す削除も
    // 「届いた」扱いの version も意味を失う。作り直しを名指しで案内する。
    // このレシートは旧届け先に何が居るかの唯一の記録なので、消させる前に
    // 名前の一覧をここで見せる(driverFailureMessage の pendingHint と同型。
    // maruhi は旧届け先を消しに行かない: 設定が今指していない先に書く・消す
    // ことはしない)
    if (decoded.preset !== input.preset) {
      const delivered = Object.keys(decoded.variables).toSorted();
      const orphanHint =
        delivered.length === 0
          ? ""
          : ` Those deliveries stay at the ${decoded.preset} destination and this receipt is their only record, so remove them there yourself first: ${delivered.map(displayText).join(", ")}.`;
      return yield* Effect.fail(
        cliError(
          `The receipt variable ${displayText(name)} in environment ${displayText(input.environmentId)} was written by the ${decoded.preset} preset, but target ${displayText(input.target)} is now configured with preset ${input.preset}, so its deliveries do not describe this destination.${orphanHint} Remove it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\` and apply again (the next apply rewrites every variable of the target)`,
        ),
      );
    }
    return {
      receipt: decoded,
      variableVersion: variable.version,
      verified: pulled.verified,
      warnings: pulled.warnings,
    };
  });
}

/** 上限接近の警告文(該当しなければ null)。 */
export function receiptVersionWarning(input: {
  readonly target: string;
  readonly environmentId: string;
  readonly variableVersion: number;
}): string | null {
  if (input.variableVersion < RECEIPT_VERSION_WARN_AT) {
    return null;
  }
  const name = receiptVariableName(input.target);
  return `the receipt variable ${displayText(name)} is at version ${input.variableVersion} of the ${RECEIPT_VERSION_LIMIT}-version limit per variable. Before it fills up, delete it with \`maruhi var rm ${displayText(name)} --env ${displayText(input.environmentId)}\`; the next apply starts a fresh receipt and rewrites every variable of the target once`;
}

/**
 * Writes a receipt as a new version of the receipt variable (creating it on
 * the first sync). Signed with the caller's master key like any push (§4.1).
 */
export function storeReceipt(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  readonly receipt: SyncReceipt;
}): Effect.Effect<{ readonly version: number; readonly warnings: readonly string[] }, CliError> {
  return Effect.map(
    pushVariable({
      client: input.client,
      environmentId: input.environmentId,
      recipient: input.recipient,
      name: receiptVariableName(input.receipt.target),
      value: Redacted.make(encodeReceipt(input.receipt), { label: "variable-value" }),
      verified: input.verified,
      resync: input.resync,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
      floor: input.floor,
    }),
    (pushed) => ({ version: pushed.version, warnings: pushed.warnings }),
  );
}
