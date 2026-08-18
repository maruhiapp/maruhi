// リポジトリアンカー(CRYPTO_SPEC §6.3 帯域外アンカー (b))。
//
// プロジェクトのソースリポジトリへコミットする非機密アンカーファイル:
// genesis ハッシュ(= projectId)・検証済みヘッド(hash + seq)・環境ごとの
// 「その時点のチェーン導出現エポック」。ワークロードリース(§9.1)の受信
// クライアント(ci-run.ts)は、チェーン検証に加えて「アンカーのヘッドを含み、
// 環境エポックがアンカー以上」のビューのみを受理する(SHOULD)。CI という
// 床なし・自動・無人の最弱クライアントへの巻き戻し配布(例: インシデント
// ローテーション後に旧ビューを配布し、漏洩済み credential を再デプロイさせ
// 続ける)をこれで検出可能にする。
//
// 生成は `maruhi project anchor`(メンバーの検証済みビューから stdout へ)。
// 内容はハッシュ・連番・エポック番号のみで、平文値・鍵素材を含まない
// (ディスクレス不変条件と両立 — 書くのは利用者のリダイレクトであり非機密)。

import { readFile } from "node:fs/promises";

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { VerifiedProject } from "./sync.ts";

/** A repository anchor file (CRYPTO_SPEC §6.3 out-of-band anchor (b)). */
export interface RepositoryAnchor {
  readonly version: 1;
  /** genesis ハッシュ(= projectId — §6.4)。 */
  readonly projectId: string;
  /** 生成時点の検証済みチェーンヘッド。 */
  readonly headSeq: number;
  readonly headHashHex: string;
  /** 環境 ID → 生成時点のチェーン導出現エポック。 */
  readonly environments: Readonly<Record<string, number>>;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

/** 検証済みビューからアンカーを組み立てる(`maruhi project anchor`)。 */
export function buildRepositoryAnchor(verified: VerifiedProject): RepositoryAnchor {
  const environments: Record<string, number> = {};
  // 決定論的な出力(コミット差分を安定させる)のため環境 ID の昇順で並べる
  for (const environmentId of [...verified.state.environments.keys()].toSorted()) {
    const environment = verified.state.environments.get(environmentId);
    if (environment !== undefined) {
      environments[environmentId] = environment.currentEpoch;
    }
  }
  return {
    version: 1,
    projectId: verified.projectId,
    headSeq: verified.state.headSeq,
    headHashHex: verified.state.headHashHex,
    environments,
  };
}

/** アンカーのファイル表現(コミットしやすい pretty JSON + 終端改行)。 */
export function formatRepositoryAnchor(anchor: RepositoryAnchor): string {
  return `${JSON.stringify(anchor, null, 2)}\n`;
}

function isPositiveInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

/** environments フィールドの解釈(不正なら理由の文字列)。 */
function parseAnchorEnvironments(value: unknown): Readonly<Record<string, number>> | string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "environments must be an object of { environmentId: epoch }";
  }
  const environments: Record<string, number> = {};
  for (const [environmentId, epoch] of Object.entries(value)) {
    if (!isEnvironmentId(environmentId) || !isPositiveInt(epoch)) {
      return "environments must map environment IDs to positive integer epochs";
    }
    environments[environmentId] = epoch;
  }
  return environments;
}

/** headSeq / headHashHex の解釈(不正なら理由の文字列)。 */
function parseAnchorHead(
  record: Record<string, unknown>,
): { readonly headSeq: number; readonly headHashHex: string } | string {
  const headSeq = record["headSeq"];
  const headHashHex = record["headHashHex"];
  if (!isPositiveInt(headSeq)) {
    return "headSeq must be a positive integer";
  }
  if (typeof headHashHex !== "string" || !SHA256_HEX.test(headHashHex)) {
    return "headHashHex must be 64 lowercase hex digits";
  }
  return { headSeq, headHashHex };
}

/** トップレベルの形と version / projectId の解釈(不正なら理由の文字列)。 */
function anchorRecordOf(content: string): Record<string, unknown> | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return "not valid JSON";
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return "the top level must be an object";
  }
  const record = parsed as Record<string, unknown>;
  if (record["version"] !== 1) {
    return "unsupported anchor version (expected 1)";
  }
  return record;
}

/** アンカー JSON の解釈(不正なら理由の文字列)。 */
function parseRepositoryAnchor(content: string): RepositoryAnchor | string {
  const record = anchorRecordOf(content);
  if (typeof record === "string") {
    return record;
  }
  const projectId = record["projectId"];
  if (typeof projectId !== "string" || !isProjectId(projectId)) {
    return "projectId must be the genesis hash (64 hex digits)";
  }
  const head = parseAnchorHead(record);
  if (typeof head === "string") {
    return head;
  }
  const environments = parseAnchorEnvironments(record["environments"]);
  if (typeof environments === "string") {
    return environments;
  }
  return { version: 1, projectId, ...head, environments };
}

/** `--anchor <file>` の読み込み(生成は `maruhi project anchor`)。 */
export function loadRepositoryAnchor(path: string): Effect.Effect<RepositoryAnchor, CliError> {
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () => cliError("Cannot read the --anchor file (check the path)"),
    });
    const parsed = parseRepositoryAnchor(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(
        cliError(
          `The --anchor file is invalid: ${parsed}. Regenerate it with \`maruhi project anchor\``,
        ),
      );
    }
    return parsed;
  });
}

/**
 * アンカー検査(§6.3 (b) / §9.1 の検証義務 (2)): 検証済みビューが
 * (i) アンカーと同じ genesis を持ち、(ii) アンカーのピン留めヘッドを当該 seq に
 * 含み、(iii) アンカーされた各環境のチェーン導出現エポックがアンカー以上で
 * あること。不一致は署名検証済み成果物とコミット済みアンカーの矛盾 = 巻き戻し・
 * fork 配布の証拠なので拒否する(SHOULD の強い側 — checkInviteAnchor と同型)。
 */
export function checkRepositoryAnchor(input: {
  readonly anchor: RepositoryAnchor;
  readonly verified: VerifiedProject;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const { anchor, verified } = input;
    const evidenceHint =
      "The verification material is the committed anchor file plus the distributed chain (CRYPTO_SPEC §6.3 out-of-band anchor (b))";
    if (anchor.projectId !== verified.projectId) {
      return yield* Effect.fail(
        cliError(
          `Repository-anchor check failed: the anchor's genesis hash does not match the pinned project ID. The anchor file belongs to a different project, or the CI configuration is wrong. ${evidenceHint}`,
        ),
      );
    }
    if (verified.history.entryHashAt(anchor.headSeq) !== anchor.headHashHex) {
      return yield* Effect.fail(
        cliError(
          `Repository-anchor check failed: the distributed chain does not contain the anchored head (seq=${anchor.headSeq}). This suggests a server-side rollback or fork distribution — do not trust this response. ${evidenceHint}`,
        ),
      );
    }
    for (const [environmentId, anchoredEpoch] of Object.entries(anchor.environments)) {
      // 環境の存在自体がチェーン導出(§6.2)。アンカー済み環境の不在は、
      // create_environment を含む区間ごと巻き戻された形なので同じ証拠
      // (文言は分ける — 後退と不在では観測した事実が違う)
      const environment = verified.state.environments.get(environmentId);
      if (environment === undefined) {
        return yield* Effect.fail(
          cliError(
            `Repository-anchor check failed: anchored environment ${environmentId} does not exist on the distributed chain. This suggests a rollback past the environment's creation — do not trust this response. ${evidenceHint}`,
          ),
        );
      }
      if (environment.currentEpoch < anchoredEpoch) {
        return yield* Effect.fail(
          cliError(
            `Repository-anchor check failed: environment ${environmentId} has a chain-derived epoch below the anchored epoch (${anchoredEpoch}). This suggests distribution of a pre-rotation view (a leaked credential could be re-deployed) — do not trust this response. ${evidenceHint}`,
          ),
        );
      }
    }
  });
}
