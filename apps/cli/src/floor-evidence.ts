// fork 証拠の報告 UX(CRYPTO_SPEC §6.3 / §14.2-5)。
//
// 床検査の不一致は「§6.3 の署名検証を通過したデータ同士の矛盾」なので、双方の
// 座標・signed bytes ハッシュ・宣言ヘッドを人間が第三者へ提示可能な形で出力する
// (同一座標への内容の異なる 2 つの有効署名 = サーバーの equivocation または
// 鍵漏洩の否認不能な証拠 — §14.2-5)。**平文値・鍵素材は含めない**(識別は
// すべて ID とハッシュ — ディスクレス不変条件)。

import type { FloorViolation } from "./floor-check.ts";
import { floorViolationLabel } from "./floor-check.ts";

/** 証拠に含める座標(すべて ID — 名前は含めない: 名前自体が係争対象になりうる)。 */
export interface FloorEvidenceCoordinates {
  readonly projectId: string;
  readonly environmentId?: string;
}

function headText(seq: number, hashHex: string): string {
  return `seq=${seq} hash=${hashHex}`;
}

function coordinateLine(coordinates: FloorEvidenceCoordinates, variableId?: string | null): string {
  const parts = [`project=${coordinates.projectId}`];
  if (coordinates.environmentId !== undefined) {
    parts.push(`environment=${coordinates.environmentId}`);
  }
  if (variableId !== undefined && variableId !== null) {
    parts.push(`variable=${variableId}`);
  }
  return `  座標: ${parts.join(" ")}`;
}

function floorVariableLines(violation: Extract<FloorViolation, { kind: "variable-omitted" }>) {
  const floor = violation.floor;
  return floor.status === "active"
    ? [
        `  床の記録(過去に検証済み): status=active version=${floor.version} epoch=${floor.epoch}`,
        `    value_signed_bytes_hash=${floor.valueSigHashHex}`,
        `    metaVersion=${floor.metaVersion} meta_signed_bytes_hash=${floor.metaSigHashHex}`,
      ]
    : [
        `  床の記録(過去に検証済み): status=deleted metaVersion=${floor.metaVersion}`,
        `    meta_signed_bytes_hash=${floor.metaSigHashHex}`,
      ];
}

type ValueViolation = Extract<
  FloorViolation,
  { kind: "value-rollback" | "value-equivocation" | "value-epoch-regression" }
>;

function valueEvidenceLines(violation: ValueViolation): readonly string[] {
  return [
    `  床の記録(過去に検証済み): version=${violation.floor.version} epoch=${violation.floor.epoch}`,
    `    value_signed_bytes_hash=${violation.floor.valueSigHashHex}`,
    `  今回の配布: version=${violation.pulled.version} epoch=${violation.pulled.epoch}`,
    `    value_signed_bytes_hash=${violation.pulled.valueSigHashHex}`,
    `    宣言ヘッド: ${headText(violation.pulled.chainHeadSeq, violation.pulled.chainHeadHashHex)}`,
  ];
}

type MetaViolation = Extract<
  FloorViolation,
  { kind: "meta-rollback" | "meta-equivocation" | "deletion-revoked" | "tombstone-mismatch" }
>;

function metaEvidenceLines(violation: MetaViolation): readonly string[] {
  return [
    `  床の記録(過去に検証済み): metaVersion=${violation.floor.metaVersion}`,
    `    meta_signed_bytes_hash=${violation.floor.metaSigHashHex}`,
    `  今回の配布: status=${violation.pulled.status} metaVersion=${violation.pulled.metaVersion}`,
    `    meta_signed_bytes_hash=${violation.pulled.metaSigHashHex}`,
    `    宣言ヘッド: ${headText(violation.pulled.chainHeadSeq, violation.pulled.chainHeadHashHex)}`,
  ];
}

type ChainViolation = Extract<FloorViolation, { kind: "chain-shortened" | "chain-diverged" }>;

function chainEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: ChainViolation,
): readonly string[] {
  const divergedLine =
    violation.kind === "chain-diverged"
      ? [
          `  今回のチェーンの同 seq のエントリハッシュ: ${violation.actualHashHex === "" ? "(存在しない)" : violation.actualHashHex}`,
        ]
      : [];
  return [
    coordinateLine(coordinates),
    `  床の記録(過去に検証済みのヘッド): ${headText(violation.floorHead.seq, violation.floorHead.hashHex)}`,
    ...divergedLine,
    `  今回の同期ヘッド: ${headText(violation.syncedHead.seq, violation.syncedHead.hashHex)}`,
  ];
}

function variableEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: Exclude<FloorViolation, ChainViolation>,
): readonly string[] {
  if (violation.kind === "variable-omitted") {
    return [coordinateLine(coordinates, violation.variableId), ...floorVariableLines(violation)];
  }
  if (violation.kind === "stale-epoch-injection") {
    return [
      coordinateLine(coordinates, violation.variableId),
      `  規則 (c) の基準: pull 時点エポック基準=${violation.baselineEpoch}(前回成功 pull 時点のチェーン導出現エポック)`,
      `  床の記録 version=${violation.floorVersion}(0 = 床に記録なし)`,
      `  今回の配布: version=${violation.pulled.version} epoch=${violation.pulled.epoch}`,
      `    value_signed_bytes_hash=${violation.pulled.valueSigHashHex}`,
      `    宣言ヘッド: ${headText(violation.pulled.chainHeadSeq, violation.pulled.chainHeadHashHex)}`,
    ];
  }
  if (
    violation.kind === "value-rollback" ||
    violation.kind === "value-equivocation" ||
    violation.kind === "value-epoch-regression"
  ) {
    return [coordinateLine(coordinates, violation.variableId), ...valueEvidenceLines(violation)];
  }
  // メタ系 4 種(環境メタの violation は variableId が null — 座標行は環境まで)
  return [coordinateLine(coordinates, violation.variableId), ...metaEvidenceLines(violation)];
}

function evidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: FloorViolation,
): readonly string[] {
  if (violation.kind === "chain-shortened" || violation.kind === "chain-diverged") {
    return chainEvidenceLines(coordinates, violation);
  }
  return variableEvidenceLines(coordinates, violation);
}

/**
 * 床検査の不一致を、拒否メッセージ + 提示可能な証拠(座標・両 signed bytes
 * ハッシュ・宣言ヘッド)の複数行テキストへ整形する。
 */
export function formatFloorViolation(
  coordinates: FloorEvidenceCoordinates,
  violation: FloorViolation,
): string {
  return [
    `ローカル床検査で不整合を検出しました: ${floorViolationLabel(violation)}`,
    ...evidenceLines(coordinates, violation),
    "  これは過去に検証済みの署名データと今回の配布の矛盾であり、サーバーの equivocation または署名鍵漏洩の証拠です(CRYPTO_SPEC §14.2-5)。この出力とローカル床ファイルを保全し、プロジェクト管理者に提示してください",
  ].join("\n");
}
