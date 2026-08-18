// fork 証拠の報告 UX(CRYPTO_SPEC §6.3 / §14.2-5)。
//
// 床検査の不一致は「§6.3 の署名検証を通過したデータ同士の矛盾」なので、双方の
// 座標・signed bytes ハッシュ・宣言ヘッドを人間が第三者へ提示可能な形で出力する
// (同一座標への内容の異なる 2 つの有効署名 = サーバーの equivocation または
// 鍵漏洩の否認不能な証拠 — §14.2-5)。**平文値・鍵素材は含めない**(識別は
// すべて ID とハッシュ — ディスクレス不変条件)。

import { displayText } from "./display.ts";
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
  return `  coordinates: ${parts.join(" ")}`;
}

function floorVariableLines(violation: Extract<FloorViolation, { kind: "variable-omitted" }>) {
  const floor = violation.floor;
  return floor.status === "active"
    ? [
        `  floor record (previously verified): status=active version=${floor.version} epoch=${floor.epoch}`,
        `    value_signed_bytes_hash=${floor.valueSigHashHex}`,
        `    metaVersion=${floor.metaVersion} meta_signed_bytes_hash=${floor.metaSigHashHex}`,
      ]
    : [
        `  floor record (previously verified): status=deleted metaVersion=${floor.metaVersion}`,
        `    meta_signed_bytes_hash=${floor.metaSigHashHex}`,
      ];
}

type ValueViolation = Extract<
  FloorViolation,
  { kind: "value-rollback" | "value-equivocation" | "value-epoch-regression" }
>;

function pulledValueLines(pulled: {
  readonly version: number;
  readonly epoch: number;
  readonly valueSigHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}): readonly string[] {
  return [
    `  this distribution: version=${pulled.version} epoch=${pulled.epoch}`,
    `    value_signed_bytes_hash=${pulled.valueSigHashHex}`,
    `    declared head: ${headText(pulled.chainHeadSeq, pulled.chainHeadHashHex)}`,
    // user_id はワイヤ上は長さ制約のみの自由文字列 — 端末へ出す前に中和する
    `    writer signature: writer=${displayText(pulled.writerUserId)} fp=${pulled.writerKeyFingerprintHex}`,
    `    signature=${pulled.signatureHex}`,
  ];
}

function valueEvidenceLines(violation: ValueViolation): readonly string[] {
  return [
    `  floor record (previously verified): version=${violation.floor.version} epoch=${violation.floor.epoch}`,
    `    value_signed_bytes_hash=${violation.floor.valueSigHashHex}`,
    ...pulledValueLines(violation.pulled),
  ];
}

type MetaViolation = Extract<
  FloorViolation,
  { kind: "meta-rollback" | "meta-equivocation" | "deletion-revoked" | "tombstone-mismatch" }
>;

function metaEvidenceLines(violation: MetaViolation): readonly string[] {
  return [
    `  floor record (previously verified): metaVersion=${violation.floor.metaVersion}`,
    `    meta_signed_bytes_hash=${violation.floor.metaSigHashHex}`,
    `  this distribution: status=${violation.pulled.status} metaVersion=${violation.pulled.metaVersion}`,
    `    meta_signed_bytes_hash=${violation.pulled.metaSigHashHex}`,
    `    declared head: ${headText(violation.pulled.chainHeadSeq, violation.pulled.chainHeadHashHex)}`,
    // user_id はワイヤ上は長さ制約のみの自由文字列 — 端末へ出す前に中和する
    `    author signature: author=${displayText(violation.pulled.authorUserId)} fp=${violation.pulled.authorKeyFingerprintHex}`,
    `    signature=${violation.pulled.signatureHex}`,
  ];
}

type ManifestViolation = Extract<
  FloorViolation,
  {
    kind:
      | "manifest-rollback"
      | "manifest-equivocation"
      | "manifest-omitted"
      | "stale-manifest-injection";
  }
>;

function pulledManifestLines(pulled: {
  readonly manifestVersion: number;
  readonly epoch: number;
  readonly signedBytesHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}): readonly string[] {
  return [
    `  this distribution: manifestVersion=${pulled.manifestVersion} epoch=${pulled.epoch}`,
    `    manifest_signed_bytes_hash=${pulled.signedBytesHashHex}`,
    `    declared head: ${headText(pulled.chainHeadSeq, pulled.chainHeadHashHex)}`,
    // user_id はワイヤ上は長さ制約のみの自由文字列 — 端末へ出す前に中和する
    `    issuer signature: issuer=${displayText(pulled.issuerUserId)} fp=${pulled.issuerKeyFingerprintHex}`,
    `    signature=${pulled.signatureHex}`,
  ];
}

function manifestEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: ManifestViolation,
): readonly string[] {
  if (violation.kind === "manifest-omitted") {
    return [
      coordinateLine(coordinates),
      `  floor record (previously verified): manifestVersion=${violation.floor.manifestVersion} epoch=${violation.floor.epoch}`,
      `    manifest_signed_bytes_hash=${violation.floor.manifestSigHashHex}`,
      "  this distribution: (no manifest)",
    ];
  }
  if (violation.kind === "stale-manifest-injection") {
    return [
      coordinateLine(coordinates),
      `  rule (c) baseline: pull-time epoch baseline=${violation.baselineEpoch} (the chain-derived current epoch at the last successful pull)`,
      `  floor record manifestVersion=${violation.floorManifestVersion} (0 = no floor record)`,
      ...pulledManifestLines(violation.pulled),
    ];
  }
  return [
    coordinateLine(coordinates),
    `  floor record (previously verified): manifestVersion=${violation.floor.manifestVersion} epoch=${violation.floor.epoch}`,
    `    manifest_signed_bytes_hash=${violation.floor.manifestSigHashHex}`,
    ...pulledManifestLines(violation.pulled),
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
          `  this chain's entry hash at that seq: ${violation.actualHashHex === "" ? "(absent)" : violation.actualHashHex}`,
        ]
      : [];
  return [
    coordinateLine(coordinates),
    `  floor record (previously verified head): ${headText(violation.floorHead.seq, violation.floorHead.hashHex)}`,
    ...divergedLine,
    `  this sync's head: ${headText(violation.syncedHead.seq, violation.syncedHead.hashHex)}`,
  ];
}

function variableEvidenceLines(
  coordinates: FloorEvidenceCoordinates,
  violation: Exclude<FloorViolation, ChainViolation | ManifestViolation>,
): readonly string[] {
  if (violation.kind === "variable-omitted") {
    return [coordinateLine(coordinates, violation.variableId), ...floorVariableLines(violation)];
  }
  if (violation.kind === "stale-epoch-injection") {
    return [
      coordinateLine(coordinates, violation.variableId),
      `  rule (c) baseline: pull-time epoch baseline=${violation.baselineEpoch} (the chain-derived current epoch at the last successful pull)`,
      `  floor record version=${violation.floorVersion} (0 = no floor record)`,
      ...pulledValueLines(violation.pulled),
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
  if (
    violation.kind === "manifest-rollback" ||
    violation.kind === "manifest-equivocation" ||
    violation.kind === "manifest-omitted" ||
    violation.kind === "stale-manifest-injection"
  ) {
    return manifestEvidenceLines(coordinates, violation);
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
    `The local floor check detected an inconsistency: ${floorViolationLabel(violation)}`,
    ...evidenceLines(coordinates, violation),
    "  This is a contradiction between previously verified signed data and this distribution — evidence of server equivocation or a leaked signing key (CRYPTO_SPEC §14.2-5). Preserve this output and the local floor file, and present them to the project administrators",
  ].join("\n");
}
