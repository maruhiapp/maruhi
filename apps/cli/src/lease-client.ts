// ワークロードリース応答の検証・開封・復号(CRYPTO_SPEC §9.1 の受信ワーク
// ロードの検証義務 / AUTH_SPEC §14-2)。
//
// リース応答は**自己完結**である: チェーン・現エポック・全アクティブ変数の
// 最新値・最新メタステートメント・リースラップ済み DEK がすべて 1 応答に
// 同梱される(チェーン API は非メンバーへ 404 を返すため、これが唯一の配布
// 経路 — §14-2)。検証材料を他のエンドポイントへ取りに行かない。
//
// 検証義務の対応:
//   (1) チェーン検証 — verifyChainSnapshot(sync.ts と同一実装)。genesis =
//       projectId は CI 設定(--project)に事前固定された値と照合する
//   (2) リポジトリアンカー(SHOULD)— anchor.ts(--anchor 指定時)
//   (3) DEK コミットメント照合(§5.2)— unwrapLeaseDek の開封後・使用前。
//       リースラップは §5.1 登録署名を持たない(サーバー生成・応答スコープ —
//       LeasedDek 型が構造的に区別する)ため deks.ts の署名検証段は適用されず、
//       エポック上限・重複・コミットメント存在の検査をここに置く。DEK 長の
//       検査は発明しない(32 バイト以外の Seal はコミットメント照合で落ちる —
//       セキュリティレビュー A-5)
//   (4) 値署名・メタステートメント検証 — values.ts の verifyLeaseDistribution
//       (future head は再同期せず即時拒否 — チェーンが同梱される以上、
//       「自分のチェーンが古いだけ」という正直な説明が存在しない)
//
// 床は使わない: ワークロードは床を持たない初回同期クラス(§14.3-3)で、
// その主要な緩和が (2) のアンカーである。

import type {
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  LeasedDek,
} from "@maruhi/api-schema";
import type { EnvironmentId, ProjectId } from "@maruhi/core";
import type { ChainEntry, EncryptionKeyPair, LeaseClaims } from "@maruhi/crypto";
import {
  computeLeaseClaimsDigest,
  decodeHex,
  SUITE_ID,
  unwrapLeaseDek,
  verifyDekCommitment,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { RepositoryAnchor } from "./anchor.ts";
import { checkRepositoryAnchor } from "./anchor.ts";
import { requireChainEnvironment } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import type { DecryptedVariable } from "./pull.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { verifyChainSnapshot, type VerifiedProject } from "./sync.ts";
import { type PulledWire, verifyLeaseDistribution } from "./values.ts";

/** リース応答のワイヤ形(api-schema の LeaseResponseSchema の構造型)。 */
export interface LeaseResponseWire {
  readonly projectId: string;
  readonly environmentId: string;
  readonly currentEpoch: number;
  readonly chain: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly PulledWire[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly leases: readonly LeasedDek[];
}

/** リース応答から検証・復号された実行材料(run と同じ注入境界へ渡る)。 */
export interface VerifiedLeaseMaterial {
  readonly variables: readonly DecryptedVariable[];
  /** 非 NFC 名の配布などの SHOULD 警告(呼び出し側が表示する)。 */
  readonly warnings: readonly string[];
}

/** 1 リースラップの開封結果(タグ付き Result — deks.ts の UnwrapResult と同型)。 */
type LeaseUnwrapResult =
  | { readonly kind: "ok"; readonly dek: Uint8Array }
  | { readonly kind: "rejected"; readonly message: string };

/**
 * 1 リースラップの開封 + コミットメント照合(§5.2 / §9.1 検証義務 (3))。
 * 照合に成功するまで DEK はこの関数の外へ出ない。座標は自前の検証済み値
 * (genesis ハッシュ・要求環境)から組む。
 */
async function unwrapOneLease(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly claimsDigestHex: string;
  readonly lease: LeasedDek;
  /** チェーン導出の当該 (environment, epoch) のコミットメント(§5.2)。 */
  readonly expectedCommitmentHex: string;
}): Promise<LeaseUnwrapResult> {
  const { verified, environmentId, lease } = input;
  const enc = decodeHex(lease.encHex);
  const ciphertext = decodeHex(lease.ciphertextHex);
  if (enc === null || ciphertext === null) {
    return { kind: "rejected", message: `The leased DEK is malformed (epoch=${lease.epoch})` };
  }
  const dek = await unwrapLeaseDek({
    workloadKeyPair: input.workloadKeyPair,
    wrapped: { enc, ciphertext },
    context: {
      projectId: verified.projectId,
      environmentId,
      epoch: lease.epoch,
      claimsDigestHex: input.claimsDigestHex,
    },
  });
  if (!dek.ok) {
    return {
      kind: "rejected",
      message: `Cannot open the leased DEK (epoch=${lease.epoch}). The lease was issued for a different workload identity or context (claims-digest mismatch), or the response is corrupt`,
    };
  }
  const commitment = await verifyDekCommitment({
    context: {
      suite: SUITE_ID,
      projectId: verified.projectId,
      environmentId,
      epoch: lease.epoch,
    },
    dek: dek.value,
    expectedCommitmentHex: input.expectedCommitmentHex,
  });
  if (!commitment.ok) {
    return {
      kind: "rejected",
      message: `The leased DEK does not match the commitment on the chain (epoch=${lease.epoch}). This may be a fake DEK injected by a compromised server — do not trust this response`,
    };
  }
  return { kind: "ok", dek: dek.value };
}

/**
 * リースラップの集合検査(申告 epoch のチェーン上限・重複拒否・コミットメントの
 * 存在)。deks.ts の verifyAndUnwrapDeks のループ前段と同じ規律で、通れば
 * 当該エポックの期待コミットメントを返す。
 */
function leaseEpochProblem(
  chainEpoch: number,
  seen: ReadonlySet<number>,
  lease: LeasedDek,
): string | null {
  if (lease.suite !== SUITE_ID) {
    return `The leased DEK uses an unknown suite (${lease.suite})`;
  }
  if (lease.epoch > chainEpoch) {
    return `A leased DEK for epoch ${lease.epoch}, beyond the chain's current epoch (${chainEpoch}), was served (the response contradicts the chain)`;
  }
  if (seen.has(lease.epoch)) {
    return `Duplicate leased DEKs for the same epoch (epoch=${lease.epoch})`;
  }
  return null;
}

/**
 * リースラップ済み DEK の開封とコミットメント照合(§9.1 の検証義務 (3))。
 * deks.ts の verifyAndUnwrapDeks と同じ規律(申告 epoch のチェーン上限・重複
 * 拒否・チェーン導出コミットメントとの照合まで DEK を使わない)を、§5.1
 * 登録署名を持たないリースラップに適用した形。
 */
function unwrapLeases(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly claims: LeaseClaims;
  readonly leases: readonly LeasedDek[];
}): Effect.Effect<ReadonlyMap<number, Redacted.Redacted<Uint8Array>>, CliError> {
  return Effect.gen(function* () {
    const { verified, environmentId } = input;
    const environment = yield* requireChainEnvironment(verified, environmentId);
    const chainEpoch = environment.currentEpoch;
    // claims digest は検証付きの入口(computeLeaseClaimsDigest)のみを使う —
    // builder 直接使用は空フィールドガードを迂回する(セキュリティレビュー A-5)
    const digest = yield* Effect.tryPromise({
      try: () => computeLeaseClaimsDigest(input.claims),
      catch: () => cliError("Failed to compute the lease claims digest (crypto error)"),
    });
    if (!digest.ok) {
      return yield* Effect.fail(
        cliError("Failed to compute the lease claims digest (the OIDC claims are unusable)"),
      );
    }
    const byEpoch = new Map<number, Redacted.Redacted<Uint8Array>>();
    for (const lease of input.leases) {
      const problem = leaseEpochProblem(chainEpoch, new Set(byEpoch.keys()), lease);
      if (problem !== null) {
        return yield* Effect.fail(cliError(problem));
      }
      const expectedCommitmentHex = environment.dekCommitments.get(lease.epoch);
      if (expectedCommitmentHex === undefined) {
        return yield* Effect.fail(
          cliError(
            `No commitment for epoch ${lease.epoch} exists on the chain (a chain-derivation inconsistency)`,
          ),
        );
      }
      const result = yield* Effect.tryPromise({
        try: () =>
          unwrapOneLease({
            verified,
            environmentId,
            workloadKeyPair: input.workloadKeyPair,
            claimsDigestHex: digest.value,
            lease,
            expectedCommitmentHex,
          }),
        catch: () => cliError(`Leased-DEK unwrap failed (epoch=${lease.epoch} — crypto error)`),
      });
      if (result.kind === "rejected") {
        return yield* Effect.fail(cliError(result.message));
      }
      // 開封済み DEK はここで包む(§5.2 照合を通った後 — 照合前の DEK は
      // unwrapOneLease の内側から出ない)
      byEpoch.set(lease.epoch, Redacted.make(result.dek, { label: "dek" }));
    }
    return byEpoch;
  });
}

/**
 * Verifies a lease response end to end (CRYPTO_SPEC §9.1 duties (1)–(4)) and
 * decrypts every latest value. Nothing in the response is trusted before it
 * passes: the chain is re-verified against the pre-pinned genesis, declared
 * coordinates are cross-checked against derived state, every statement and
 * value signature is verified, and every DEK must match its chain-published
 * commitment before use.
 */
export function verifyLeaseResponse(input: {
  /** CI 設定に事前固定された genesis(= `--project` — §9.1 検証義務 (1))。 */
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly response: LeaseResponseWire;
  readonly claims: LeaseClaims;
  readonly workloadKeyPair: EncryptionKeyPair;
  /** リポジトリアンカー(§6.3 (b) — SHOULD。--anchor 指定時のみ)。 */
  readonly anchor: RepositoryAnchor | null;
}): Effect.Effect<VerifiedLeaseMaterial, CliError> {
  return Effect.gen(function* () {
    const response = input.response;
    // 申告座標の整合(§6.3-5 と同じ姿勢): 要求した座標と応答の申告が食い違う
    // 応答は、以降の検証がどのみち落とすが、何が食い違ったかを先に可視化する
    if (response.projectId !== input.projectId || response.environmentId !== input.environmentId) {
      return yield* Effect.fail(
        cliError(
          "The lease response declares coordinates that do not match the requested project / environment (an inconsistent server response)",
        ),
      );
    }
    // (1) チェーン検証: 同梱チェーンの全再検証 + genesis ハッシュ = 事前固定の
    // projectId + 申告ヘッドと導出ヘッドの整合(sync.ts と同一実装)
    const verified = yield* verifyChainSnapshot({
      projectId: input.projectId,
      entries: response.chain,
      claimedHeadSeq: response.headSeq,
      claimedHeadHashHex: response.headHashHex,
    });
    // (2) リポジトリアンカー(SHOULD): ピン留めヘッドの包含 + 環境エポックの
    // 非後退(巻き戻し配布の検出 — CI は床を持たないため、これが代替)
    if (input.anchor !== null) {
      yield* checkRepositoryAnchor({ anchor: input.anchor, verified });
    }
    // 現エポックはチェーン導出値のみを使う(§6.2)。申告 currentEpoch は
    // 導出値との一致だけを検査する(申告値を信用しない)
    const chainEpoch = (yield* requireChainEnvironment(verified, input.environmentId)).currentEpoch;
    if (response.currentEpoch !== chainEpoch) {
      return yield* Effect.fail(
        cliError(
          `The lease response declares epoch ${response.currentEpoch}, but the chain derives epoch ${chainEpoch} (the response contradicts the chain)`,
        ),
      );
    }
    // (4) 値署名・メタステートメント検証(future head は即時拒否)
    const distribution = yield* verifyLeaseDistribution({
      verified,
      environmentId: input.environmentId,
      wire: {
        statement: response.statement,
        variables: response.variables,
        deletedVariables: response.deletedVariables,
      },
    });
    // (3) リースラップの開封 + DEK コミットメント照合
    const deksByEpoch = yield* unwrapLeases({
      verified,
      environmentId: input.environmentId,
      workloadKeyPair: input.workloadKeyPair,
      claims: input.claims,
      leases: response.leases,
    });
    // 復号(run / rotate と同じ decryptVerifiedValue — 復号文脈は検証済み
    // 座標から組み、値の epoch に対応するラップの欠けは硬い失敗)
    const variables: DecryptedVariable[] = [];
    for (const variable of distribution.variables) {
      const plaintext = yield* decryptVerifiedValue({
        verified,
        environmentId: input.environmentId,
        variable,
        deksByEpoch,
        chainEpoch,
      });
      variables.push({
        variableId: variable.variableId,
        name: variable.name,
        version: variable.version,
        epoch: variable.epoch,
        value: plaintext,
      });
    }
    return { variables, warnings: distribution.warnings };
  });
}
