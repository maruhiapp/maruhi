// メタ操作(変数作成・activation・スキーマ設定)の効果確認(AUTH_SPEC
// §12-10 (3) — 1-E′)の共有実装: 成功 = 「2xx を受け取った」ではなく「検証
// 可能な配布物で効果を確認した」。確認材料は metadata-only pull(var.read を
// 記録しない経路 — §12-7)で、自己発行マニフェストの (version, signed-bytes
// hash) を照合する。
//
// - 配布マニフェストが自己発行と完全一致 → 確認完了(床のマニフェスト前進は
//   確認 pull の検証済み観測 — enforceMetadataFloor — が join 済み)
// - 版が前進していても操作の効果が検証済み集合から見える(effectVisible —
//   作成 = 乱数採番 ID の存在、activation / スキーマ再発行 = 発行 metaVersion
//   以上のステートメントの存在)→ 確認済み(直後の並行メタ操作に追い越された形)
// - マニフェスト欠落(旧サーバーの黙殺)・別マニフェスト(同版異ハッシュ)・
//   効果の不在 → 失敗。**床は自己発行マニフェストへ前進していない**(自分の
//   思い込みを床に書かない — 記録されるのは検証済み観測のみ)

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import { type ManifestDigestEntry, type SignedManifest, signNextManifest } from "./manifest.ts";
import type { VerifiedProject } from "./sync.ts";
import { pullVerifiedEnvironmentMetadata, type VerifiedEnvironmentMetadata } from "./values.ts";

/**
 * メタ操作の複合送信の前半の共有実装(push の create / activation・schema set):
 * 操作後のメタ集合を反映したマニフェストの発行(§4.3 / §12-5)と、送信前
 * intent(3-F — journal-before-send)の追記。intent の永続化に失敗したら
 * 呼び出し側は送信しない(fail-closed — appendIntent の失敗がそのまま伝播する)。
 */
export function issueManifestWithIntent(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  /** 発行時点の現エポック(チェーン導出値)。 */
  readonly epoch: number;
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  } | null;
  /** 操作の適用後のメタ集合(tombstone 込み — §4.3 (3) の再計算対象)。 */
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  readonly issuerUserId: string;
  readonly signingKey: CryptoKey;
  readonly floor: FloorHandle;
  /** intent の照合座標(メタ操作の対象変数)。 */
  readonly variableId: string;
}): Effect.Effect<{ readonly manifest: SignedManifest; readonly intentId: string }, CliError> {
  return Effect.gen(function* () {
    const chainHead = {
      seq: input.verified.state.headSeq,
      hashHex: input.verified.state.headHashHex,
    };
    const manifest = yield* signNextManifest({
      verified: input.verified,
      environmentId: input.environmentId,
      epoch: input.epoch,
      previous: input.previous,
      entries: input.entries,
      envMeta: input.envMeta,
      issuerUserId: input.issuerUserId,
      signingKey: input.signingKey,
      chainHead,
    });
    const intentId = yield* input.floor.appendIntent({
      op: "meta-op",
      environmentId: input.environmentId,
      epoch: input.epoch,
      dekCommitmentHex: null,
      variableId: input.variableId,
      manifestVersion: manifest.manifestVersion,
      manifestSigHashHex: manifest.manifestSigHashHex,
      declaredHead: chainHead,
    });
    return { manifest, intentId };
  });
}

/**
 * Confirms one accepted meta mutation against the verified distribution
 * (AUTH_SPEC §12-10 (3)): resolves the 3-F intent on success, and fails with
 * a typed error when the issued manifest was not stored or the effect is not
 * visible in the verified statement set.
 */
export function confirmMetaMutation(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly selfManifest: ManifestFloor;
  /** 送信前に追記した intent(3-F)の id(null = intent なしの呼び出し形)。 */
  readonly intentId: string | null;
  /** 操作の英語名(文面用 — 例: "variable creation" / "activation")。 */
  readonly describe: string;
  /**
   * マニフェスト版が自己発行を追い越していた場合の効果確認(検証済み集合から
   * この操作の効果が見えるか)。作成 = 乱数採番 ID の存在、継続ステートメント =
   * 発行 metaVersion 以上のステートメント / tombstone の存在。
   */
  readonly effectVisible: (metadata: VerifiedEnvironmentMetadata) => boolean;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const metadata = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      verified: input.verified,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `The ${input.describe} was accepted (2xx), but the post-acceptance confirmation against the verified distribution failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}`,
        ),
      ),
    );
    const distributed = metadata.manifest;
    const resolve = (outcome: Parameters<FloorHandle["resolveIntent"]>[1]) =>
      input.intentId === null ? Effect.void : input.floor.resolveIntent(input.intentId, outcome);
    if (
      distributed.manifestVersion === input.selfManifest.manifestVersion &&
      distributed.signedBytesHashHex === input.selfManifest.manifestSigHashHex
    ) {
      return yield* resolve("accepted");
    }
    if (
      distributed.manifestVersion > input.selfManifest.manifestVersion &&
      input.effectVisible(metadata)
    ) {
      // 並行メタ操作に追い越されたが、この操作の効果は検証済み集合に存在する
      return yield* resolve("accepted-superseded");
    }
    if (distributed.manifestVersion === input.selfManifest.manifestVersion) {
      yield* resolve("not-accepted");
      return yield* Effect.fail(
        cliError(
          `The ${input.describe} was accepted (2xx), but the server distributes a different manifest at the issued manifestVersion ${input.selfManifest.manifestVersion} (issued signed-bytes hash ${input.selfManifest.manifestSigHashHex}, distributed ${distributed.signedBytesHashHex}). The issued manifest was not stored — treating the ${input.describe} as unconfirmed (AUTH_SPEC §12-10 (3)); the local floor was not advanced with the issued manifest`,
        ),
      );
    }
    return yield* Effect.fail(
      cliError(
        `The ${input.describe} was accepted (2xx), but its effect could not be confirmed in the verified distribution (the distributed manifestVersion is ${distributed.manifestVersion} vs the issued ${input.selfManifest.manifestVersion}, and the effect is not visible in the verified statement set). Treating the ${input.describe} as unconfirmed (AUTH_SPEC §12-10 (3)) — re-run the command after investigating the server`,
      ),
    );
  });
}
