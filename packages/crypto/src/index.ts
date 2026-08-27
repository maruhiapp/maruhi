// @maruhi/crypto — E2EE コア(WebCrypto + HPKE)。
// 暗号仕様は docs/CRYPTO_SPEC.md が唯一の正。このパッケージへの変更は人間レビュー必須。
// 実装は test-vectors/ の全ベクターを通ることを必須とする。
//
// 全環境(ブラウザ / Bun / workerd)で動く: WebCrypto + panva hpke 以外のプリミティブ禁止。
// エラーは型付きエラー値(CryptoResult)で返し、Effect ラップは packages/core 側で行う。
//
// export は CRYPTO_SPEC のセクション別にグルーピングしている(集合は不変)。

// §1-§2: 共通 — スイート識別子・エンコーディング規約(§2.1)・結果型
export {
  type CryptoError,
  type CryptoResult,
  decodeHex,
  encodeHex,
  encodeLengthPrefixed,
  type LengthPrefixedField,
  SUITE_ID,
} from "./internal.package/index.ts";

// §3: 鍵階層 — マスター鍵ペア・DEK の生成、鍵の入出力、ユーザー鍵フィンガープリント、
// FP のワード表示(BIP39 英語 12 語 — 帯域外照合の表示符号化。辞書は §3 の固定
// 辞書として公開する — 完全性はテストが upstream 既知ハッシュで固定)
export {
  BIP39_ENGLISH_WORDS,
  computeUserKeyFingerprint,
  deriveEncryptionKeyPair,
  FINGERPRINT_WORD_COUNT,
  fingerprintToWords,
  type EncryptionKey,
  type EncryptionKeyPair,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateDek,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  importSigningKeyPair,
  importSigningPublicKey,
  type SigningKeyPair,
} from "./internal.package/index.ts";

// §4: 変数の暗号化 — AES-GCM と座標束縛 AAD
export {
  buildVariableAad,
  decryptVariable,
  type EncryptedVariable,
  encryptVariable,
  type VariableContext,
} from "./internal.package/index.ts";

// §4.1: 値の書き込み署名
export {
  buildValueSignedBytes,
  computeValueSignedBytesHash,
  type DistributedValueInput,
  signValue,
  type ValueInvalidReason,
  type ValuePredecessor,
  type ValueSignatureContext,
  verifyDistributedValue,
  verifyValueSignature,
} from "./internal.package/index.ts";

// §4.2: 変数・環境メタデータの署名付きステートメント
export {
  buildMetaSignedBytes,
  computeMetaSignedBytesHash,
  type DistributedMetaStatementInput,
  type MetaInvalidReason,
  type MetaPredecessor,
  type MetaStatementContext,
  type MetaStatementStatus,
  type MetaStatementTarget,
  signMetaStatement,
  verifyDistributedMetaStatement,
  verifyMetaStatementSignature,
} from "./internal.package/index.ts";

// §4.3: 環境マニフェスト(メタ層の鮮度アンカー — エポック焼き込み +
// 変数集合ダイジェスト。正規形実装はここに 1 つだけ置き、サーバー / CLI が共有する)
export {
  buildEnvManifestSignedBytes,
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  type DistributedEnvManifestInput,
  type EnvManifestContext,
  type EnvManifestEnvMeta,
  type EnvManifestPredecessor,
  manifestContextInvalidField,
  type ManifestInvalidReason,
  signEnvManifest,
  type VariablesDigestEntry,
  verifyDistributedEnvManifest,
  verifyEnvManifestSignature,
} from "./internal.package/index.ts";

// §5: 鍵ラップ(HPKE)
export {
  buildDekWrapInfo,
  type DekWrapContext,
  unwrapDek,
  wrapDek,
  type WrappedDek,
} from "./internal.package/index.ts";

// §5.1: DEK ラップの登録署名
export {
  buildDekWrapSignatureBytes,
  type DekWrapSignatureContext,
  signDekWrap,
  verifyDekWrapSignature,
} from "./internal.package/index.ts";

// §5.2: エポック DEK のコミットメント(チェーンによる真正性の束縛)
export {
  buildDekCommitmentBytes,
  computeDekCommitment,
  type DekCommitmentContext,
  verifyDekCommitment,
} from "./internal.package/index.ts";

// §6: メンバーシップログ(署名付きハッシュチェーン)— エントリ形式(§6.1)、
// role と操作種別(§6.2)、検証(§6.3 / §6.4)、導出状態
export {
  type AddMemberPayload,
  canonicalChainEntryBytes,
  canonicalChainPayloadBytes,
  canonicalChainSignedBytes,
  type ChainActor,
  type ChainEntry,
  type ChainHistoryIndex,
  type ChainInvalidReason,
  type ChainMember,
  type ChainOp,
  type ChainOperation,
  type ChainState,
  type ChangeRolePayload,
  type CheckpointEnvironmentEntry,
  type CheckpointPayload,
  type CheckpointTupleLookup,
  computeChainEntryHash,
  computeEnvValuesDigest,
  type CreateEnvironmentPayload,
  type EnvironmentChainState,
  type EnvironmentCheckpointState,
  type EnvironmentStateAtSeq,
  type EnvValuesDigestEntry,
  type GenesisPayload,
  type GrantServerPayload,
  type LeaseClaimConstraint,
  type LeasePolicyIssuer,
  type MemberStateAtSeq,
  type RemoveMemberPayload,
  type RevokeServerPayload,
  type Role,
  type RotateEpochPayload,
  type ServerGrant,
  signChainEntry,
  type UnsignedChainEntry,
  verifyChain,
  verifyChainWithHistory,
} from "./internal.package/index.ts";

// §6.5: 招待の暗号面 — 受諾署名(チェーン外の追加証跡。相互確認の表示は §3 の
// fingerprintToWords、リンクアンカーは §6.3 — いずれも既存 export)
export {
  buildInviteAcceptSignedBytes,
  type InviteAcceptSignatureContext,
  signInviteAccept,
  verifyInviteAcceptSignature,
} from "./internal.package/index.ts";

// §7: エポックとメンバーシップ変更 — export 面なし(ワークフロー規定のみ)

// §8: リカバリーコード
export {
  generateRecoverySecret,
  unwrapMasterSecret,
  type WrappedMasterSecret,
  wrapMasterSecret,
} from "./internal.package/index.ts";

// §9: 選択的開示(サーバー鍵)
export { computeServerKeyFingerprint } from "./internal.package/index.ts";

// §9.1: ワークロードリース — リースラップ(§5 と同一プリミティブ。info に
// claims_digest を束縛)。ラップは応答スコープであり永続化しない
export {
  buildLeaseClaimsBytes,
  buildLeaseWrapInfo,
  computeLeaseClaimsDigest,
  type LeaseClaims,
  type LeaseWrapContext,
  unwrapLeaseDek,
  wrapLeaseDek,
} from "./internal.package/index.ts";
