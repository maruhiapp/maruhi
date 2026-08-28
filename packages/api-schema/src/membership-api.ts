// メンバーシップログの HttpApi 定義(CRYPTO_SPEC §6.4)。
// サーバー実装(apps/server)と将来の CLI クライアント導出の共有源。
//
// API 境界の不変条件(§10): このファイルのどの型も平文シークレット・DEK・
// master 秘密鍵を表現しない。チェーンエントリは署名付き公開データである。

import { ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { auditGroup } from "./audit-api.ts";
import { authGroup } from "./auth-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import { ChainEntrySchema } from "./chain.ts";
import { deksGroup, environmentsGroup, variablesGroup } from "./data-api.ts";
import {
  AttestationRateLimitedError,
  AttestationRegressionError,
  AttestationRejectedError,
  AuditHeadNotReadyError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  CompositeRequiredError,
  ForbiddenError,
  ProjectAlreadyInitializedError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import { HeadAttestationSignatureHex, KeyFingerprintHex, PositiveInt, Sha256Hex } from "./hex.ts";
import { invitesGroup } from "./invites-api.ts";
import { leaseGroup } from "./lease-api.ts";
import { rotationGroup } from "./rotation-api.ts";
import { assertSecurityCriticalPayloadsStrict, strictPayload } from "./strict.ts";

/** Chain head after a successful initialization or append. */
export const ChainHeadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

/**
 * ヘッド申告の提出リクエスト(CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1)。attester は
 * 呼び出し主体(§12-5 の「呼び出し主体 = 署名者」規則 — ワイヤに attester
 * フィールドを持たない)。
 */
export const HeadAttestationSubmissionSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: HeadAttestationSignatureHex,
});

/**
 * 配布されるヘッド申告(AUTH_SPEC §16-1 — チェーン取得応答の `attestations`)。
 * attesterUserId + attesterKeyFingerprintHex は §12-2 の検証材料と同型(受信者は
 * チェーン履歴と照合して CRYPTO_SPEC §6.6 のクライアント検証を行う)。
 * サーバー受理時刻は配布しない(申告が運ぶ行動情報を「チェーン同期の到達点」に
 * 限定する — §16-1)。
 */
export const DistributedHeadAttestationSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  attesterUserId: Schema.String,
  attesterKeyFingerprintHex: KeyFingerprintHex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: HeadAttestationSignatureHex,
});

/**
 * Full chain as stored by the project DO (entries in seq order).
 *
 * `attestations` = 現メンバーの最新ヘッド申告集合(AUTH_SPEC §16-1 — 2026-08-28
 * PR-M4 の加法追加)。optionalKey なのは新 CLI × 旧サーバーの応答に欠けるため —
 * **欠落は拒否にしない**(配布の省略は CRYPTO_SPEC §6.3 の規範的非保証 = G8。
 * 欠落拒否の分岐は攻撃検出を足さず、旧サーバーとの併用だけを壊す)。
 */
export const ChainSnapshotSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  entries: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
  attestations: Schema.optionalKey(Schema.Array(DistributedHeadAttestationSchema)),
});

/**
 * Membership-log endpoints (CRYPTO_SPEC §6.4)。全エンドポイント認証必須
 * (AUTH_SPEC §11-1。AuthMiddleware が 401 / CSRF 403 を担う)。
 *
 * - `init`: submit a genesis entry; the server verifies it and derives the
 *   project id as the genesis entry hash. `orgId` は帰属先 org(§11-3。作成
 *   権限 = org member 以上)。非メンバー・スコープ外への応答は一律 404(§11-2)。
 * - `get`: fetch the stored chain for client-side verification (§6.3).
 * - `append`: append one entry; `parentHeadHashHex` is the compare-and-swap
 *   parent (§6.4)。§6.3 の「署名付き申告ヘッド」(ヘッドゴシップ)とは別物。
 *   認証主体と entry.actor の厳密一致を要求する(§11-1)。
 *   `create_environment` / `rotate_epoch` は複合エンドポイント
 *   (environments group の create / rotate — AUTH_SPEC §12-4)経由のみ受理し、
 *   ここでは CompositeRequired で拒否する(AUTH_SPEC §6。2026-08-03)。
 *   standalone(周期)`checkpoint` は本エンドポイントが受理する(AUTH_SPEC
 *   §16-2 — 2026-08-28 PR-M2): 認可は空 audit_head_hash = write × member 以上、
 *   非空 = 実効権限 admin(不足 403)。受理時点の保存状態との突合失敗は 422
 *   `CheckpointStateMismatch`。
 */
export const membershipGroup = HttpApiGroup.make("membership")
  .add(
    HttpApiEndpoint.post("init", "/projects", {
      // strict 受理(§12-10 (1) — genesis を運ぶチェーン追記面)
      payload: strictPayload(Schema.Struct({ orgId: Schema.String, entry: ChainEntrySchema })),
      success: ChainHeadSchema,
      error: [
        ProjectAlreadyInitializedError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ForbiddenError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("get", "/projects/:projectId/chain", {
      params: { projectId: ProjectIdSchema },
      success: ChainSnapshotSchema,
      error: [ProjectNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("append", "/projects/:projectId/chain/entries", {
      params: { projectId: ProjectIdSchema },
      payload: strictPayload(
        Schema.Struct({
          // CAS の親ヘッド。不正形式は schema 境界の 400 で落とす(意図的な受理変更)
          parentHeadHashHex: Sha256Hex,
          entry: ChainEntrySchema,
        }),
      ),
      success: ChainHeadSchema,
      error: [
        ProjectNotFoundError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        CheckpointStateMismatchError,
        // 非空 audit_head_hash の受理検査の前段: 監査ヘッド派生列の有界伸長が
        // 未完了(AUDIT_SPEC §5.1 — セッション 38)。retryable 503 — 古い列で
        // audit-head-unknown / stale を判定しない(fail-closed)
        AuditHeadNotReadyError,
        CompositeRequiredError,
        ForbiddenError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    // ヘッド申告の提出(CRYPTO_SPEC §6.6 / AUTH_SPEC §16-1 — 2026-08-28 PR-M4)。
    // 認可はトークンスコープ read × チェーン role reader 以上(申告は読み取り
    // 同期の付随で、書けるのは自分の署名済み申告 1 行のみ — §16-1)。受理検証
    // (署名・ヘッド実在・seq 単調前進)は §6.4。後退 = 409(保存済み seq を
    // 返す — 黙って成功させない)、同一 seq 再提出 = 冪等 204。
    HttpApiEndpoint.put("attest", "/projects/:projectId/head-attestation", {
      params: { projectId: ProjectIdSchema },
      // strict 受理(§12-10 (1) — 署名済み構造を運ぶ mutation)
      payload: strictPayload(HeadAttestationSubmissionSchema),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        AttestationRegressionError,
        AttestationRejectedError,
        AttestationRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  );

/** The maruhi HTTP API. */
export const maruhiApi = HttpApi.make("maruhi")
  .add(membershipGroup)
  .add(authGroup)
  .add(environmentsGroup)
  .add(variablesGroup)
  .add(deksGroup)
  .add(invitesGroup)
  .add(rotationGroup)
  .add(auditGroup)
  // 唯一の未認証グループ(資格情報 = OIDC トークン自体 — AUTH_SPEC §14-1)
  .add(leaseGroup);

// ロード時スイープ(AUTH_SPEC §12-10 (1) / session-32 §5-2): 登録済みの全
// security-critical payload ルートで strict 注釈が parser の読む位置にあることを
// import 時に検査する。strictPayload 適用後の .check() 再合成(wrapper 内 assert は
// ラップ時 1 回きりで捕捉できない)をモジュールロードの fail-loud に格上げする。
assertSecurityCriticalPayloadsStrict(maruhiApi);
