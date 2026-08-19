// ワークロードリース API の HttpApi 定義(AUTH_SPEC §14 = CRYPTO_SPEC §9.1)。
//
// **このグループだけ AuthMiddleware を宣言しない**: 資格情報はリクエスト同梱の
// OIDC トークン自体であり、maruhi のセッション・API トークンは使わない
// (§14-1。§12-3 の認可表の外)。長期資格情報を持たないワークロードのための
// 経路であることの API 面の表明でもある。
//
// API 境界の不変条件(CRYPTO_SPEC §10)はリース経路でも不変: 応答に載るのは
// 暗号文とラップだけで、平文値・DEK・秘密鍵は現れない。リースラップは
// LeasedDek(登録署名を持たない別型 — data.ts)で運ぶ。

import { EnvironmentIdSchema, ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

import { ChainEntrySchema } from "./chain.ts";
import { PulledVariableSchema } from "./data-api.ts";
import {
  DistributedEnvironmentManifestSchema,
  DistributedEnvironmentMetaStatementSchema,
  DistributedVariableMetaStatementSchema,
  LeasedDekSchema,
} from "./data.ts";
import {
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  ProjectNotFoundError,
} from "./errors/index.ts";
import { EncPubHex, PositiveInt, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/**
 * 受理ポリシー(§14-3): oidcToken は 16 KiB 以下。値と違い専用の検証層を
 * 持たないため Schema が強制する(表示名の 256 文字上限と同じ規律 — §12-8)。
 * JWT は base64url + `.` のみからなる compact serialization であり、
 * 文字集合もここで絞る(パース前に明らかな異物を落とす)。
 */
const OidcTokenSchema = Schema.String.check(
  Schema.isMaxLength(16 * 1024),
  Schema.isPattern(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, {
    description: "compact JWS (three base64url segments)",
  }),
);

/**
 * Lease request (AUTH_SPEC §14-2): the workload's OIDC token and the ephemeral
 * X25519 public key it generated in memory for this job. The matching private
 * key never leaves the workload and dies with the job, so the response is
 * worthless to anyone else (CRYPTO_SPEC §9.1).
 */
export const LeaseRequestSchema = Schema.Struct({
  oidcToken: OidcTokenSchema,
  ephemeralPubHex: EncPubHex,
});

/**
 * Lease response (AUTH_SPEC §14-2). Shaped like the bulk pull (§12-7) — the
 * same verification material travels with every value and statement — plus
 * two differences that follow from the recipient not being a chain member:
 *
 * - **the chain travels with it**: the chain API returns 404 to non-members
 *   (§11-2), so this response is the workload's only distribution channel for
 *   the material its §6.3 verification needs
 * - **`leases` instead of `deks`**: server-generated, response-scoped wraps
 *   sealed to the ephemeral key (CRYPTO_SPEC §9.1), never the stored
 *   `RecipientDek` wraps a chain member registered
 *
 * The workload must run the §9.1 verification duties (chain verification with
 * a pre-pinned genesis, repository anchor, commitment matching, value and
 * statement signatures) before using anything here.
 */
export const LeaseResponseSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  currentEpoch: PositiveInt,
  // チェーン全体(§14-2 の同梱)。ワークロードは genesis を事前固定した上で
  // §6.3 の検証を自ら行う — サーバー申告のヘッドを信用してはならない
  chain: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(PulledVariableSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  leases: Schema.Array(LeasedDekSchema),
  /**
   * 最新の環境マニフェスト + issuer 情報(§14-2 — 2026-08-18)。ワークロードの
   * 検証義務 §9.1 (5)(ダイジェスト再計算・エポック整合)の材料。欠落 = 拒否は
   * pull と同一(optional は移行完了までの過渡状態のみ)。
   */
  manifest: Schema.optionalKey(DistributedEnvironmentManifestSchema),
});

/**
 * Workload lease (AUTH_SPEC §14 = CRYPTO_SPEC §9.1): a CI job with no
 * long-lived credential presents an OIDC token and an ephemeral public key,
 * and receives the environment's chain, ciphertexts, statements and the epoch
 * DEKs re-sealed to that ephemeral key. The server opens only its own
 * server-addressed wraps — it never decrypts a value (§9.1).
 *
 * 判定順(§14-3): OIDC 検証(401)→ lease_policy 一致 + 開示スコープ
 * (不一致は一律 404)→ 先着束縛(同一トークン + 別鍵は 401 `token-replayed` —
 * §14-1。2026-08-15 裁定)→ 環境の存在(404)→ レート制限(429)→ サーバー宛
 * ラップの存在(503)。レート制限を認可の後ろに置くのは §11-2 の存在秘匿のため
 * (errors/lease.ts)。`token-replayed` は認可通過後にのみ到達する唯一の 401 で、
 * 存在秘匿と両立する(errors/lease.ts の LeaseUnauthorizedReasonSchema)。
 */
export const leaseGroup = HttpApiGroup.make("lease").add(
  HttpApiEndpoint.post("issue", "/projects/:projectId/environments/:environmentId/lease", {
    params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
    // strict 受理(§12-10 (1))。共有部品の LeaseRequestSchema 自体には注釈せず、
    // payload ルートの使用点でのみ被せる(応答側へ strict を波及させない規律)
    payload: strictPayload(LeaseRequestSchema),
    success: LeaseResponseSchema,
    error: [
      LeaseUnauthorizedError,
      // 未知プロジェクト・grant なし・ポリシー不一致・スコープ外・環境なしは
      // **すべてこの 1 種**へ畳む(§14-1 の存在秘匿)。EnvironmentNotFound を
      // 別に宣言しないのは、認可を通過した呼び出し元にだけ環境の不在を明かす
      // 形が、リース経路では価値がない(ワークロードは環境 ID を設定として
      // 持っており、不在は設定ミスとして 404 で十分)一方、契約に二つの 404 が
      // 並ぶと実装がどちらを返すかの選択を持ってしまうため
      ProjectNotFoundError,
      LeaseRateLimitedError,
      LeaseUnavailableError,
    ],
  }),
);
