// `maruhi server grant`(CRYPTO_SPEC §9 / AUTH_SPEC §12-6 — Wave 2 A1)。
//
// grant_server をチェーンへ追記し、開示スコープ内の全環境 × 全エポックの
// サーバー宛ラップをバックフィルする(grant 実行者 = owner がラップ実行者 —
// CRYPTO_SPEC §7)。フロー:
//   1. owner 検査・環境の存在検査・duplicate-server-key / 再 grant 二層の早期検査
//   2. `/auth/config` からサーバー鍵の公開面を取得し、FP = SHA-256(enc_pub)[:16]
//      を再計算照合(輸送破損・設定飛びの機械検出)
//   3. サーバー鍵確認の儀式(§9): FP の BIP39 12 語表示 + 明示確認
//      (対話 = 最終語の再入力、非対話 = --expect-fingerprint の帯域外値照合)
//   4. grant_server 追記(親ヘッド CAS リトライ)
//   5. バックフィル: 環境ごとに全エポックのサーバー宛ラップを一括登録し、
//      409(登録済み)はエポック単位に落として続行 — **再実行が常に収束する**
//      (進捗ファイルなし。分散状態が再開状態 — env rotate と同じ規律)
//
// 中断復旧: grant がチェーンに載った後で落ちても、再実行が「同一内容の有効
// grant を検出 → 追記スキップ → バックフィル(409 = 登録済み)」で収束する。
// A2 のリースは不足時に 503 `server-wraps-missing` へ倒れる(AUTH_SPEC §14-3)。

import { ChainHeadConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainEntry, LeasePolicyIssuer, ServerGrant, SigningKeyPair } from "@maruhi/crypto";
import { computeServerKeyFingerprint, decodeHex, encodeHex } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type BackfillEnvironmentOutcome, backfillEnvironmentFor } from "./backfill.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import type { DekRecipient } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/** サーバー鍵の公開面(`/auth/config` — AUTH_SPEC §4)。 */
interface ServerKeyConfig {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
}

export interface GrantSummary {
  /** チェーンへ追記したか(false = 同一内容の有効 grant を検出してスキップ)。 */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string;
  readonly scopeEnvironmentIds: readonly string[];
  readonly leasePolicyCount: number;
  /** バックフィルで新規登録したラップ数。 */
  readonly registered: number;
  /** 既に登録済みだったラップ数(再実行の収束)。 */
  readonly alreadyRegistered: number;
}

/** スコープの各環境がチェーン上に存在するか(不成立なら理由の文字列)。 */
function scopeExistsRejection(verified: VerifiedProject, scope: readonly string[]): string | null {
  for (const environmentId of scope) {
    if (!verified.state.environments.has(environmentId)) {
      return `Environment ${environmentId} does not exist on the chain (no create_environment observed). Pass existing environment IDs to --environments`;
    }
  }
  return null;
}

/**
 * duplicate-server-key(§6.2)の早期検査: サーバー enc 公開鍵が現メンバーの
 * enc 公開鍵と一致する grant は合意規則で無効になる。
 */
function duplicateServerKeyRejection(
  verified: VerifiedProject,
  serverEncPubHex: string,
): string | null {
  for (const chainMember of verified.state.members.values()) {
    if (chainMember.encPubHex === serverEncPubHex) {
      return "The server enc public key equals a current member's enc public key (consensus rule duplicate-server-key — CRYPTO_SPEC §6.2). Check the deployment's key configuration";
    }
  }
  return null;
}

/**
 * 再 grant 二層(§6.3): scope は拡大のみ。縮小には revoke_server(全環境
 * ローテーション義務つき)を案内する。lease_policy は自由改訂。
 */
function scopeNarrowedRejection(
  existing: ServerGrant | null,
  scope: readonly string[],
): string | null {
  if (existing === null) {
    return null;
  }
  const missing = existing.scopeEnvironmentIds.filter((id) => !scope.includes(id));
  if (missing.length === 0) {
    return null;
  }
  return `The disclosure scope can only grow (re-grant rule — CRYPTO_SPEC §6.3). Environments in the existing grant's scope are missing from this invocation: ${missing.join(", ")}. To narrow the scope, run \`maruhi server revoke\` (which rotates every environment — §7) and grant again`;
}

/** grant_server 実行前の検査一式(再同期後のリトライでも同じ検査を通す)。 */
function ensureGrantable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly scope: readonly string[];
  readonly serverConfig: ServerKeyConfig;
}): Effect.Effect<{ readonly existing: ServerGrant | null }, CliError> {
  const member = input.verified.state.members.get(input.signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("Only an owner can run grant_server (CRYPTO_SPEC §6.2)"));
  }
  const existing =
    input.verified.state.serverGrants.get(input.serverConfig.serverKeyFingerprintHex) ?? null;
  const rejection =
    scopeExistsRejection(input.verified, input.scope) ??
    duplicateServerKeyRejection(input.verified, input.serverConfig.serverEncPubHex) ??
    scopeNarrowedRejection(existing, input.scope);
  return rejection !== null ? Effect.fail(cliError(rejection)) : Effect.succeed({ existing });
}

/** オブジェクトのキー順に依存しない正規形(配列形)で比較する。 */
function canonicalPolicyKey(policy: readonly LeasePolicyIssuer[]): string {
  return JSON.stringify(
    policy.map((element) => [
      element.issuerUrl,
      element.audience,
      element.claimConstraints.map((constraint) => [constraint.claimName, constraint.claimValue]),
    ]),
  );
}

function samePolicy(a: readonly LeasePolicyIssuer[], b: readonly LeasePolicyIssuer[]): boolean {
  return canonicalPolicyKey(a) === canonicalPolicyKey(b);
}

function sameScope(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((id, index) => b[index] === id);
}

/**
 * `/auth/config` のサーバー鍵公開面を取得し、FP を再計算照合する。FP の照合
 * 「対象」は帯域外の控え(儀式 — §9)であり、ここでの再計算は応答の自己整合
 * 検査(輸送破損・別ソースの取り違えの機械検出)である。
 */
function fetchServerKeyConfig(client: MaruhiClient): Effect.Effect<ServerKeyConfig, CliError> {
  return Effect.gen(function* () {
    const config = yield* client.auth.authConfig({}).pipe(Effect.mapError(toCliError));
    const encPubHex = config.serverEncPubHex;
    const fingerprintHex = config.serverKeyFingerprintHex;
    if (encPubHex === undefined || fingerprintHex === undefined) {
      return yield* Effect.fail(
        cliError(
          "The server has no deployment keypair configured (/auth/config has no serverKeyFingerprintHex). Register SERVER_ENC_KEY_IKM following docs/SELF_HOSTING.md",
        ),
      );
    }
    const encPub = decodeHex(encPubHex);
    if (encPub === null || encPub.length !== 32) {
      return yield* Effect.fail(cliError("serverEncPubHex in /auth/config is malformed"));
    }
    const computed = yield* Effect.tryPromise({
      try: () => computeServerKeyFingerprint(encPub),
      catch: () => cliError("Failed to compute the server key fingerprint (crypto error)"),
    });
    if (!computed.ok || encodeHex(computed.value) !== fingerprintHex) {
      return yield* Effect.fail(
        cliError(
          "The server-provided enc public key does not match serverKeyFingerprintHex (the response contradicts itself). Check the deployment configuration or the transport path",
        ),
      );
    }
    return { serverEncPubHex: encPubHex, serverKeyFingerprintHex: fingerprintHex };
  });
}

/**
 * サーバー鍵確認の儀式(§9): FP のワード表示と、デプロイメントの公開設定との
 * 照合の明示確認。メンバー鍵に課している真正性確認(§6.5)をサーバー鍵にだけ
 * 免除しない — grant はサーバーを「メンバー N+1」にする操作である。
 *
 * 確認の形は 2 つ:
 * - `--expect-fingerprint <hex>`: 帯域外で控えた FP を引数で供給する(非対話の
 *   明示確認。デプロイ時の控えと一致しなければ即エラー)
 * - 対話: 12 語を表示し、**最終語の再入力**を要求する(リカバリーコードの
 *   保存確認 — recovery.ts — と同じ儀式。読まずに y を打つ形を塞ぐ)
 */
function confirmServerKey(input: {
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "The server key fingerprint is malformed",
    );
    const lines = [
      "Server key fingerprint (first 16 bytes of SHA-256(enc public key) — CRYPTO_SPEC §9):",
      `  hex:  ${input.fingerprintHex}`,
      "  word: " + formatWordList(words),
      "Check against your out-of-band record that this word list matches the server key fingerprint noted at deploy time (see the recording step in docs/SELF_HOSTING.md).",
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectFingerprintHex !== null) {
      if (input.expectFingerprintHex !== input.fingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--expect-fingerprint does not match the fingerprint of the server-provided key. The deployment's key is not the one you expected — the grant was aborted (verify the key out of band)",
          ),
        );
      }
      yield* io.log(
        "--expect-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      return;
    }
    // AI エージェント環境では儀式を代行させない(照合は人間の帯域外確認 — §9 /
    // ADR-0014。値表示の拒否 — agent.ts — と同じ姿勢の grant 版)
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the server-key confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the fingerprint noted out of band via --expect-fingerprint",
        ),
      );
    }
    return yield* confirmByLastWord({
      words,
      promptText: "Once checked, type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Server key fingerprint confirmation failed (the re-typed word does not match). The grant was not performed — re-run once you can check against your out-of-band record",
    });
  });
}

/** grant_server エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。 */
function signGrantEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly serverConfig: ServerKeyConfig;
  readonly scope: readonly string[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    return yield* signEntryAtHead({
      verified: input.verified,
      signerUserId: input.signerUserId,
      operation: {
        op: "grant_server",
        payload: {
          serverEncPubHex: input.serverConfig.serverEncPubHex,
          serverKeyFingerprintHex: input.serverConfig.serverKeyFingerprintHex,
          scopeEnvironmentIds: input.scope,
          leasePolicy: input.leasePolicy,
        },
      },
      signingKeyPair: input.signingKeyPair,
      failureText: "Failed to sign the grant_server entry",
    });
  });
}

/**
 * 1 環境の全エポック(1〜現エポック)のサーバー宛ラップを登録する(共有核 =
 * backfill.ts)。エポック単位の 409 は「登録済み」として吸収する(サーバー宛
 * ラップの一覧 API は存在しない — 配布は本人宛のみ §12-6 — ため、「409 を
 * 完了扱い」が唯一かつ十分な照合手段)。
 */
function backfillEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly grant: ServerGrant;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<BackfillEnvironmentOutcome, CliError> {
  return backfillEnvironmentFor({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    wrapRecipient: { kind: "server", grant: input.grant },
    recipientLabel: "server-addressed",
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
  });
}

/** CAS リトライの状態。 */
interface GrantState {
  readonly verified: VerifiedProject;
}

export function serverGrantOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentIds: readonly EnvironmentId[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
  readonly expectFingerprintHex: string | null;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<GrantSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // スコープの正規化: コードポイント昇順・重複なし(§6.2 の SHOULD)
    const scope = [...new Set<string>(input.environmentIds)].toSorted();
    const serverConfig = yield* fetchServerKeyConfig(input.client);
    const { existing } = yield* ensureGrantable({
      verified: input.verified,
      signerUserId: input.signerUserId,
      scope,
      serverConfig,
    });

    const unchanged =
      existing !== null &&
      sameScope([...existing.scopeEnvironmentIds].toSorted(), scope) &&
      samePolicy(existing.leasePolicy, input.leasePolicy);

    // 儀式(§9)は追記の有無に関わらず行う(バックフィルだけの再実行でも、
    // これから開示し続ける鍵の照合を省略しない)
    yield* confirmServerKey({
      fingerprintHex: serverConfig.serverKeyFingerprintHex,
      expectFingerprintHex: input.expectFingerprintHex,
    });

    let verified = input.verified;
    if (unchanged) {
      yield* io.log(
        "An active grant with identical content (both scope and lease_policy) already exists — skipping the chain append and running only the backfill (crash recovery)",
      );
    } else {
      const appended = yield* retryOnConflict<GrantState, VerifiedProject, "head-conflict">(
        { verified },
        {
          maxAttempts: MAX_ATTEMPTS,
          attempt: (state) =>
            Effect.gen(function* () {
              const entry = yield* signGrantEntry({
                verified: state.verified,
                signerUserId: input.signerUserId,
                signingKeyPair: input.signingKeyPair,
                serverConfig,
                scope,
                leasePolicy: input.leasePolicy,
              });
              yield* appendEntry(input.client, state.verified, entry);
              return state.verified;
            }),
          classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
          recover: (state) =>
            Effect.gen(function* () {
              // 延長検査付き再同期(短縮・分岐チェーンへの再署名を塞ぐ —
              // env create / rotate の CAS リトライと同じ規律)
              const resynced = yield* resyncExtended(input.resync, state.verified);
              yield* ensureGrantable({
                verified: resynced,
                signerUserId: input.signerUserId,
                scope,
                serverConfig,
              });
              return { verified: resynced };
            }),
          exhaustedMessage: `grant_server's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
        },
      );
      // 受理後の再同期で grant の掲載を確認する(サーバー申告を真実源にしない)
      verified = yield* resyncExtended(input.resync, appended);
      const granted = verified.state.serverGrants.get(serverConfig.serverKeyFingerprintHex);
      if (granted === undefined) {
        return yield* Effect.fail(
          cliError(
            "The resync after grant_server was accepted does not show the grant (the server's response contradicts the chain). Investigate the served chain",
          ),
        );
      }
      yield* io.log(
        `Appended grant_server to the chain (seq=${verified.state.headSeq}, scope=${scope.join(", ")})`,
      );
    }

    const grant = verified.state.serverGrants.get(serverConfig.serverKeyFingerprintHex);
    if (grant === undefined) {
      return yield* Effect.fail(
        cliError("Cannot confirm an active grant (contradicts the resync result)"),
      );
    }

    // バックフィル(開示スコープ内の全環境 × 全エポック — AUTH_SPEC §12-6)
    let registered = 0;
    let alreadyRegistered = 0;
    for (const environmentId of grant.scopeEnvironmentIds) {
      const result = yield* backfillEnvironment({
        client: input.client,
        verified,
        environmentId,
        recipient: input.recipient,
        grant,
        signerUserId: input.signerUserId,
        signingKeyPair: input.signingKeyPair,
      });
      registered += result.registered;
      alreadyRegistered += result.alreadyRegistered;
    }

    return {
      appended: !unchanged,
      serverKeyFingerprintHex: serverConfig.serverKeyFingerprintHex,
      scopeEnvironmentIds: grant.scopeEnvironmentIds,
      leasePolicyCount: grant.leasePolicy.length,
      registered,
      alreadyRegistered,
    };
  });
}
