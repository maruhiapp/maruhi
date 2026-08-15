// デプロイメント keypair(CRYPTO_SPEC §9)の導出、公開情報の提供、および
// リース時の「自分宛ラップの開封 → ワークロード宛の再ラップ」(§9.1)。
//
// Workers Secret `SERVER_ENC_KEY_IKM`(32 バイト hex)から RFC 9180
// DeriveKeyPair で X25519 keypair を導出し、公開面(enc 公開鍵 + サーバー鍵 FP =
// SHA-256(enc_pub)[:16])を `/auth/config` に載せる(AUTH_SPEC §4)。
//
// **秘密鍵も開封した DEK もこのモジュールのクロージャ外へ出さない**(A1 の
// 申し送りどおり、A2 でここへ Open 経路を足した)。公開する操作は
// `reseal`(開封 + 再ラップを一体で行い、**リースラップだけを返す**)であり、
// 平文 DEK を返す口は存在しない — 戻り値・RPC 境界・ログのどこにも DEK が
// 現れないことを型で保証する(§10 の API 境界の不変条件のサーバー内版)。
// サーバーが復号するのは DEK までで、変数値は復号しない(§9.1)。
//
// secret 未設定は「選択的開示なしの純粋 E2EE デプロイメント」(正常な既定)。
// 形式不正(hex でない・長さ不正)も未設定として扱う — /auth/config から
// serverKeyFingerprintHex が消えるため、grant CLI 側が「サーバー鍵未設定」を
// 明示エラーにする(トラブルシュートは docs/SELF_HOSTING.md)。GitHub OAuth の
// 未設定(503 SetupIncomplete)と違い fail-closed にしないのは、サーバー鍵が
// 任意機能でありログイン経路を塞ぐ理由がないため。

import {
  computeServerKeyFingerprint,
  decodeHex,
  deriveEncryptionKeyPair,
  encodeHex,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  importEncryptionPublicKey,
  type LeaseWrapContext,
  unwrapDek,
  wrapLeaseDek,
} from "@maruhi/crypto";
import { Context, Effect } from "effect";

import type { WireSuite } from "./data-plane.ts";

const IKM_BYTES = 32;

/** デプロイメント keypair の公開面(/auth/config が配布する — AUTH_SPEC §4)。 */
export interface ServerKeyInfo {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
}

/** 保存済みのサーバー宛ラップ(dek_wraps の 1 行 — §12-6)。 */
export interface StoredServerWrap {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/**
 * リースラップ 1 件(応答スコープ。永続化しない — §9.1)。suite は開封元の
 * 保存行から引き継ぐ: リースは「保存済みラップの再ラップ」であり、
 * 別スイートの材料を v1 として配布しない(CRYPTO_SPEC §2 設計原則 4)。
 */
export interface LeaseWrapOutput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** reseal の失敗理由(いずれもサーバー内部の不整合であり、応答に理由は出さない)。 */
export type ResealFailure = "not-configured" | "unwrap-failed" | "wrap-failed";

export interface ServerKeyShape {
  /** 設定済みなら公開面、未設定(または形式不正)なら null。 */
  readonly info: Effect.Effect<ServerKeyInfo | null>;
  /**
   * サーバー宛ラップを開封し、同じエポック DEK をワークロードの一時公開鍵へ
   * 再ラップする(CRYPTO_SPEC §9.1)。開封した DEK はこの呼び出しの中に閉じ、
   * 戻り値には**再ラップ済みのラップだけ**が載る。
   *
   * 失敗は理由コードのみを返す(暗号文・鍵素材の断片を運ばない)。
   */
  readonly reseal: (input: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly claimsDigestHex: string;
    readonly workloadPubHex: string;
    readonly wraps: readonly StoredServerWrap[];
  }) => Effect.Effect<readonly LeaseWrapOutput[], ResealFailure>;
}

export class ServerKey extends Context.Service<ServerKey, ServerKeyShape>()("ServerKey") {}

/** 導出済みのサーバー鍵(公開面 + 開封に使う keypair)。 */
interface DerivedServerKey {
  readonly info: ServerKeyInfo;
  readonly keyPair: EncryptionKeyPair;
}

async function derive(ikmHex: string | undefined): Promise<DerivedServerKey | null> {
  if (ikmHex === undefined || ikmHex === "") {
    return null;
  }
  const ikm = decodeHex(ikmHex);
  if (ikm === null || ikm.length !== IKM_BYTES) {
    return null;
  }
  const pair = await deriveEncryptionKeyPair({ ikm });
  if (!pair.ok) {
    return null;
  }
  const publicKey = await exportEncryptionPublicKey(pair.value.publicKey);
  const fingerprint = await computeServerKeyFingerprint(publicKey);
  if (!fingerprint.ok) {
    return null;
  }
  return {
    info: {
      serverEncPubHex: encodeHex(publicKey),
      serverKeyFingerprintHex: encodeHex(fingerprint.value),
    },
    keyPair: pair.value,
  };
}

/**
 * 開封済み DEK のバッファをゼロ埋めする。JS では GC 前のコピーまでは消せない
 * ため暗号境界ではないが、長命な isolate のヒープに DEK がそのまま残る窓を
 * 縮める(多層防御)。
 */
function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}

/**
 * worker / DO 起動時に一度だけ構築するサービス。導出は初回参照時に 1 回だけ
 * 行い、以後は isolate 内でキャッシュする(ikm と秘密鍵はクロージャに閉じる)。
 */
export function makeServerKey(ikmHex: string | undefined): ServerKeyShape {
  let cached: Promise<DerivedServerKey | null> | undefined;
  const derived = (): Promise<DerivedServerKey | null> => {
    cached ??= derive(ikmHex);
    return cached;
  };
  return {
    info: Effect.promise(async () => (await derived())?.info ?? null),
    reseal: (input) =>
      Effect.gen(function* () {
        const key = yield* Effect.promise(derived);
        if (key === null) {
          return yield* Effect.fail<ResealFailure>("not-configured");
        }
        const workloadPubBytes = decodeHex(input.workloadPubHex);
        if (workloadPubBytes === null) {
          return yield* Effect.fail<ResealFailure>("wrap-failed");
        }
        const workloadPublicKey = yield* Effect.promise(() =>
          importEncryptionPublicKey(workloadPubBytes),
        );
        if (!workloadPublicKey.ok) {
          // ワイヤ Schema(32 バイト hex)を通っていてもインポートは失敗しうる
          // (点として不正な X25519 公開鍵)。呼び出し側が 400 相当へ写す
          return yield* Effect.fail<ResealFailure>("wrap-failed");
        }
        const leases: LeaseWrapOutput[] = [];
        for (const wrap of input.wraps) {
          const enc = decodeHex(wrap.encHex);
          const ciphertext = decodeHex(wrap.ciphertextHex);
          if (enc === null || ciphertext === null) {
            return yield* Effect.fail<ResealFailure>("unwrap-failed");
          }
          const dek = yield* Effect.promise(() =>
            unwrapDek({
              recipientKeyPair: key.keyPair,
              wrapped: { enc, ciphertext },
              context: {
                projectId: input.projectId,
                environmentId: input.environmentId,
                epoch: wrap.epoch,
                // §9: サーバー宛ラップの info は recipient 位置にサーバー鍵 FP
                recipientUserId: key.info.serverKeyFingerprintHex,
              },
            }),
          );
          if (!dek.ok) {
            // 復号不能な毒ラップ(§12-6 の修復経路の対象)。DEK は得られていない
            return yield* Effect.fail<ResealFailure>("unwrap-failed");
          }
          const context: LeaseWrapContext = {
            projectId: input.projectId,
            environmentId: input.environmentId,
            epoch: wrap.epoch,
            claimsDigestHex: input.claimsDigestHex,
          };
          const leased = yield* Effect.promise(() =>
            wrapLeaseDek({ workloadPublicKey: workloadPublicKey.value, dek: dek.value, context }),
          );
          zeroize(dek.value);
          if (!leased.ok) {
            return yield* Effect.fail<ResealFailure>("wrap-failed");
          }
          leases.push({
            suite: wrap.suite,
            epoch: wrap.epoch,
            encHex: encodeHex(leased.value.enc),
            ciphertextHex: encodeHex(leased.value.ciphertext),
          });
        }
        return leases;
      }),
  };
}
