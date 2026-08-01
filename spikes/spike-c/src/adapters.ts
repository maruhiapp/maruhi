// スパイク C: 使い捨て検証コード。製品コードではない(packages/crypto には置かない)。
// CRYPTO_SPEC §2 のスイート DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM を
// 候補 2 ライブラリで同一インターフェースに揃え、ラウンドトリップ・相互運用・
// RFC 9180 ベクター検証をブラウザ / Bun / workerd で共通実行できるようにする。

import { Aes256Gcm, CipherSuite as HpkeJsCipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import * as PanvaHPKE from "hpke";

export interface RawKeyPair {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
}

export interface SealResult {
  readonly enc: Uint8Array;
  readonly ct: Uint8Array;
}

/** 生バイト列を境界にした共通アダプタ(相互運用テストを可能にするため) */
export interface HpkeAdapter {
  readonly name: string;
  generateKeyPair(): Promise<RawKeyPair>;
  /** RFC 9180 §7.1.3 DeriveKeyPair(ikm) */
  deriveKeyPair(ikm: Uint8Array): Promise<RawKeyPair>;
  seal(
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    pt: Uint8Array,
  ): Promise<SealResult>;
  open(
    recipientPrivateKey: Uint8Array,
    enc: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    ct: Uint8Array,
  ): Promise<Uint8Array>;
}

export const hex = {
  decode(s: string): Uint8Array {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  },
  encode(b: Uint8Array | ArrayBuffer): string {
    const view = b instanceof ArrayBuffer ? new Uint8Array(b) : b;
    return Array.from(view, (x) => x.toString(16).padStart(2, "0")).join("");
  },
};

// ---------------------------------------------------------------------------
// hpke-js(dajiaji): @hpke/core + @hpke/dhkem-x25519(X25519 は @noble/curves 実装)
// ---------------------------------------------------------------------------

function hpkeJsSuite() {
  return new HpkeJsCipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
}

export const hpkeJsAdapter: HpkeAdapter & {
  /** テストベクター用: ekm(ephemeral key material)で derandomize した Seal */
  sealWithEkm(
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    pt: Uint8Array,
    ikmE: Uint8Array,
  ): Promise<SealResult>;
} = {
  name: "hpke-js (@hpke/core + @hpke/dhkem-x25519)",
  async generateKeyPair() {
    const suite = hpkeJsSuite();
    const kp = await suite.kem.generateKeyPair();
    return {
      publicKey: new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey)),
      privateKey: new Uint8Array(await suite.kem.serializePrivateKey(kp.privateKey)),
    };
  },
  async deriveKeyPair(ikm) {
    const suite = hpkeJsSuite();
    const kp = await suite.kem.deriveKeyPair(ikm.slice().buffer);
    return {
      publicKey: new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey)),
      privateKey: new Uint8Array(await suite.kem.serializePrivateKey(kp.privateKey)),
    };
  },
  async seal(recipientPublicKey, info, aad, pt) {
    const suite = hpkeJsSuite();
    const sender = await suite.createSenderContext({
      recipientPublicKey: await suite.kem.deserializePublicKey(recipientPublicKey.slice().buffer),
      info: info.slice().buffer,
    });
    const ct = new Uint8Array(await sender.seal(pt.slice().buffer, aad.slice().buffer));
    return { enc: new Uint8Array(sender.enc), ct };
  },
  async sealWithEkm(recipientPublicKey, info, aad, pt, ikmE) {
    const suite = hpkeJsSuite();
    const sender = await suite.createSenderContext({
      recipientPublicKey: await suite.kem.deserializePublicKey(recipientPublicKey.slice().buffer),
      info: info.slice().buffer,
      ekm: ikmE.slice().buffer,
    });
    const ct = new Uint8Array(await sender.seal(pt.slice().buffer, aad.slice().buffer));
    return { enc: new Uint8Array(sender.enc), ct };
  },
  async open(recipientPrivateKey, enc, info, aad, ct) {
    const suite = hpkeJsSuite();
    const recipient = await suite.createRecipientContext({
      recipientKey: await suite.kem.deserializePrivateKey(recipientPrivateKey.slice().buffer),
      enc: enc.slice().buffer,
      info: info.slice().buffer,
    });
    return new Uint8Array(await recipient.open(ct.slice().buffer, aad.slice().buffer));
  },
};

// ---------------------------------------------------------------------------
// hpke(panva): ゼロ依存・WebCrypto ベース(X25519 はランタイムの WebCrypto 実装)
// ---------------------------------------------------------------------------

function panvaSuite() {
  return new PanvaHPKE.CipherSuite(
    PanvaHPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    PanvaHPKE.KDF_HKDF_SHA256,
    PanvaHPKE.AEAD_AES_256_GCM,
  );
}

export const panvaAdapter: HpkeAdapter = {
  name: "hpke (panva)",
  async generateKeyPair() {
    const suite = panvaSuite();
    const kp = await suite.GenerateKeyPair(true);
    return {
      publicKey: await suite.SerializePublicKey(kp.publicKey),
      privateKey: await suite.SerializePrivateKey(kp.privateKey),
    };
  },
  async deriveKeyPair(ikm) {
    const suite = panvaSuite();
    const kp = await suite.DeriveKeyPair(ikm, true);
    return {
      publicKey: await suite.SerializePublicKey(kp.publicKey),
      privateKey: await suite.SerializePrivateKey(kp.privateKey),
    };
  },
  async seal(recipientPublicKey, info, aad, pt) {
    const suite = panvaSuite();
    const pk = await suite.DeserializePublicKey(recipientPublicKey);
    const { encapsulatedSecret, ciphertext } = await suite.Seal(pk, pt, { info, aad });
    return { enc: encapsulatedSecret, ct: ciphertext };
  },
  async open(recipientPrivateKey, enc, info, aad, ct) {
    const suite = panvaSuite();
    // 検証知見: panva hpke の Open は「秘密鍵単体」を渡す場合 extractable=true を要求する
    // (内部で公開鍵を秘密鍵から導出するため)。Node / workerd / Bun すべてで
    // 「"privateKey" must be extractable or a Key Pair must be used in this runtime」となる。
    // 非抽出鍵を使いたい場合は KeyPair(公開鍵込み)を渡す設計にする必要がある。
    const sk = await suite.DeserializePrivateKey(recipientPrivateKey, true);
    return suite.Open(sk, enc, ct, { info, aad });
  },
};

export const adapters: readonly HpkeAdapter[] = [hpkeJsAdapter, panvaAdapter];
