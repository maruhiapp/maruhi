// dek-wrap.json(CRYPTO_SPEC §5)の参照生成器。
// 生成には hpke-js(@hpke/core + @hpke/dhkem-x25519)を使う: 製品実装が採用する
// panva hpke とは独立の実装系であり、かつ ekm による derandomize で Seal 方向を
// 決定論的に固定できる(panva では不可。docs/notes/spike-c.md)。
// 使い捨ての参照ツールであり、製品コードではない。鍵・値はすべてダミー。
// 再生成: bun install && bun run generate-dek-wrap.mjs(このディレクトリで実行)
import { writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

// CRYPTO_SPEC §2.1 の長さプレフィックス付きエンコーディング(generate_reference.py と同一定義)
function lpEncode(fields) {
  const parts = [];
  for (const f of fields) {
    const bytes =
      f instanceof Uint8Array ? f : new TextEncoder().encode(typeof f === "number" ? String(f) : f);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    parts.push(len, bytes);
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const pat = (prefix, n) => Uint8Array.from({ length: n }, (_, i) => (prefix + i) % 256);

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

// 受信者鍵は固定 ikm からの DeriveKeyPair(決定論的)
const ikmR = pat(0x70, 32);
const kp = await suite.kem.deriveKeyPair(ikmR.slice().buffer);
const pkRm = new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey));
const skRm = new Uint8Array(await suite.kem.serializePrivateKey(kp.privateKey));

const projectId = "proj-0001";
const environmentId = "env-prod-0001";
const epoch = 3;
const recipientUserId = "user-recipient-0002";
const infoFields = ["maruhi/v1/dek-wrap", projectId, environmentId, epoch, recipientUserId];
const info = lpEncode(infoFields);
const dek = pat(0x80, 32);
const ikmE = pat(0x90, 32);
const aad = new Uint8Array(0); // §5: 文脈束縛は info が担う。aad は空

async function seal(infoBytes) {
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(pkRm.slice().buffer),
    info: infoBytes.slice().buffer,
    ekm: ikmE.slice().buffer,
  });
  const ct = new Uint8Array(await sender.seal(dek.slice().buffer, aad.slice().buffer));
  return { enc: new Uint8Array(sender.enc), ct };
}

const { enc, ct } = await seal(info);

const tamperedEnc = enc.slice();
tamperedEnc[0] ^= 0x01;

const vector = {
  description:
    "CRYPTO_SPEC §5: DEK ラップ(HPKE Base mode 単発 Seal、DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM)。info は §2.1 エンコーディング。Seal は hpke-js の ekm derandomize で固定(panva 実装は Open 方向 + ラウンドトリップで検証する)",
  info_fields_order: ["domain", "project_id", "environment_id", "epoch", "recipient_user_id"],
  recipient_keypair: {
    ikmR_hex: hex(ikmR),
    skRm_hex: hex(skRm),
    pkRm_hex: hex(pkRm),
    note: "DeriveKeyPair(ikmR) による決定論的生成。RFC 9180 ベクター(hpke/)でも同 API を検証済み",
  },
  vectors: [
    {
      name: "basic",
      domain: "maruhi/v1/dek-wrap",
      project_id: projectId,
      environment_id: environmentId,
      epoch,
      recipient_user_id: recipientUserId,
      info_hex: hex(info),
      dek_hex: hex(dek),
      ikmE_hex: hex(ikmE),
      aad_hex: "",
      enc_hex: hex(enc),
      ciphertext_hex: hex(ct),
    },
  ],
  negative: [
    {
      name: "info-epoch-mismatch",
      base: "basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, environmentId, 4, recipientUserId]),
      ),
      must_fail: true,
      note: "epoch 差し替え(別エポックへの移植)は Open 失敗",
    },
    {
      name: "info-recipient-mismatch",
      base: "basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, environmentId, epoch, "user-owner-0001"]),
      ),
      must_fail: true,
      note: "受信者差し替え(別メンバー宛ラップの移植)は Open 失敗",
    },
    {
      name: "info-environment-mismatch",
      base: "basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, "env-dev-0002", epoch, recipientUserId]),
      ),
      must_fail: true,
      note: "環境差し替えは Open 失敗(環境モデルの文脈束縛)",
    },
    {
      name: "enc-tampered",
      base: "basic",
      enc_hex: hex(tamperedEnc),
      must_fail: true,
      note: "enc(カプセル化公開鍵)の改竄は Open 失敗",
    },
  ],
};

writeFileSync(new URL("../dek-wrap.json", import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log("wrote dek-wrap.json");
