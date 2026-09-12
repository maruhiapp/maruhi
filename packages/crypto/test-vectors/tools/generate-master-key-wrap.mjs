// master-key-wrap.json(CRYPTO_SPEC §8 — master 鍵ラップ台帳。0.9-draft / KL3)の参照生成器。
// dek-wrap.json / lease-wrap.json と同じ理由で hpke-js を使う: 製品実装が採用する
// panva hpke とは独立の実装系であり、ekm による derandomize で Seal 方向を決定論的に
// 固定できる(panva では不可。docs/notes/spike-c.md)。HKDF / AES-GCM / SHA-256 は
// WebCrypto(Bun)。使い捨ての参照ツールであり、製品コードではない。鍵・値はすべてダミー。
//
// recovery-wrap.json を読み、その master_secret_blob_hex(ブロブ B)と user_id を
// 引き継ぐ: 台帳は「同じ B を受信者ごとに包んだラップの集合」であり、recovery-code
// 行(既存ベクター — 不変)と新経路が同じ B を指すことをベクター上で追跡できる。
//
// 固定するもの(§8.1〜8.4):
//   - master_wrap_aad = LP("maruhi/v1/master-wrap", user_id, kind, wrap_ref, mode)
//   - passkey-prf: KEK = HKDF(prf_out, salt=空, info="maruhi/v1/passkey-prf")
//   - guardian: mode any = 全分片が KEK / mode all = 乱数 XOR 分割(s_n = KEK ⊕ 他)、
//     分片は HPKE Seal(info = LP("maruhi/v1/guardian-wrap", user_id, group_id, mode,
//     share_index, guardian_user_id)、aad 空)
//   - handoff: request_id = SHA-256(LP("maruhi/v1/handoff-id", E_pub_hex))、
//     ハンドオフコード = Base32(E_pub ‖ SHA-256(E_pub)[:4])を 4 文字ずつハイフン区切り、
//     承認 = HPKE Seal(info = LP("maruhi/v1/handoff-wrap", user_id, request_id, source,
//     share_index, approver_user_id)、aad 空)
//
// 再生成: bun install && bun run generate(このディレクトリで実行)
import { readFileSync, writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

// CRYPTO_SPEC §2.1 の長さプレフィックス付きエンコーディング(他の生成器と同一定義。
// tools/ は使い捨てのため共有モジュール化しない既存慣行に従う)
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
const fromHex = (h) => Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest("SHA-256", u8.slice()));
const xor = (...arrays) => {
  const out = new Uint8Array(arrays[0].length);
  for (const a of arrays) {
    for (let i = 0; i < out.length; i++) {
      out[i] ^= a[i];
    }
  }
  return out;
};

// --- Base32(RFC 4648 アルファベット・パディング無し)------------------------------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes) {
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    out += B32[(acc << (5 - bits)) & 31];
  }
  return out;
}
const group4 = (s) => (s.match(/.{1,4}/g) ?? []).join("-");

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});
const emptyAad = new Uint8Array(0);

async function deriveKeyPair(ikm) {
  const kp = await suite.kem.deriveKeyPair(ikm.slice().buffer);
  return {
    ikm_hex: hex(ikm),
    pk_hex: hex(new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey))),
    sk_hex: hex(new Uint8Array(await suite.kem.serializePrivateKey(kp.privateKey))),
  };
}

async function seal(recipientPkHex, infoBytes, plaintext, ekm) {
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(
      fromHex(recipientPkHex).slice().buffer,
    ),
    info: infoBytes.slice().buffer,
    ekm: ekm.slice().buffer,
  });
  const ct = new Uint8Array(await sender.seal(plaintext.slice().buffer, emptyAad.slice().buffer));
  return { enc_hex: hex(new Uint8Array(sender.enc)), ciphertext_hex: hex(ct) };
}

async function aesGcmEncrypt(keyBytes, nonce, aad, plaintext) {
  const key = await crypto.subtle.importKey("raw", keyBytes.slice(), "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce.slice(), additionalData: aad.slice() },
      key,
      plaintext.slice(),
    ),
  );
}

async function hkdf(ikmBytes, infoUtf8) {
  const ikm = await crypto.subtle.importKey("raw", ikmBytes.slice(), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(infoUtf8),
      },
      ikm,
      256,
    ),
  );
}

// --- recovery-wrap.json から B と user_id を引き継ぐ ------------------------------
const recoveryDoc = JSON.parse(
  readFileSync(new URL("../recovery-wrap.json", import.meta.url), "utf8"),
);
const recoveryBase = recoveryDoc.vectors[0];
const userId = recoveryBase.user_id;
const blob = fromHex(recoveryBase.master_secret_blob_hex);

const MASTER_WRAP_DOMAIN = "maruhi/v1/master-wrap";
const PASSKEY_HKDF_INFO = "maruhi/v1/passkey-prf";
const GUARDIAN_WRAP_DOMAIN = "maruhi/v1/guardian-wrap";
const HANDOFF_WRAP_DOMAIN = "maruhi/v1/handoff-wrap";
const HANDOFF_ID_DOMAIN = "maruhi/v1/handoff-id";

const masterAad = (kind, wrapRef, mode) =>
  lpEncode([MASTER_WRAP_DOMAIN, userId, kind, wrapRef, mode]);
const guardianInfo = (groupId, mode, shareIndex, guardianUserId) =>
  lpEncode([GUARDIAN_WRAP_DOMAIN, userId, groupId, mode, shareIndex, guardianUserId]);
const handoffInfo = (requestId, source, shareIndex, approverUserId) =>
  lpEncode([HANDOFF_WRAP_DOMAIN, userId, requestId, source, shareIndex, approverUserId]);

// --- クラス S: passkey-prf ----------------------------------------------------------
const passkeyWrapId = "01JMKWRAP0000000000000PASSK";
const credentialId = pat(0x11, 16);
const prfSalt = pat(0x20, 32);
const prfOut = pat(0x10, 32); // 認証器の HMAC 出力(ベクターでは固定パターン)
const otherPrfOut = pat(0x18, 32); // 別 prf_salt で評価した出力(prf-salt-mismatch の材料)
const passkeyKek = await hkdf(prfOut, PASSKEY_HKDF_INFO);
const otherPasskeyKek = await hkdf(otherPrfOut, PASSKEY_HKDF_INFO);
const passkeyNonce = pat(0xe0, 12);
const passkeyAad = masterAad("passkey-prf", passkeyWrapId, "");
const passkeyCt = await aesGcmEncrypt(passkeyKek, passkeyNonce, passkeyAad, blob);

// --- クラス G: guardian(any-2 / all-3)---------------------------------------------
const guardianKeys = {
  "user-member-0002": await deriveKeyPair(pat(0x71, 32)),
  "user-admin-0003": await deriveKeyPair(pat(0x72, 32)),
  "user-guardian-0004": await deriveKeyPair(pat(0x73, 32)),
};

const any2 = {
  group_id: "01JMKGRP00000000000000ANY02",
  mode: "any",
  kek: pat(0xa0, 32),
  nonce: pat(0xe1, 12),
  guardians: ["user-member-0002", "user-admin-0003"],
};
any2.shares = any2.guardians.map(() => any2.kek);
any2.aad = masterAad("guardian", any2.group_id, any2.mode);
any2.ciphertext = await aesGcmEncrypt(any2.kek, any2.nonce, any2.aad, blob);

const all3 = {
  group_id: "01JMKGRP00000000000000ALL03",
  mode: "all",
  kek: pat(0xa8, 32),
  nonce: pat(0xe2, 12),
  guardians: ["user-member-0002", "user-admin-0003", "user-guardian-0004"],
};
const s1 = pat(0x30, 32);
const s2 = pat(0x50, 32);
all3.shares = [s1, s2, xor(all3.kek, s1, s2)];
all3.aad = masterAad("guardian", all3.group_id, all3.mode);
all3.ciphertext = await aesGcmEncrypt(all3.kek, all3.nonce, all3.aad, blob);

async function sealShares(group, ekmPrefix) {
  const out = [];
  for (let i = 0; i < group.guardians.length; i++) {
    const guardianUserId = group.guardians[i];
    const shareIndex = i + 1;
    const info = guardianInfo(group.group_id, group.mode, shareIndex, guardianUserId);
    const ekm = pat(ekmPrefix + i, 32);
    const sealed = await seal(guardianKeys[guardianUserId].pk_hex, info, group.shares[i], ekm);
    out.push({
      share_index: shareIndex,
      guardian_user_id: guardianUserId,
      guardian_enc_pub_hex: guardianKeys[guardianUserId].pk_hex,
      share_hex: hex(group.shares[i]),
      info_hex: hex(info),
      ikmE_hex: hex(ekm),
      aad_hex: "",
      ...sealed,
    });
  }
  return out;
}
any2.sealed = await sealShares(any2, 0x91);
all3.sealed = await sealShares(all3, 0x93);

// --- クラス H: handoff ---------------------------------------------------------------
const ephemeral = await deriveKeyPair(pat(0xd1, 32));
const otherEphemeral = await deriveKeyPair(pat(0xd2, 32));
const requestIdOf = async (pkHex) => hex(await sha256(lpEncode([HANDOFF_ID_DOMAIN, pkHex])));
const requestId = await requestIdOf(ephemeral.pk_hex);
const otherRequestId = await requestIdOf(otherEphemeral.pk_hex);
const codeOf = async (pkHex) => {
  const pk = fromHex(pkHex);
  const checksum = (await sha256(pk)).slice(0, 4);
  const payload = new Uint8Array(36);
  payload.set(pk, 0);
  payload.set(checksum, 32);
  const symbols = base32Encode(payload);
  return { checksum_hex: hex(checksum), symbols, display: group4(symbols) };
};
const code = await codeOf(ephemeral.pk_hex);

// 保護者の承認: all-3 の分片 1(user-member-0002)を E.pub へ再封印
const guardianApprovalInfo = handoffInfo(requestId, all3.group_id, 1, "user-member-0002");
const guardianApprovalEkm = pat(0x96, 32);
const guardianApproval = await seal(
  ephemeral.pk_hex,
  guardianApprovalInfo,
  all3.shares[0],
  guardianApprovalEkm,
);

// 旧端末の承認: KEK_h を生成し、B を device 形 AAD でラップ、KEK_h を E.pub へ封印
const kekH = pat(0xb8, 32);
const deviceNonce = pat(0xe3, 12);
const deviceAad = masterAad("device", requestId, "");
const deviceCt = await aesGcmEncrypt(kekH, deviceNonce, deviceAad, blob);
const deviceApprovalInfo = handoffInfo(requestId, "device", 0, userId);
const deviceApprovalEkm = pat(0x97, 32);
const deviceApproval = await seal(ephemeral.pk_hex, deviceApprovalInfo, kekH, deviceApprovalEkm);

// --- 負例の材料 ---------------------------------------------------------------------
const flipFirstHexNibble = (h) =>
  `${(Number.parseInt(h.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, "0")}${h.slice(2)}`;
const badChecksumSymbols = `${code.symbols.slice(0, 55)}${code.symbols[55] === "A" ? "B" : "A"}${code.symbols.slice(56)}`;
// 末尾シンボルの下位 2 bit(ゼロ詰め)が非ゼロ: 最終シンボル値 +1
const lastValue = B32.indexOf(code.symbols[57]);
const badPaddingSymbols = `${code.symbols.slice(0, 57)}${B32[(lastValue + 1) % 32]}`;

const vector = {
  description:
    "CRYPTO_SPEC §8(0.9-draft / KL3): master 鍵ラップ台帳。B(recovery-wrap.json の master_secret_blob_hex と同一)を受信者クラス S(passkey-prf: HKDF + AES-256-GCM)/ G(guardian: 乱数 KEK + AES-256-GCM、分片は HPKE Seal)/ H(handoff: 一時鍵 E への HPKE Seal)へ包む。AES-GCM は WebCrypto、Seal は hpke-js の ekm derandomize で固定(panva 実装は Open 方向 + ラウンドトリップで検証する)。recovery-wrap.json(recovery-code 行)はバイト互換のまま不変",
  provenance_note:
    "user_id と B は recovery-wrap.json の basic を引き継ぐ。台帳 = 同一 B に対する受信者ごとのラップの集合であることを実データで表す",
  master_wrap_aad_fields_order: ["domain", "user_id", "kind", "wrap_ref", "mode"],
  guardian_wrap_info_fields_order: [
    "domain",
    "user_id",
    "group_id",
    "mode",
    "share_index",
    "guardian_user_id",
  ],
  handoff_wrap_info_fields_order: [
    "domain",
    "user_id",
    "request_id",
    "source",
    "share_index",
    "approver_user_id",
  ],
  handoff_id_fields_order: ["domain", "ephemeral_pub_hex"],
  user_id: userId,
  master_secret_blob_hex: hex(blob),
  guardian_keypairs: Object.fromEntries(
    Object.entries(guardianKeys).map(([id, k]) => [
      id,
      {
        ikm_hex: k.ikm_hex,
        sk_hex: k.sk_hex,
        pk_hex: k.pk_hex,
        note: "保護者の master enc 鍵(DEK ラップを受ける鍵と同じ)。DeriveKeyPair(ikm) による決定論的生成",
      },
    ]),
  ),
  ephemeral_keypair: {
    ikm_hex: ephemeral.ikm_hex,
    sk_hex: ephemeral.sk_hex,
    pk_hex: ephemeral.pk_hex,
    note: "要求者(新端末)の一時 X25519 鍵 E。ベクターの決定論のため DeriveKeyPair(ikm) で固定するが、実運用では毎回ランダム生成し要求者プロセスとともに破棄する(§8.4)",
  },
  passkey: {
    hkdf: { salt: "", info_utf8: PASSKEY_HKDF_INFO, length: 32 },
    note: "prf_out = WebAuthn PRF(credential, eval.first = prf_salt)。prf_salt は登録ごとの乱数で公開パラメータ。KEK = HKDF-SHA256(prf_out, salt 空, info)",
  },
  handoff: {
    request_id_domain: HANDOFF_ID_DOMAIN,
    ephemeral_pub_hex: ephemeral.pk_hex,
    request_id_lp_hex: hex(lpEncode([HANDOFF_ID_DOMAIN, ephemeral.pk_hex])),
    request_id_hex: requestId,
    code: {
      payload_hex: `${ephemeral.pk_hex}${code.checksum_hex}`,
      checksum_hex: code.checksum_hex,
      symbols: code.symbols,
      display: code.display,
      note: "ハンドオフコード = Base32(RFC 4648 アルファベット・パディング無し)(E_pub 32 B ‖ SHA-256(E_pub)[:4]) = 58 シンボル(末尾 2 bit はゼロ詰め)。表示は 4 文字ずつハイフン区切り。入力は小文字・ハイフン・空白を吸収し、アルファベット外・長さ違い・チェックサム不一致・ゼロ詰め非ゼロは拒否",
    },
    other_ephemeral: {
      ikm_hex: otherEphemeral.ikm_hex,
      pk_hex: otherEphemeral.pk_hex,
      request_id_hex: otherRequestId,
      note: "別要求(別の一時鍵)。transplant-request-id の材料",
    },
  },
  vectors: [
    {
      name: "passkey-prf-basic",
      class: "S",
      kind: "passkey-prf",
      wrap_id: passkeyWrapId,
      credential_id_hex: hex(credentialId),
      prf_salt_hex: hex(prfSalt),
      prf_out_hex: hex(prfOut),
      kek_hex: hex(passkeyKek),
      aad_hex: hex(passkeyAad),
      nonce_hex: hex(passkeyNonce),
      ciphertext_hex: hex(passkeyCt),
      note: "パスキー PRF 由来 KEK による B のラップ。AAD = LP(master-wrap, user_id, 'passkey-prf', wrap_id, '')",
    },
    {
      name: "guardian-any-2",
      class: "G",
      kind: "guardian",
      group_id: any2.group_id,
      mode: any2.mode,
      kek_hex: hex(any2.kek),
      aad_hex: hex(any2.aad),
      nonce_hex: hex(any2.nonce),
      ciphertext_hex: hex(any2.ciphertext),
      shares: any2.sealed,
      note: "1-of-n(mode any): 全分片 = KEK。どの 1 片でも B を開ける",
    },
    {
      name: "guardian-all-3",
      class: "G",
      kind: "guardian",
      group_id: all3.group_id,
      mode: all3.mode,
      kek_hex: hex(all3.kek),
      aad_hex: hex(all3.aad),
      nonce_hex: hex(all3.nonce),
      ciphertext_hex: hex(all3.ciphertext),
      shares: all3.sealed,
      note: "n-of-n(mode all): s_1, s_2 は乱数、s_3 = KEK ⊕ s_1 ⊕ s_2。KEK = 全片の XOR",
    },
    {
      name: "handoff-guardian-share",
      class: "H",
      source: all3.group_id,
      share_index: 1,
      approver_user_id: "user-member-0002",
      request_id_hex: requestId,
      value_hex: hex(all3.shares[0]),
      info_hex: hex(guardianApprovalInfo),
      ikmE_hex: hex(guardianApprovalEkm),
      aad_hex: "",
      enc_hex: guardianApproval.enc_hex,
      ciphertext_hex: guardianApproval.ciphertext_hex,
      note: "保護者 user-member-0002 が guardian-all-3 の分片 1 を開き、その場で要求者の E.pub へ再封印した承認",
    },
    {
      name: "handoff-device",
      class: "H",
      source: "device",
      share_index: 0,
      approver_user_id: userId,
      request_id_hex: requestId,
      value_hex: hex(kekH),
      info_hex: hex(deviceApprovalInfo),
      ikmE_hex: hex(deviceApprovalEkm),
      aad_hex: "",
      enc_hex: deviceApproval.enc_hex,
      ciphertext_hex: deviceApproval.ciphertext_hex,
      blob_wrap: {
        kind: "device",
        wrap_ref: requestId,
        aad_hex: hex(deviceAad),
        nonce_hex: hex(deviceNonce),
        ciphertext_hex: hex(deviceCt),
      },
      note: "旧端末(ward 本人)の承認: 乱数 KEK_h で B をラップ(AAD kind='device', wrap_ref=request_id)し、KEK_h を E.pub へ封印して同送",
    },
  ],
  negative: [
    {
      name: "aad-kind-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(masterAad("device", passkeyWrapId, "")),
      must_fail: true,
      note: "kind の付け替え(passkey-prf → device。同じ wrap_ref・空 mode のまま)は復号失敗",
    },
    {
      name: "aad-wrap-ref-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(masterAad("passkey-prf", "01JMKWRAP0000000000000OTHER", "")),
      must_fail: true,
      note: "別の wrap_id(別行)への移植は復号失敗",
    },
    {
      name: "aad-user-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(
        lpEncode([MASTER_WRAP_DOMAIN, "user-member-0002", "passkey-prf", passkeyWrapId, ""]),
      ),
      must_fail: true,
      note: "他ユーザーの台帳への移植は復号失敗",
    },
    {
      name: "aad-mode-all-as-any",
      base: "guardian-all-3",
      decrypt_aad_hex: hex(masterAad("guardian", all3.group_id, "any")),
      must_fail: true,
      note: "サーバーが all グループを any と偽っても(要求者が 1 片で足りると誤らされても)AAD の mode 束縛で復号失敗",
    },
    {
      name: "aad-mode-any-as-all",
      base: "guardian-any-2",
      decrypt_aad_hex: hex(masterAad("guardian", any2.group_id, "all")),
      must_fail: true,
      note: "any グループを all と偽る方向も復号失敗",
    },
    {
      name: "share-missing",
      base: "guardian-all-3",
      decrypt_kek_hex: hex(xor(all3.shares[0], all3.shares[1])),
      must_fail: true,
      note: "n−1 片(s_1 ⊕ s_2)では KEK にならず復号失敗(n-of-n の固定)",
    },
    {
      name: "prf-salt-mismatch",
      base: "passkey-prf-basic",
      other_prf_out_hex: hex(otherPrfOut),
      decrypt_kek_hex: hex(otherPasskeyKek),
      must_fail: true,
      note: "別 prf_salt で評価した PRF 出力から導いた KEK では復号失敗(登録ごとの乱数 salt = 登録ごとの独立 KEK)",
    },
    {
      name: "suite-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(
        lpEncode(["maruhi/v2/master-wrap", userId, "passkey-prf", passkeyWrapId, ""]),
      ),
      must_fail: true,
      note: "ドメイン文字列のスイート部を変えた AAD では復号失敗(スイート束縛はドメイン文字列が担う)",
    },
    {
      name: "guardian-transplant-share-index",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(all3.group_id, all3.mode, 2, "user-member-0002")),
      must_fail: true,
      note: "分片番号の付け替えは Open 失敗",
    },
    {
      name: "guardian-transplant-guardian",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(all3.group_id, all3.mode, 1, "user-admin-0003")),
      must_fail: true,
      note: "別の保護者への帰属付け替えは Open 失敗(鍵も違うが info だけでも落ちる形を固定)",
    },
    {
      name: "guardian-transplant-group",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(any2.group_id, all3.mode, 1, "user-member-0002")),
      must_fail: true,
      note: "別グループへの移植は Open 失敗",
    },
    {
      name: "guardian-mode-relabel",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(all3.group_id, "any", 1, "user-member-0002")),
      must_fail: true,
      note: "分片側でも mode の付け替えは Open 失敗(AAD と info の二重束縛)",
    },
    {
      name: "handoff-transplant-request-id",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(otherRequestId, all3.group_id, 1, "user-member-0002")),
      must_fail: true,
      note: "別要求への移植は Open 失敗(承認は要求 1 件に束縛)",
    },
    {
      name: "handoff-transplant-approver",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(requestId, all3.group_id, 1, "user-admin-0003")),
      must_fail: true,
      note: "承認者の帰属付け替えは Open 失敗",
    },
    {
      name: "handoff-transplant-source",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(requestId, "device", 1, "user-member-0002")),
      must_fail: true,
      note: "source の付け替え(保護者分片 → device)は Open 失敗(要求者の組み立て経路を偽れない)",
    },
    {
      name: "handoff-share-index-mismatch",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(requestId, all3.group_id, 2, "user-member-0002")),
      must_fail: true,
      note: "分片番号の付け替えは Open 失敗",
    },
    {
      name: "handoff-code-checksum-mismatch",
      base: "handoff-guardian-share",
      code_symbols: badChecksumSymbols,
      must_fail: true,
      note: "1 シンボル違いのコードはチェックサム不一致で拒否(別の公開鍵として黙って解釈しない)",
    },
    {
      name: "handoff-code-bad-padding",
      base: "handoff-guardian-share",
      code_symbols: badPaddingSymbols,
      must_fail: true,
      note: "末尾 2 bit のゼロ詰めが非ゼロのコードは拒否",
    },
    {
      name: "handoff-code-wrong-length",
      base: "handoff-guardian-share",
      code_symbols: code.symbols.slice(0, 57),
      must_fail: true,
      note: "58 シンボル以外は拒否",
    },
    {
      name: "handoff-request-id-other-key",
      base: "handoff-guardian-share",
      open_enc_hex: flipFirstHexNibble(guardianApproval.enc_hex),
      must_fail: true,
      note: "encapsulated key の改竄は Open 失敗",
    },
  ],
};

writeFileSync(
  new URL("../master-key-wrap.json", import.meta.url),
  `${JSON.stringify(vector, null, 2)}\n`,
);
console.log("wrote master-key-wrap.json");
