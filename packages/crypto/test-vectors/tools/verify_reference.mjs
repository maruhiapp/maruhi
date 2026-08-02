// テストベクターの独立検証スクリプト(使い捨てツール。製品コードではない)。
// 生成系(pyca/cryptography、hpke-js)とは別の実装系で全ベクターを検証する:
//   - encoding / variable-encryption / chain-entries / recovery-wrap → WebCrypto(Bun)
//   - dek-wrap → panva hpke(製品実装が採用予定のライブラリ)で Open
// これにより「期待値が正しいこと」と「実装予定スタックで再現できること」を両方確認する。
// 実行: bun run verify_reference.mjs(このディレクトリで実行。exit 0 = 全検証通過)
import { readFileSync } from "node:fs";

import * as HPKE from "hpke";

const read = (name) => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), "utf8"));
const fromHex = (h) => Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");

function lpEncode(fields) {
  const parts = [];
  for (const f of fields) {
    const bytes =
      f instanceof Uint8Array ? f : new TextEncoder().encode(typeof f === "number" ? String(f) : f);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    parts.push(len, bytes);
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures += 1;
};

// --- encoding.json -----------------------------------------------------------
{
  const doc = read("encoding.json");
  for (const c of doc.cases) {
    check(`encoding: ${c.name}`, toHex(lpEncode(c.fields)) === c.expected_hex);
  }
}

// --- variable-encryption.json ------------------------------------------------
async function aesGcmDecrypt(keyHex, nonceHex, aadHex, ctHex) {
  const key = await crypto.subtle.importKey("raw", fromHex(keyHex), "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromHex(nonceHex), additionalData: fromHex(aadHex) },
      key,
      fromHex(ctHex),
    ),
  );
}

{
  const doc = read("variable-encryption.json");
  const base = doc.vectors[0];
  const aad = lpEncode([
    base.suite,
    base.project_id,
    base.environment_id,
    base.epoch,
    base.variable_id,
    base.version,
  ]);
  check("var-enc: aad reconstruction", toHex(aad) === base.aad_hex);
  const pt = await aesGcmDecrypt(base.key_hex, base.nonce_hex, base.aad_hex, base.ciphertext_hex);
  check("var-enc: basic decrypt", new TextDecoder().decode(pt) === base.plaintext_utf8);
  for (const n of doc.negative) {
    let failed = false;
    try {
      await aesGcmDecrypt(
        base.key_hex,
        n.decrypt_nonce_hex ?? base.nonce_hex,
        n.decrypt_aad_hex ?? base.aad_hex,
        n.ciphertext_hex ?? base.ciphertext_hex,
      );
    } catch {
      failed = true;
    }
    check(`var-enc negative: ${n.name}`, failed === n.must_fail);
  }
}

// --- chain-entries.json ------------------------------------------------------
{
  const doc = read("chain-entries.json");
  const order = doc.canonicalization.payload_field_order;
  let prevHash = "0".repeat(64);
  const sha256 = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  for (const e of doc.entries) {
    const payloadBytes = lpEncode(order[e.op].map((k) => e.payload[k]));
    check(`chain seq ${e.seq}: payload bytes`, toHex(payloadBytes) === e.payload_bytes_hex);
    const signed = lpEncode([
      e.suite,
      e.seq,
      e.prev_hash_hex,
      e.op,
      e.actor.user_id,
      e.actor.key_fingerprint_hex,
      payloadBytes,
      e.timestamp_ms,
    ]);
    check(`chain seq ${e.seq}: signed bytes`, toHex(signed) === e.signed_bytes_hex);
    check(`chain seq ${e.seq}: prev_hash linkage`, e.prev_hash_hex === prevHash);
    const sigPubHex = doc.keys[e.actor.user_id].sig_pub_hex;
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(sigPubHex),
      fromHex(e.signature_hex),
      signed,
    );
    check(`chain seq ${e.seq}: Ed25519 signature`, ok);
    const entryBytes = lpEncode([
      e.suite,
      e.seq,
      e.prev_hash_hex,
      e.op,
      e.actor.user_id,
      e.actor.key_fingerprint_hex,
      payloadBytes,
      e.timestamp_ms,
      e.signature_hex,
    ]);
    check(`chain seq ${e.seq}: entry bytes`, toHex(entryBytes) === e.entry_bytes_hex);
    const hash = await sha256(entryBytes);
    check(`chain seq ${e.seq}: entry hash`, hash === e.entry_hash_hex);
    prevHash = hash;
  }
  // 鍵フィンガープリント: SHA-256(enc_pub || sig_pub) 先頭 16 バイト(素の連結)
  for (const [uid, k] of Object.entries(doc.keys)) {
    const cat = new Uint8Array([...fromHex(k.enc_pub_hex), ...fromHex(k.sig_pub_hex)]);
    const fp = (await sha256(cat)).slice(0, 32);
    check(`chain: fingerprint ${uid}`, fp === k.key_fingerprint_hex);
  }
  // サーバー鍵フィンガープリント: SHA-256(server_enc_pub) 先頭 16 バイト(enc 鍵のみ。§9)
  {
    const fp = (await sha256(fromHex(doc.server_key.enc_pub_hex))).slice(0, 32);
    check("chain: server key fingerprint", fp === doc.server_key.key_fingerprint_hex);
  }
  // grant_server の scope_environments: 入れ子 LP(環境 ID リストの LP の hex 文字列)
  {
    const e7 = doc.entries.find((e) => e.op === "grant_server");
    check(
      "chain: grant_server scope nested LP",
      toHex(lpEncode(e7.payload.scope_environments)) === e7.payload.scope_environments_lp_hex,
    );
  }
  for (const n of doc.negative) {
    if (n.name === "prev-hash-mismatch") {
      check(`chain negative: ${n.name}`, n.claimed_prev_hash_hex !== n.expected_prev_hash_hex);
      continue;
    }
    if (n.kind === "authorization") {
      // 認可系は「暗号学的には有効(署名・正規化・prev_hash が正しい)」ことを確認する。
      // 拒否は §6.2 の権限規則によるもので、その検査は実装テストが担う
      const e = n.entry;
      const payloadBytes = lpEncode(order[e.op].map((k) => e.payload[k]));
      const signed = lpEncode([
        e.suite,
        e.seq,
        e.prev_hash_hex,
        e.op,
        e.actor.user_id,
        e.actor.key_fingerprint_hex,
        payloadBytes,
        e.timestamp_ms,
      ]);
      const sigOk = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(n.verify_key_hex),
        fromHex(e.signature_hex),
        signed,
      );
      check(
        `chain authz negative: ${n.name} (signature must be VALID)`,
        sigOk && toHex(signed) === e.signed_bytes_hex,
      );
      continue;
    }
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      fromHex(n.signed_bytes_hex),
    );
    check(`chain negative: ${n.name}`, ok === false);
  }
}

// --- recovery-wrap.json ------------------------------------------------------
{
  const doc = read("recovery-wrap.json");
  const base = doc.vectors[0];
  const ikm = await crypto.subtle.importKey(
    "raw",
    fromHex(base.recovery_secret_hex),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const kek = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(base.hkdf.info_utf8),
      },
      ikm,
      256,
    ),
  );
  check("recovery: KEK derivation (salt empty)", toHex(kek) === base.kek_hex);
  const aad = lpEncode(["maruhi/v1/recovery-wrap", base.user_id]);
  check("recovery: aad reconstruction", toHex(aad) === base.aad_hex);
  const pt = await aesGcmDecrypt(base.kek_hex, base.nonce_hex, base.aad_hex, base.ciphertext_hex);
  check("recovery: basic decrypt", toHex(pt) === base.master_secret_blob_hex);
  for (const n of doc.negative) {
    let failed = false;
    try {
      await aesGcmDecrypt(
        n.decrypt_kek_hex ?? base.kek_hex,
        base.nonce_hex,
        n.decrypt_aad_hex ?? base.aad_hex,
        n.ciphertext_hex ?? base.ciphertext_hex,
      );
    } catch {
      failed = true;
    }
    check(`recovery negative: ${n.name}`, failed === n.must_fail);
  }
}

// --- dek-wrap.json(panva hpke で Open)--------------------------------------
{
  const doc = read("dek-wrap.json");
  const base = doc.vectors[0];
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  // KeyPair 渡しの Open を標準とする(CRYPTO_SPEC §2。非抽出鍵と両立する経路)
  const keyPair = {
    privateKey: await suite.DeserializePrivateKey(fromHex(doc.recipient_keypair.skRm_hex), false),
    publicKey: await suite.DeserializePublicKey(fromHex(doc.recipient_keypair.pkRm_hex)),
  };
  const open = (infoHex, encHex, ctHex) =>
    suite.Open(keyPair, fromHex(encHex), fromHex(ctHex), {
      info: fromHex(infoHex),
      aad: fromHex(base.aad_hex),
    });
  const dek = await open(base.info_hex, base.enc_hex, base.ciphertext_hex);
  check("dek-wrap: panva open == DEK", toHex(new Uint8Array(dek)) === base.dek_hex);
  for (const n of doc.negative) {
    let failed = false;
    try {
      await open(
        n.open_info_hex ?? base.info_hex,
        n.enc_hex ?? base.enc_hex,
        n.ciphertext_hex ?? base.ciphertext_hex,
      );
    } catch {
      failed = true;
    }
    check(`dek-wrap negative: ${n.name}`, failed === n.must_fail);
  }
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall vectors verified");
