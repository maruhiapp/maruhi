// CRYPTO_SPEC §3(鍵生成・フィンガープリント・DEK)のチェック。
// フィンガープリントは test-vectors/chain-entries.json の keys / server_key で固定。

import {
  computeServerKeyFingerprint,
  computeUserKeyFingerprint,
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
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

interface VectorUserKeys {
  readonly enc_sk_seed_hex: string;
  readonly sig_sk_seed_hex: string;
  readonly enc_pub_hex: string;
  readonly sig_pub_hex: string;
  readonly key_fingerprint_hex: string;
}

const users = chainVectors.keys as Readonly<Record<string, VectorUserKeys>>;

async function fingerprintChecks(c: Checks): Promise<void> {
  // ユーザー鍵フィンガープリント: SHA-256(enc_pub || sig_pub) 先頭 16 バイト
  for (const [userId, keys] of Object.entries(users)) {
    const fp = await computeUserKeyFingerprint(
      fromHex(keys.enc_pub_hex),
      fromHex(keys.sig_pub_hex),
    );
    c.push(
      `keys: user fingerprint ${userId}`,
      fp.ok && toHex(fp.value) === keys.key_fingerprint_hex,
    );
  }

  // サーバー鍵フィンガープリント: SHA-256(server_enc_pub) 先頭 16 バイト(enc 鍵のみ)
  const server = chainVectors.server_key;
  const serverFp = await computeServerKeyFingerprint(fromHex(server.enc_pub_hex));
  c.push(
    "keys: server fingerprint",
    serverFp.ok && toHex(serverFp.value) === server.key_fingerprint_hex,
  );

  // 長さ検証: 32 バイト以外は InvalidInput
  const bad = await computeUserKeyFingerprint(new Uint8Array(31), new Uint8Array(32));
  c.push("keys: fingerprint rejects bad length", !bad.ok && bad.error.kind === "InvalidInput");
}

async function vectorImportChecks(c: Checks): Promise<void> {
  const owner = users["user-owner-0001"];
  if (owner === undefined) {
    c.push("keys: vector user-owner-0001 present", false);
    return;
  }

  // sig 鍵の seed → JWK インポートがベクターの公開鍵と整合する
  const sigPair = await importSigningKeyPair({
    publicKey: fromHex(owner.sig_pub_hex),
    privateSeed: fromHex(owner.sig_sk_seed_hex),
  });
  const sigRoundtrip =
    sigPair.ok &&
    toHex(await exportSigningPublicKey(sigPair.value.publicKey)) === owner.sig_pub_hex;
  c.push("keys: signing key pair import from seed", sigRoundtrip);

  // enc KeyPair の raw インポート(非抽出)— HPKE Open の KeyPair 渡し経路の前提。
  // enc_sk_seed は X25519 の生秘密鍵として生成されている(from_private_bytes)
  const encPair = await importEncryptionKeyPair({
    publicKey: fromHex(owner.enc_pub_hex),
    privateKey: fromHex(owner.enc_sk_seed_hex),
  });
  const encRoundtrip =
    encPair.ok &&
    toHex(await exportEncryptionPublicKey(encPair.value.publicKey)) === owner.enc_pub_hex &&
    encPair.value.privateKey.extractable === false;
  c.push("keys: encryption key pair import (non-extractable)", encRoundtrip);
}

async function generationChecks(c: Checks): Promise<void> {
  // 鍵生成: enc(X25519)/ sig(Ed25519)の公開鍵は 32 バイト raw で往復できる
  const enc = await generateEncryptionKeyPair();
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  const encImported = await importEncryptionPublicKey(encPub);
  c.push(
    "keys: encryption key pair generate/export/import",
    encPub.length === 32 && encImported.ok && enc.privateKey.extractable === false,
  );

  const sig = await generateSigningKeyPair();
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  const sigImported = await importSigningPublicKey(sigPub);
  c.push(
    "keys: signing key pair generate/export/import",
    sigPub.length === 32 && sigImported.ok && sig.privateKey.extractable === false,
  );

  // DEK: 256-bit 乱数。長さと(確率的にだが)一意性
  const a = generateDek();
  const b = generateDek();
  c.push("keys: DEK is 32 bytes and random", a.length === 32 && toHex(a) !== toHex(b));
}

async function privateExportChecks(c: Checks): Promise<void> {
  // enc 秘密鍵: extractable 生成 → raw エクスポート → 再インポートで公開鍵が一致
  // (CLI が master keypair を OS キーチェーンへ保存する経路 — CRYPTO_SPEC §3)
  const enc = await generateEncryptionKeyPair({ extractable: true });
  const encSk = await exportEncryptionPrivateKey(enc.privateKey);
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  let encRoundtrip = false;
  if (encSk.ok) {
    const reimported = await importEncryptionKeyPair({
      publicKey: encPub,
      privateKey: encSk.value,
    });
    encRoundtrip =
      encSk.value.length === 32 &&
      reimported.ok &&
      toHex(await exportEncryptionPublicKey(reimported.value.publicKey)) === toHex(encPub);
  }
  c.push("keys: encryption private key export/import round trip", encRoundtrip);

  // sig 秘密鍵: extractable 生成 → seed エクスポート → 再インポートで公開鍵が一致
  const sig = await generateSigningKeyPair({ extractable: true });
  const sigSeed = await exportSigningPrivateSeed(sig.privateKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  let sigRoundtrip = false;
  if (sigSeed.ok) {
    const reimported = await importSigningKeyPair({
      publicKey: sigPub,
      privateSeed: sigSeed.value,
    });
    sigRoundtrip =
      sigSeed.value.length === 32 &&
      reimported.ok &&
      toHex(await exportSigningPublicKey(reimported.value.publicKey)) === toHex(sigPub);
  }
  c.push("keys: signing private seed export/import round trip", sigRoundtrip);

  // 非抽出鍵のエクスポートは KeyExportFailed(throw しない)
  const encLocked = await generateEncryptionKeyPair();
  const encDenied = await exportEncryptionPrivateKey(encLocked.privateKey);
  c.push(
    "keys: non-extractable encryption private key export fails",
    !encDenied.ok && encDenied.error.kind === "KeyExportFailed",
  );
  const sigLocked = await generateSigningKeyPair();
  const sigDenied = await exportSigningPrivateSeed(sigLocked.privateKey);
  c.push(
    "keys: non-extractable signing private key export fails",
    !sigDenied.ok && sigDenied.error.kind === "KeyExportFailed",
  );
}

export async function keysChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await fingerprintChecks(c);
  await vectorImportChecks(c);
  await generationChecks(c);
  await privateExportChecks(c);
  return c.results;
}
