// CRYPTO_SPEC §3(鍵生成・フィンガープリント・DEK)のチェック。
// フィンガープリントは test-vectors/chain-entries.json の keys / server_key で固定。

import {
  computeServerKeyFingerprint,
  computeUserKeyFingerprint,
  deriveEncryptionKeyPair,
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
  unwrapDek,
  wrapDek,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import dekWrapVectors from "../../test-vectors/dek-wrap.json" with { type: "json" };
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

async function deriveChecks(c: Checks): Promise<void> {
  // RFC 9180 DeriveKeyPair: dek-wrap.json の server_keypair(hpke-js で導出)と
  // 同じ ikm から同じ公開鍵が導出される(デプロイメント keypair — §9 — の
  // 「secret 1 本 → keypair」経路の固定。RFC 公式ベクターは rfc9180.ts が担う)
  const serverKeys = dekWrapVectors.server_keypair;
  const derived = await deriveEncryptionKeyPair({ ikm: fromHex(serverKeys.ikmS_hex) });
  if (!derived.ok) {
    c.push("keys: derive server keypair from ikm", false, "derive failed");
  } else {
    const pub = await exportEncryptionPublicKey(derived.value.publicKey);
    const fp = await computeServerKeyFingerprint(pub);
    c.push("keys: derive server keypair from ikm", toHex(pub) === serverKeys.pkSm_hex);
    c.push(
      "keys: derived server fingerprint",
      fp.ok && toHex(fp.value) === serverKeys.server_key_fingerprint_hex,
    );
    // 非抽出が既定(サーバー側の運用姿勢): エクスポートは KeyExportFailed
    const denied = await exportEncryptionPrivateKey(derived.value.privateKey);
    c.push(
      "keys: derived private key is non-extractable by default",
      !denied.ok && denied.error.kind === "KeyExportFailed",
    );
  }
  // ikm 長不正は InvalidInput(throw しない)
  const badIkm = await deriveEncryptionKeyPair({ ikm: new Uint8Array(31) });
  c.push("keys: derive rejects bad ikm length", !badIkm.ok && badIkm.error.kind === "InvalidInput");
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

async function encExportChecks(c: Checks): Promise<void> {
  // enc 秘密鍵: extractable 生成 → raw エクスポート → 再インポートした鍵ペアで
  // HPKE Open が機能する(公開鍵一致は入力からの復元で自明のため、機能検証で
  // エクスポート値の正しさを固定する — CLI の OS キーチェーン経路 CRYPTO_SPEC §3)
  const enc = await generateEncryptionKeyPair({ extractable: true });
  const encSk = await exportEncryptionPrivateKey(enc.privateKey);
  const encPub = await exportEncryptionPublicKey(enc.publicKey);
  let encRoundtrip = false;
  if (encSk.ok && encSk.value.length === 32) {
    const reimported = await importEncryptionKeyPair({
      publicKey: encPub,
      privateKey: encSk.value,
    });
    if (reimported.ok) {
      const dek = generateDek();
      const context = {
        projectId: "p".repeat(64),
        environmentId: "env-export-check",
        epoch: 1,
        recipientUserId: "user-export-check",
      };
      const wrapped = await wrapDek({ recipientPublicKey: enc.publicKey, dek, context });
      if (wrapped.ok) {
        const opened = await unwrapDek({
          recipientKeyPair: reimported.value,
          wrapped: wrapped.value,
          context,
        });
        encRoundtrip = opened.ok && toHex(opened.value) === toHex(dek);
      }
    }
  }
  c.push("keys: encryption private key export/import round trip (HPKE open)", encRoundtrip);
}

async function sigExportChecks(c: Checks): Promise<void> {
  // sig 秘密鍵: extractable 生成 → seed エクスポート → 再インポートした秘密鍵の
  // 署名が「元の」公開鍵で検証できる(機能検証)
  const sig = await generateSigningKeyPair({ extractable: true });
  const sigSeed = await exportSigningPrivateSeed(sig.privateKey);
  const sigPub = await exportSigningPublicKey(sig.publicKey);
  let sigRoundtrip = false;
  if (sigSeed.ok && sigSeed.value.length === 32) {
    const reimported = await importSigningKeyPair({
      publicKey: sigPub,
      privateSeed: sigSeed.value,
    });
    if (reimported.ok) {
      const message = new TextEncoder().encode("export-check");
      const signature = new Uint8Array(
        await crypto.subtle.sign("Ed25519", reimported.value.privateKey, message as BufferSource),
      );
      sigRoundtrip = await crypto.subtle.verify(
        "Ed25519",
        sig.publicKey,
        signature as BufferSource,
        message as BufferSource,
      );
    }
  }
  c.push("keys: signing private seed export/import round trip (sign/verify)", sigRoundtrip);
}

async function vectorExportChecks(c: Checks): Promise<void> {
  // ベクター固定: chain-entries.json の固定鍵を extractable でインポート →
  // エクスポートがベクターの秘密鍵 hex と一致する(決定的検査)
  const ownerKeys = users["user-owner-0001"];
  if (ownerKeys === undefined) {
    c.push("keys: vector user-owner-0001 present for export checks", false);
  } else {
    const encPair = await importEncryptionKeyPair({
      publicKey: fromHex(ownerKeys.enc_pub_hex),
      privateKey: fromHex(ownerKeys.enc_sk_seed_hex),
      extractable: true,
    });
    const encExported = encPair.ok
      ? await exportEncryptionPrivateKey(encPair.value.privateKey)
      : null;
    c.push(
      "keys: encryption private key export matches vector",
      encExported !== null &&
        encExported.ok &&
        toHex(encExported.value) === ownerKeys.enc_sk_seed_hex,
    );
    const sigPair = await importSigningKeyPair({
      publicKey: fromHex(ownerKeys.sig_pub_hex),
      privateSeed: fromHex(ownerKeys.sig_sk_seed_hex),
      extractable: true,
    });
    const sigExported = sigPair.ok
      ? await exportSigningPrivateSeed(sigPair.value.privateKey)
      : null;
    c.push(
      "keys: signing private seed export matches vector",
      sigExported !== null &&
        sigExported.ok &&
        toHex(sigExported.value) === ownerKeys.sig_sk_seed_hex,
    );
  }
}

async function lockedExportChecks(c: Checks): Promise<void> {
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
  await deriveChecks(c);
  await vectorImportChecks(c);
  await generationChecks(c);
  await encExportChecks(c);
  await sigExportChecks(c);
  await vectorExportChecks(c);
  await lockedExportChecks(c);
  return c.results;
}
