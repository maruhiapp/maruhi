// RFC 9180 公式テストベクター(Base mode, DHKEM(X25519,HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM)による HPKE 層の検証(CRYPTO_SPEC §11)。
// 実装が採用する panva hpke を直接検証する: DeriveKeyPair 一致 + Open 方向一致
// (Seal 方向の derandomize は panva では不可。spike-c の知見)。

import * as HPKE from "hpke";

import rfcVectors from "../../test-vectors/hpke/rfc9180-base-x25519-hkdfsha256-aes256gcm.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

function suite(): HPKE.CipherSuite {
  return new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
}

export async function rfc9180Checks(): Promise<CheckResult[]> {
  const c = new Checks();
  const vector = rfcVectors[0];
  if (vector === undefined) {
    c.push("rfc9180: vector present", false);
    return c.results;
  }

  // DeriveKeyPair(ikmR) == (pkRm, skRm)
  {
    const s = suite();
    const pair = await s.DeriveKeyPair(fromHex(vector.ikmR), true);
    const pk = await s.SerializePublicKey(pair.publicKey);
    const sk = await s.SerializePrivateKey(pair.privateKey);
    c.push(
      "rfc9180: DeriveKeyPair(ikmR) == (pkRm, skRm)",
      toHex(pk) === vector.pkRm && toHex(sk) === vector.skRm,
    );
  }

  // Open 方向のベクター一致(単発 Open は encryptions[0] = seq 0 に対応)
  {
    const s = suite();
    const enc0 = vector.encryptions[0];
    if (enc0 === undefined) {
      c.push("rfc9180: encryptions present", false);
      return c.results;
    }
    const keyPair = {
      privateKey: await s.DeserializePrivateKey(fromHex(vector.skRm), false),
      publicKey: await s.DeserializePublicKey(fromHex(vector.pkRm)),
    };
    const pt = await s.Open(keyPair, fromHex(vector.enc), fromHex(enc0.ct), {
      info: fromHex(vector.info),
      aad: fromHex(enc0.aad),
    });
    c.push("rfc9180: Open(vector enc/ct) == pt", toHex(pt) === enc0.pt);

    // aad 改竄で Open 失敗(文脈束縛の基礎)
    let failed = false;
    try {
      await s.Open(keyPair, fromHex(vector.enc), fromHex(enc0.ct), {
        info: fromHex(vector.info),
        aad: fromHex(`${enc0.aad.slice(0, -2)}ff`),
      });
    } catch {
      failed = true;
    }
    c.push("rfc9180: tampered aad rejected", failed);
  }

  return c.results;
}
