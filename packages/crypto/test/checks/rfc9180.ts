// Verification of the HPKE layer against the official RFC 9180 test vectors
// (Base mode, DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, AES-256-GCM)
// (CRYPTO_SPEC §11).
// Verifies the panva hpke the implementation adopts directly: DeriveKeyPair
// match + Open-direction match (derandomizing the Seal direction is impossible
// with panva).

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

  // Open-direction vector match (a single-shot Open corresponds to encryptions[0] = seq 0)
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

    // Open fails on tampered aad (the basis of context binding)
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
