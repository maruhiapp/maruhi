// Reference generator for dek-wrap.json (CRYPTO_SPEC §5).
// Generation uses hpke-js (@hpke/core + @hpke/dhkem-x25519): an
// implementation family independent of the panva hpke the product
// implementation adopts, and the Seal direction can be pinned
// deterministically via ekm derandomize (impossible with panva.
// docs/notes/spike-c.md).
// A disposable reference tool, not product code. All keys and values are
// dummies.
// Regenerate: bun install && bun run generate-dek-wrap.mjs (run in this
// directory)
import { writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

// CRYPTO_SPEC §2.1 length-prefixed encoding (same definition as generate_reference.py)
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

// The recipient key is a DeriveKeyPair from a fixed ikm (deterministic)
const ikmR = pat(0x70, 32);
const kp = await suite.kem.deriveKeyPair(ikmR.slice().buffer);
const pkRm = new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey));
const skRm = new Uint8Array(await suite.kem.serializePrivateKey(kp.privateKey));

// Recipient class server (CRYPTO_SPEC §9. 2026-08-12): the server
// (deployment) key is also a DeriveKeyPair from a fixed ikm. The
// recipient_user_id position of info carries the server key FP
// (lowercase hex of SHA-256(server_enc_pub)[:16]) (a server has no
// user_id)
const ikmS = pat(0xb0, 32);
const kpS = await suite.kem.deriveKeyPair(ikmS.slice().buffer);
const pkSm = new Uint8Array(await suite.kem.serializePublicKey(kpS.publicKey));
const skSm = new Uint8Array(await suite.kem.serializePrivateKey(kpS.privateKey));
const serverFpHex = hex(
  new Uint8Array(await crypto.subtle.digest("SHA-256", pkSm.slice())).slice(0, 16),
);

const projectId = "proj-0001";
const environmentId = "env-prod-0001";
const epoch = 3;
const recipientUserId = "user-recipient-0002";
const infoFields = ["maruhi/v1/dek-wrap", projectId, environmentId, epoch, recipientUserId];
const info = lpEncode(infoFields);
const serverInfoFields = ["maruhi/v1/dek-wrap", projectId, environmentId, epoch, serverFpHex];
const serverInfo = lpEncode(serverInfoFields);
const dek = pat(0x80, 32);
const ikmE = pat(0x90, 32);
const ikmE2 = pat(0xc0, 32); // for the server-bound Seal (an independent ekm per Seal)
const aad = new Uint8Array(0); // §5: context binding is carried by info; aad is empty

async function seal(infoBytes, recipientPk, ekm) {
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(recipientPk.slice().buffer),
    info: infoBytes.slice().buffer,
    ekm: ekm.slice().buffer,
  });
  const ct = new Uint8Array(await sender.seal(dek.slice().buffer, aad.slice().buffer));
  return { enc: new Uint8Array(sender.enc), ct };
}

const { enc, ct } = await seal(info, pkRm, ikmE);
// Also wrap the same-epoch DEK to the server key (same shape as a real
// recipient set: one DEK x multiple recipients. The §7 wrap-complete set)
const { enc: serverEnc, ct: serverCt } = await seal(serverInfo, pkSm, ikmE2);

const tamperedEnc = enc.slice();
tamperedEnc[0] ^= 0x01;

// The server key FP with its first byte flipped — "another server key's FP" (for the transplant negative)
const wrongServerFp = `${(Number.parseInt(serverFpHex.slice(0, 2), 16) ^ 0x01)
  .toString(16)
  .padStart(2, "0")}${serverFpHex.slice(2)}`;

const vector = {
  description:
    "CRYPTO_SPEC §5: DEK wrap (HPKE Base mode single Seal, DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+AES-256-GCM). info is the §2.1 encoding. Seal is pinned by hpke-js ekm derandomize (the panva implementation is verified in the Open direction + roundtrip)",
  info_fields_order: ["domain", "project_id", "environment_id", "epoch", "recipient_user_id"],
  server_recipient_note:
    "Recipient class server (§9. 2026-08-12): the recipient_user_id position of info carries the server key FP (lowercase hex of SHA-256(server_enc_pub)[:16]). Pinned by server-basic and its negatives",
  recipient_keypair: {
    ikmR_hex: hex(ikmR),
    skRm_hex: hex(skRm),
    pkRm_hex: hex(pkRm),
    note: "Deterministic generation via DeriveKeyPair(ikmR). The same API is verified by the RFC 9180 vectors (hpke/)",
  },
  server_keypair: {
    ikmS_hex: hex(ikmS),
    skSm_hex: hex(skSm),
    pkSm_hex: hex(pkSm),
    server_key_fingerprint_hex: serverFpHex,
    note: "The server (deployment) key. Deterministic generation via DeriveKeyPair(ikmS). FP = SHA-256(pkSm)[:16] (§9 — enc key only, so the §3 enc||sig definition does not apply)",
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
    {
      name: "server-basic",
      domain: "maruhi/v1/dek-wrap",
      project_id: projectId,
      environment_id: environmentId,
      epoch,
      recipient_class: "server",
      server_key_fingerprint_hex: serverFpHex,
      info_hex: hex(serverInfo),
      dek_hex: hex(dek),
      ikmE_hex: hex(ikmE2),
      aad_hex: "",
      enc_hex: hex(serverEnc),
      ciphertext_hex: hex(serverCt),
      note: "A positive case wrapping the same epoch DEK as basic to the server key (recipient class server). The recipient position of info is the server key FP",
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
      note: "Substituting the epoch (transplanting to another epoch) fails Open",
    },
    {
      name: "info-recipient-mismatch",
      base: "basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, environmentId, epoch, "user-owner-0001"]),
      ),
      must_fail: true,
      note: "Substituting the recipient (transplanting a member-bound wrap) fails Open",
    },
    {
      name: "info-environment-mismatch",
      base: "basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, "env-dev-0002", epoch, recipientUserId]),
      ),
      must_fail: true,
      note: "Substituting the environment fails Open (context binding of the environment model)",
    },
    {
      name: "enc-tampered",
      base: "basic",
      enc_hex: hex(tamperedEnc),
      must_fail: true,
      note: "Tampering with enc (the encapsulated public key) fails Open",
    },
    {
      name: "server-info-member-user-id",
      base: "server-basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, environmentId, epoch, recipientUserId]),
      ),
      must_fail: true,
      note: "info with a member user_id in the recipient position of a server-bound wrap fails Open (rejects transplant across recipient classes)",
    },
    {
      name: "server-info-fp-mismatch",
      base: "server-basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, environmentId, epoch, wrongServerFp]),
      ),
      must_fail: true,
      note: "info with another server key's FP in the recipient position fails Open (rejects transplant between server keys)",
    },
    {
      name: "member-info-server-fp",
      base: "basic",
      open_info_hex: hex(
        lpEncode(["maruhi/v1/dek-wrap", projectId, environmentId, epoch, serverFpHex]),
      ),
      must_fail: true,
      note: "info with a server key FP in the recipient position of a member-bound wrap also fails Open (rejects reverse-direction recipient-class transplant)",
    },
  ],
};

writeFileSync(new URL("../dek-wrap.json", import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log("wrote dek-wrap.json");
