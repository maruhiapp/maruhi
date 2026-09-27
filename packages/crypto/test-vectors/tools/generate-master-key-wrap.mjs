// Reference generator for master-key-wrap.json (CRYPTO_SPEC §8 — the
// reserve key wrap ledger. Regenerated at 0.9-draft / KL3 and 0.12-draft /
// DK, deleting the old-device handoff route [kind = "device" / source =
// "device"]).
// Uses hpke-js for the same reason as dek-wrap.json / lease-wrap.json: an
// implementation family independent of the panva hpke the product
// implementation adopts, and the Seal direction can be pinned
// deterministically via ekm derandomize (impossible with panva.
// docs/notes/spike-c.md). HKDF / AES-GCM / SHA-256 use WebCrypto (Bun).
// A disposable reference tool, not product code. All keys and values are
// dummies.
//
// Reads recovery-wrap.json and inherits its master_secret_blob_hex (blob B)
// and user_id: the ledger is "the set of wraps that pack the same B for
// each recipient", so it is traceable on the vectors that the
// recovery-code row (an existing vector — unchanged) and the new routes
// point at the same B.
// Since 2026-09-20 DK, B is the blob of the reserve key (§3 / §8.1). The
// old "device migration" (a handoff where the old device acts as
// approver — a co-delivery of the B wrap with kind = "device") was
// removed; approvers are now guardians only (§8.4). Adding a device is
// the chain op `add_device` (§6.2), out of scope for this vector. The
// removal is an intentional exception to README convention 28 (the
// discipline of not changing existing vectors); the byte strings of the
// other cases are unchanged
//
// Pinned (§8.1-8.4):
//   - master_wrap_aad = LP("maruhi/v1/master-wrap", user_id, kind, wrap_ref, mode)
//     (kind in {passkey-prf, guardian} — `device` was removed at
//     2026-09-20 DK)
//   - passkey-prf: KEK = HKDF(prf_out, salt=empty, info="maruhi/v1/passkey-prf")
//   - guardian: mode any = every segment is the KEK / mode all = random
//     XOR split (s_n = KEK XOR the others); a segment is an HPKE Seal
//     (info = LP("maruhi/v1/guardian-wrap", user_id, group_id, mode,
//     share_index, guardian_user_id), aad empty)
//   - handoff: request_id = SHA-256(LP("maruhi/v1/handoff-id", E_pub_hex));
//     handoff code = Base32(E_pub || SHA-256(E_pub)[:4]) in groups of 4
//     characters separated by hyphens; approval = HPKE Seal
//     (info = LP("maruhi/v1/handoff-wrap", user_id, request_id, source,
//     share_index, approver_user_id), aad empty)
//
// Regenerate: bun install && bun run generate (run in this directory)
import { readFileSync, writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

// CRYPTO_SPEC §2.1 length-prefixed encoding (same definition as the other
// generators. tools/ is disposable, so per existing convention each file
// carries its own independent definition rather than sharing a module)
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

// --- Base32 (RFC 4648 alphabet, no padding) ------------------------------
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

// --- Inherit B and user_id from recovery-wrap.json -------------------------------
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

// --- Class S: passkey-prf -----------------------------------------------------
const passkeyWrapId = "01JMKWRAP0000000000000PASSK";
const credentialId = pat(0x11, 16);
const prfSalt = pat(0x20, 32);
const prfOut = pat(0x10, 32); // the authenticator's HMAC output (a fixed pattern in the vector)
const otherPrfOut = pat(0x18, 32); // an output evaluated under a different prf_salt (material for prf-salt-mismatch)
const passkeyKek = await hkdf(prfOut, PASSKEY_HKDF_INFO);
const otherPasskeyKek = await hkdf(otherPrfOut, PASSKEY_HKDF_INFO);
const passkeyNonce = pat(0xe0, 12);
const passkeyAad = masterAad("passkey-prf", passkeyWrapId, "");
const passkeyCt = await aesGcmEncrypt(passkeyKek, passkeyNonce, passkeyAad, blob);

// --- Class G: guardian (any-2 / all-3) ----------------------------------------
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

// --- Class H: handoff ----------------------------------------------------------
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

// The guardian's approval: re-seal segment 1 of all-3 (user-member-0002)
// to E.pub
const guardianApprovalInfo = handoffInfo(requestId, all3.group_id, 1, "user-member-0002");
const guardianApprovalEkm = pat(0x96, 32);
const guardianApproval = await seal(
  ephemeral.pk_hex,
  guardianApprovalInfo,
  all3.shares[0],
  guardianApprovalEkm,
);

// (The old-device approval — a co-delivery of the B wrap with kind =
// "device" — was removed at 2026-09-20 DK. Approvers are guardians only)

// --- Material for the negatives -----------------------------------------------
const flipFirstHexNibble = (h) =>
  `${(Number.parseInt(h.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, "0")}${h.slice(2)}`;
const badChecksumSymbols = `${code.symbols.slice(0, 55)}${code.symbols[55] === "A" ? "B" : "A"}${code.symbols.slice(56)}`;
// The low 2 bits of the final symbol (zero-padding) are non-zero: final
// symbol value +1
const lastValue = B32.indexOf(code.symbols[57]);
const badPaddingSymbols = `${code.symbols.slice(0, 57)}${B32[(lastValue + 1) % 32]}`;

const vector = {
  description:
    'CRYPTO_SPEC §8 (0.9-draft / KL3. Revised into the reserve key wrap ledger at 0.12-draft / DK — regenerated with the old-device handoff route [kind = "device" / source = "device"] removed; the byte strings of the other cases are unchanged): wraps B = the reserve key blob (identical to recovery-wrap.json\'s master_secret_blob_hex) for recipient classes S (passkey-prf: HKDF + AES-256-GCM) / G (guardian: random KEK + AES-256-GCM; segments are HPKE Seals) / H (handoff: a guardian\'s approval — an HPKE Seal to the ephemeral key E). AES-GCM uses WebCrypto; Seal is pinned by hpke-js ekm derandomize (the panva implementation is verified in the Open direction + roundtrip). recovery-wrap.json (the recovery-code row) stays byte-compatible and unchanged',
  provenance_note:
    "user_id and B are inherited from recovery-wrap.json's basic. Expresses in real data that the ledger = the set of per-recipient wraps over the same B (the reserve-key blob since 2026-09-20 DK). kind in {passkey-prf, guardian}; handoff approvers are guardians only (the handoff-device old-device route and the kind = device relabeling negatives were removed at DK — README convention 28)",
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
        note: "The guardian's master enc key (the same key that receives DEK wraps). Deterministic generation via DeriveKeyPair(ikm)",
      },
    ]),
  ),
  ephemeral_keypair: {
    ikm_hex: ephemeral.ikm_hex,
    sk_hex: ephemeral.sk_hex,
    pk_hex: ephemeral.pk_hex,
    note: "The requester's (the device restoring the reserve key) ephemeral X25519 key E. Fixed via DeriveKeyPair(ikm) for vector determinism, but in production it is randomly generated each time and discarded with the requester process (§8.4)",
  },
  passkey: {
    hkdf: { salt: "", info_utf8: PASSKEY_HKDF_INFO, length: 32 },
    note: "prf_out = WebAuthn PRF(credential, eval.first = prf_salt). prf_salt is a per-registration random value and a public parameter. KEK = HKDF-SHA256(prf_out, salt empty, info)",
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
      note: "handoff code = Base32 (RFC 4648 alphabet, no padding) (E_pub 32 B || SHA-256(E_pub)[:4]) = 58 symbols (the trailing 2 bits are zero padding). Display is groups of 4 characters separated by hyphens. Input tolerates lowercase, hyphens, and whitespace; non-alphabet, wrong length, checksum mismatch, or non-zero padding is rejected",
    },
    other_ephemeral: {
      ikm_hex: otherEphemeral.ikm_hex,
      pk_hex: otherEphemeral.pk_hex,
      request_id_hex: otherRequestId,
      note: "A different request (a different ephemeral key). Material for transplant-request-id",
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
      note: "A wrap of B under a passkey-PRF-derived KEK. AAD = LP(master-wrap, user_id, 'passkey-prf', wrap_id, '')",
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
      note: "1-of-n (mode any): every segment is the KEK. Any single piece opens B",
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
      note: "n-of-n (mode all): s_1, s_2 are random; s_3 = KEK XOR s_1 XOR s_2. KEK = the XOR of all pieces",
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
      note: "An approval where guardian user-member-0002 opens segment 1 of guardian-all-3 and re-seals it in place to the requester's E.pub",
    },
  ],
  negative: [
    {
      name: "aad-kind-mismatch",
      base: "guardian-any-2",
      // mode exists only for guardian (§8.1). The mode field of an AAD
      // relabeled to passkey-prf is the empty string
      decrypt_aad_hex: hex(masterAad("passkey-prf", any2.group_id, "")),
      must_fail: true,
      note: "Relabeling the kind (guardian → passkey-prf, same wrap_ref; the mode field is the empty string as the spec prescribes for passkey-prf) fails decryption. Rebuilt at 2026-09-20 DK from the old passkey-prf → device form (device no longer exists in the kind set)",
    },
    {
      name: "aad-wrap-ref-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(masterAad("passkey-prf", "01JMKWRAP0000000000000OTHER", "")),
      must_fail: true,
      note: "Transplanting to a different wrap_id (a different row) fails decryption",
    },
    {
      name: "aad-user-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(
        lpEncode([MASTER_WRAP_DOMAIN, "user-member-0002", "passkey-prf", passkeyWrapId, ""]),
      ),
      must_fail: true,
      note: "Transplanting into another user's ledger fails decryption",
    },
    {
      name: "aad-mode-all-as-any",
      base: "guardian-all-3",
      decrypt_aad_hex: hex(masterAad("guardian", all3.group_id, "any")),
      must_fail: true,
      note: "Even if the server misrepresents an all group as any (misleading the requester into believing one piece suffices), the AAD mode binding fails decryption",
    },
    {
      name: "aad-mode-any-as-all",
      base: "guardian-any-2",
      decrypt_aad_hex: hex(masterAad("guardian", any2.group_id, "all")),
      must_fail: true,
      note: "The opposite direction — misrepresenting an any group as all — also fails decryption",
    },
    {
      name: "share-missing",
      base: "guardian-all-3",
      decrypt_kek_hex: hex(xor(all3.shares[0], all3.shares[1])),
      must_fail: true,
      note: "n-1 pieces (s_1 XOR s_2) do not reconstruct the KEK and decryption fails (pins n-of-n)",
    },
    {
      name: "prf-salt-mismatch",
      base: "passkey-prf-basic",
      other_prf_out_hex: hex(otherPrfOut),
      decrypt_kek_hex: hex(otherPasskeyKek),
      must_fail: true,
      note: "A KEK derived from a PRF output evaluated under a different prf_salt fails decryption (the per-registration random salt = an independent KEK per registration)",
    },
    {
      name: "suite-mismatch",
      base: "passkey-prf-basic",
      decrypt_aad_hex: hex(
        lpEncode(["maruhi/v2/master-wrap", userId, "passkey-prf", passkeyWrapId, ""]),
      ),
      must_fail: true,
      note: "An AAD with the suite portion of the domain string changed fails decryption (suite binding is carried by the domain string)",
    },
    {
      name: "guardian-transplant-share-index",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(all3.group_id, all3.mode, 2, "user-member-0002")),
      must_fail: true,
      note: "Relabeling the share index fails Open",
    },
    {
      name: "guardian-transplant-guardian",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(all3.group_id, all3.mode, 1, "user-admin-0003")),
      must_fail: true,
      note: "Re-attributing to a different guardian fails Open (the key differs too, but this pins that info alone already fails)",
    },
    {
      name: "guardian-transplant-group",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(any2.group_id, all3.mode, 1, "user-member-0002")),
      must_fail: true,
      note: "Transplanting to another group fails Open",
    },
    {
      name: "guardian-mode-relabel",
      base: "guardian-all-3",
      share_index: 1,
      open_info_hex: hex(guardianInfo(all3.group_id, "any", 1, "user-member-0002")),
      must_fail: true,
      note: "On the share side, relabeling the mode also fails Open (double binding by AAD and info)",
    },
    {
      name: "handoff-transplant-request-id",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(otherRequestId, all3.group_id, 1, "user-member-0002")),
      must_fail: true,
      note: "Transplanting to a different request fails Open (an approval is bound to one request)",
    },
    {
      name: "handoff-transplant-approver",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(requestId, all3.group_id, 1, "user-admin-0003")),
      must_fail: true,
      note: "Re-attributing the approver fails Open",
    },
    {
      name: "handoff-transplant-source",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(requestId, any2.group_id, 1, "user-member-0002")),
      must_fail: true,
      note: "Relabeling the source (the guardian segment's group all-3 → another group any-2) fails Open (the requester's assembly route [which group's segment] cannot be forged. Rebuilt at 2026-09-20 DK from the old → device form)",
    },
    {
      name: "handoff-share-index-mismatch",
      base: "handoff-guardian-share",
      open_info_hex: hex(handoffInfo(requestId, all3.group_id, 2, "user-member-0002")),
      must_fail: true,
      note: "Relabeling the share index fails Open",
    },
    {
      name: "handoff-code-checksum-mismatch",
      base: "handoff-guardian-share",
      code_symbols: badChecksumSymbols,
      must_fail: true,
      note: "A code one symbol off is rejected on checksum mismatch (not silently interpreted as a different public key)",
    },
    {
      name: "handoff-code-bad-padding",
      base: "handoff-guardian-share",
      code_symbols: badPaddingSymbols,
      must_fail: true,
      note: "A code whose trailing 2-bit zero padding is non-zero is rejected",
    },
    {
      name: "handoff-code-wrong-length",
      base: "handoff-guardian-share",
      code_symbols: code.symbols.slice(0, 57),
      must_fail: true,
      note: "Anything other than 58 symbols is rejected",
    },
    {
      name: "handoff-request-id-other-key",
      base: "handoff-guardian-share",
      open_enc_hex: flipFirstHexNibble(guardianApproval.enc_hex),
      must_fail: true,
      note: "Tampering with the encapsulated key fails Open",
    },
  ],
};

writeFileSync(
  new URL("../master-key-wrap.json", import.meta.url),
  `${JSON.stringify(vector, null, 2)}\n`,
);
console.log("wrote master-key-wrap.json");
