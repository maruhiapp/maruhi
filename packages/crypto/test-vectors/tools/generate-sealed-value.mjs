// Reference generator for sealed-value.json (CRYPTO_SPEC §5.3 — sealed
// value proposals). Uses hpke-js for the same reason as dek-wrap.json:
// an implementation family independent of the panva hpke the product
// implementation adopts, and the Seal direction can be pinned
// deterministically via ekm derandomize (impossible with panva.
// docs/notes/spike-c.md). A disposable reference tool, not product code.
// All keys and values are dummies.
//
// Reads dek-wrap.json and seals to the **same recipient device key** as
// its `basic` vector, at the same project / environment coordinates: a
// sealed value goes to the device key that also receives DEK wraps
// (§5.3 — the recipient set W(E) is a subset of R(E)). The plaintext is
// a dummy credential string, not a DEK.
//
// Regenerate: bun install && bun run generate (run in this directory —
// after generate-dek-wrap.mjs)
import { readFileSync, writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

// CRYPTO_SPEC §2.1 length-prefixed encoding (each tool carries its own
// independent definition — tools/ is disposable)
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
const utf8 = (s) => new TextEncoder().encode(s);

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

// --- Inherit the recipient device key and coordinates from dek-wrap.json ---
const dekWrapDoc = JSON.parse(readFileSync(new URL("../dek-wrap.json", import.meta.url), "utf8"));
const basicWrap = dekWrapDoc.vectors.find((v) => v.name === "basic");
if (basicWrap === undefined) {
  throw new Error("dek-wrap.json is missing the basic vector");
}
const projectId = basicWrap.project_id;
const environmentId = basicWrap.environment_id;
const recipientUserId = basicWrap.recipient_user_id;
const pkRm = fromHex(dekWrapDoc.recipient_keypair.pkRm_hex);

// The proposal id is client-chosen (16 random bytes as lowercase hex —
// §5.3). A fixed pattern for the vector
const proposalId = hex(pat(0x30, 16));
const otherProposalId = hex(pat(0x31, 16));
const variableId = "var-database-url-0001";
const companionVariableId = "var-database-user-0001";

// Dummy proposed credentials (the plaintext of a sealed value is the
// proposed variable value's bytes — a text credential here)
const value = utf8("postgres://app_b:rotated-dummy-password@db.example:5432/shop");
const companionValue = utf8("app_b");

// --- The sealed value (§5.3) -------------------------------------------
// info = LP("maruhi/v1/sealed-value", project_id, environment_id, proposal_id, variable_id, base_version, recipient_user_id)
// base_version = the version the proposed value replaces (a server cannot
// re-label a stale proposal as current — the member's Open fails)
const SEALED_DOMAIN = "maruhi/v1/sealed-value";
const DEK_WRAP_DOMAIN = "maruhi/v1/dek-wrap";
const baseVersion = 3;
const companionBaseVersion = 1;
const sealedInfo = (proj, env, proposal, variable, version, recipient) =>
  lpEncode([SEALED_DOMAIN, proj, env, proposal, variable, version, recipient]);

const info = sealedInfo(
  projectId,
  environmentId,
  proposalId,
  variableId,
  baseVersion,
  recipientUserId,
);
const companionInfo = sealedInfo(
  projectId,
  environmentId,
  proposalId,
  companionVariableId,
  companionBaseVersion,
  recipientUserId,
);
const aad = new Uint8Array(0); // Same as §5: context binding is carried by info; aad is empty

const ikmE = pat(0x50, 32);
const ikmE2 = pat(0x60, 32); // an independent ekm per Seal

async function seal(infoBytes, plaintext, ekm) {
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(pkRm.slice().buffer),
    info: infoBytes.slice().buffer,
    ekm: ekm.slice().buffer,
  });
  const ct = new Uint8Array(await sender.seal(plaintext.slice().buffer, aad.slice().buffer));
  return { enc: new Uint8Array(sender.enc), ct };
}

const basic = await seal(info, value, ikmE);
const companion = await seal(companionInfo, companionValue, ikmE2);

// A tampered ciphertext (one byte flipped inside the AES-GCM body) must
// fail Open — pins that the tag covers the whole body
const tampered = basic.ct.slice();
tampered[3] ^= 0x01;

const vector = {
  description:
    "CRYPTO_SPEC §5.3: a sealed value proposal (HPKE Base mode single Seal of a proposed variable value to one recipient device key — the same primitive as §5 / §9.1). info binds the project, environment, proposal id, variable id, the version the value replaces and the recipient user id, so a sealed value cannot be re-filed under another proposal, variable, base version or recipient. Seal is pinned by hpke-js ekm derandomize (the panva implementation is verified in the Open direction + roundtrip)",
  info_fields_order: [
    "domain",
    "project_id",
    "environment_id",
    "proposal_id",
    "variable_id",
    "base_version",
    "recipient_user_id",
  ],
  recipient_note:
    "The recipient key pair and the project / environment coordinates are identical to dek-wrap.json's basic (recipient_keypair / project_id / environment_id / recipient_user_id): a sealed value is addressed to the device key that also receives DEK wraps (§5.3 — W(E) ⊆ R(E) minus readers and server keys). The private key for the Open direction is dek-wrap.json's recipient_keypair.skRm_hex",
  signature_note:
    "A sealed value carries no §5.1 registration signature (the workload holds no on-chain key — §5.3). Attribution is the lease's claims_digest and the grant's chain seq, recorded by the server beside the proposal (AUTH_SPEC §14-5)",
  proposal: {
    proposal_id: proposalId,
    other_proposal_id: otherProposalId,
    note: "proposal_id is 16 random bytes as lowercase hex, chosen by the minting client (fixed here for determinism). other_proposal_id is the material for info-proposal-mismatch",
  },
  vectors: [
    {
      name: "basic",
      domain: SEALED_DOMAIN,
      project_id: projectId,
      environment_id: environmentId,
      proposal_id: proposalId,
      variable_id: variableId,
      base_version: baseVersion,
      recipient_user_id: recipientUserId,
      info_hex: hex(info),
      plaintext_hex: hex(value),
      ikmE_hex: hex(ikmE),
      aad_hex: "",
      enc_hex: hex(basic.enc),
      ciphertext_hex: hex(basic.ct),
      note: "The proposed value of the rule's variable (a dummy connection string), sealed to the recipient device",
    },
    {
      name: "companion",
      domain: SEALED_DOMAIN,
      project_id: projectId,
      environment_id: environmentId,
      proposal_id: proposalId,
      variable_id: companionVariableId,
      base_version: companionBaseVersion,
      recipient_user_id: recipientUserId,
      info_hex: hex(companionInfo),
      plaintext_hex: hex(companionValue),
      ikmE_hex: hex(ikmE2),
      aad_hex: "",
      enc_hex: hex(companion.enc),
      ciphertext_hex: hex(companion.ct),
      note: "A companion variable of the same proposal (the AWS key id / an exec rule's companion): a separate Seal under its own variable_id with an independent ephemeral key. Pins that the proposal id is shared and the variable id separates the two",
    },
  ],
  negative: [
    {
      name: "info-project-mismatch",
      base: "basic",
      open_info_hex: hex(
        sealedInfo(
          "proj-0002",
          environmentId,
          proposalId,
          variableId,
          baseVersion,
          recipientUserId,
        ),
      ),
      must_fail: true,
      note: "Transplanting to another project fails Open",
    },
    {
      name: "info-environment-mismatch",
      base: "basic",
      open_info_hex: hex(
        sealedInfo(projectId, "env-dev-0002", proposalId, variableId, baseVersion, recipientUserId),
      ),
      must_fail: true,
      note: "Transplanting to another environment fails Open",
    },
    {
      name: "info-proposal-mismatch",
      base: "basic",
      open_info_hex: hex(
        sealedInfo(
          projectId,
          environmentId,
          otherProposalId,
          variableId,
          baseVersion,
          recipientUserId,
        ),
      ),
      must_fail: true,
      note: "Re-filing the sealed value under another proposal id fails Open (two proposals for the same variable cannot be confused)",
    },
    {
      name: "info-variable-mismatch",
      base: "basic",
      open_info_hex: hex(
        sealedInfo(
          projectId,
          environmentId,
          proposalId,
          companionVariableId,
          baseVersion,
          recipientUserId,
        ),
      ),
      must_fail: true,
      note: "Presenting the primary's sealed value as the companion's fails Open (a swapped wrap inside one proposal is detected)",
    },
    {
      name: "info-base-version-mismatch",
      base: "basic",
      open_info_hex: hex(
        sealedInfo(
          projectId,
          environmentId,
          proposalId,
          variableId,
          baseVersion + 1,
          recipientUserId,
        ),
      ),
      must_fail: true,
      note: "Re-labelling the version the value replaces fails Open (a stale proposal cannot be presented as one minted against the current version — the member's base-version check is under the seal, not only in server-declared metadata)",
    },
    {
      name: "info-recipient-mismatch",
      base: "basic",
      open_info_hex: hex(
        sealedInfo(
          projectId,
          environmentId,
          proposalId,
          variableId,
          baseVersion,
          "user-recipient-0003",
        ),
      ),
      must_fail: true,
      note: "A sealed value re-addressed to another user id fails Open (the recipient binding, as in §5)",
    },
    {
      name: "info-dek-wrap-domain",
      base: "basic",
      open_info_hex: hex(
        lpEncode([
          DEK_WRAP_DOMAIN,
          projectId,
          environmentId,
          proposalId,
          variableId,
          baseVersion,
          recipientUserId,
        ]),
      ),
      must_fail: true,
      note: "info with the domain string replaced by §5's dek-wrap fails Open (domain separation between DEK wraps and sealed values — a sealed value can never be presented as a wrap)",
    },
    {
      name: "ciphertext-tampered",
      base: "basic",
      ciphertext_hex: hex(tampered),
      must_fail: true,
      note: "One byte flipped inside the ciphertext fails Open (the AEAD tag covers the whole body — a server cannot alter a stored proposal unnoticed)",
    },
  ],
};

writeFileSync(
  new URL("../sealed-value.json", import.meta.url),
  `${JSON.stringify(vector, null, 2)}\n`,
);
console.log("wrote sealed-value.json");
