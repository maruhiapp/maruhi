import { readFileSync, writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

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

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

const dekWrapDoc = JSON.parse(readFileSync(new URL("../dek-wrap.json", import.meta.url), "utf8"));
const serverWrap = dekWrapDoc.vectors.find((v) => v.name === "server-basic");
if (serverWrap === undefined) {
  throw new Error("dek-wrap.json is missing the server-basic vector");
}
const projectId = serverWrap.project_id;
const environmentId = serverWrap.environment_id;
const epoch = serverWrap.epoch;
const dek = fromHex(serverWrap.dek_hex);

const priorEpoch = epoch - 1;
const priorDek = pat(0xe0, 32);

const ikmW = pat(0xd0, 32);
const kpW = await suite.kem.deriveKeyPair(ikmW.slice().buffer);
const pkWm = new Uint8Array(await suite.kem.serializePublicKey(kpW.publicKey));
const skWm = new Uint8Array(await suite.kem.serializePrivateKey(kpW.privateKey));

const CLAIMS_DOMAIN = "maruhi/v1/lease-claims";
const issuerUrl = "https://token.actions.githubusercontent.com";
const audience = "https://maruhi.example";
const subject = "repo:maruhi-example/demo:ref:refs/heads/main";
const otherSubject = "repo:maruhi-example/demo:ref:refs/heads/feature-x";

async function claimsDigest(sub) {
  const lp = lpEncode([CLAIMS_DOMAIN, issuerUrl, sub, audience]);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", lp.slice()));
  return { lpHex: hex(lp), digestHex: hex(digest) };
}

const claims = await claimsDigest(subject);
const otherClaims = await claimsDigest(otherSubject);

const LEASE_DOMAIN = "maruhi/v1/lease-wrap";
const DEK_WRAP_DOMAIN = "maruhi/v1/dek-wrap";
const leaseInfo = (proj, env, ep, digestHex) => lpEncode([LEASE_DOMAIN, proj, env, ep, digestHex]);

const info = leaseInfo(projectId, environmentId, epoch, claims.digestHex);
const priorInfo = leaseInfo(projectId, environmentId, priorEpoch, claims.digestHex);
const aad = new Uint8Array(0);

const ikmE = pat(0xf0, 32);
const ikmE2 = pat(0x40, 32);

async function seal(infoBytes, plaintext, ekm) {
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(pkWm.slice().buffer),
    info: infoBytes.slice().buffer,
    ekm: ekm.slice().buffer,
  });
  const ct = new Uint8Array(await sender.seal(plaintext.slice().buffer, aad.slice().buffer));
  return { enc: new Uint8Array(sender.enc), ct };
}

const { enc, ct } = await seal(info, dek, ikmE);
const { enc: priorEnc, ct: priorCt } = await seal(priorInfo, priorDek, ikmE2);

const vector = {
  description:
    "CRYPTO_SPEC §9.1: the lease wrap of a workload lease (HPKE Base mode single Seal, same primitives as §5). info binds the claims_digest so that reusing a lease response in another workload context fails decryption. Seal is pinned by hpke-js ekm derandomize (the panva implementation is verified in the Open direction + roundtrip)",
  info_fields_order: ["domain", "project_id", "environment_id", "epoch", "claims_digest_hex"],
  claims_digest_fields_order: ["domain", "issuer_url", "subject", "audience"],
  persistence_note:
    "A lease wrap is not persisted (never enters dek_wraps — §9.1). Because it exists only within the response scope, it carries no §5.1 registration signature (signers are on-chain members; a server-generated wrap cannot carry an attribution signature)",
  provenance_note:
    "The coordinates (project / environment / epoch) and the DEK of basic are identical to dek-wrap.json's server-basic. Expresses in real data the shape of the server Opening its own wrap and re-wrapping the same DEK to the workload ephemeral key (§9.1 — the server does not decrypt the value)",
  workload_keypair: {
    ikmW_hex: hex(ikmW),
    skWm_hex: hex(skWm),
    pkWm_hex: hex(pkWm),
    note: "The workload's ephemeral X25519 key. Fixed via DeriveKeyPair(ikmW) for vector determinism, but in production it is randomly generated each time and discarded when the job ends (§9.1)",
  },
  claims: {
    domain: CLAIMS_DOMAIN,
    issuer_url: issuerUrl,
    audience,
    subject,
    lp_hex: claims.lpHex,
    claims_digest_hex: claims.digestHex,
    other_subject: otherSubject,
    other_lp_hex: otherClaims.lpHex,
    other_claims_digest_hex: otherClaims.digestHex,
    note: "claims_digest_hex = lower_hex(SHA-256(LP(domain, issuer_url, subject, audience))). The server and the workload independently compute the same value from the verified OIDC token's issuer / sub / aud. other_* is a same-issuer / same-audience, different-subject (different-branch) context — material for info-claims-digest-mismatch",
  },
  vectors: [
    {
      name: "basic",
      domain: LEASE_DOMAIN,
      project_id: projectId,
      environment_id: environmentId,
      epoch,
      claims_digest_hex: claims.digestHex,
      info_hex: hex(info),
      dek_hex: hex(dek),
      ikmE_hex: hex(ikmE),
      aad_hex: "",
      enc_hex: hex(enc),
      ciphertext_hex: hex(ct),
      note: "The current-epoch lease wrap. The DEK is identical to dek-wrap.json's server-basic (the DEK the server Opened and re-wrapped)",
    },
    {
      name: "prior-epoch",
      domain: LEASE_DOMAIN,
      project_id: projectId,
      environment_id: environmentId,
      epoch: priorEpoch,
      claims_digest_hex: claims.digestHex,
      info_hex: hex(priorInfo),
      dek_hex: hex(priorDek),
      ikmE_hex: hex(ikmE2),
      aad_hex: "",
      enc_hex: hex(priorEnc),
      ciphertext_hex: hex(priorCt),
      note: "The past-epoch portion included in the same lease response (§14-2: all epochs the latest value uses + the current epoch). Pins that both the DEK and info are independent per epoch",
    },
  ],
  negative: [
    {
      name: "info-project-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo("proj-0002", environmentId, epoch, claims.digestHex)),
      must_fail: true,
      note: "Transplanting to another project fails Open",
    },
    {
      name: "info-environment-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo(projectId, "env-dev-0002", epoch, claims.digestHex)),
      must_fail: true,
      note: "Transplanting to another environment fails Open (blocks reuse across the disclosure scope)",
    },
    {
      name: "info-epoch-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo(projectId, environmentId, epoch + 1, claims.digestHex)),
      must_fail: true,
      note: "Transplanting to another epoch fails Open",
    },
    {
      name: "info-claims-digest-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo(projectId, environmentId, epoch, otherClaims.digestHex)),
      must_fail: true,
      note: "A claims_digest of a different workload context (same issuer / audience, different subject) fails Open. The core of the fact that a lease response cannot be diverted to another job (§9.1)",
    },
    {
      name: "info-dek-wrap-domain",
      base: "basic",
      open_info_hex: hex(
        lpEncode([DEK_WRAP_DOMAIN, projectId, environmentId, epoch, claims.digestHex]),
      ),
      must_fail: true,
      note: "info with the domain string replaced by §5's dek-wrap fails Open (domain separation between the persistent wrap and the lease wrap)",
    },
  ],
};

writeFileSync(
  new URL("../lease-wrap.json", import.meta.url),
  `${JSON.stringify(vector, null, 2)}\n`,
);
console.log("wrote lease-wrap.json");
