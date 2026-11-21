import { readFileSync } from "node:fs";

import * as HPKE from "hpke";

const read = (name) => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), "utf8"));
const chainHeadHash = (chain, chainName, seq) => {
  if (chainName === undefined || chainName === "canonical") {
    return chain.entries[seq - 1].entry_hash_hex;
  }
  const ext = chain.extended_chains[chainName];
  return seq <= ext.base_seq
    ? chain.entries[seq - 1].entry_hash_hex
    : ext.entries[seq - ext.base_seq - 1].entry_hash_hex;
};
const chainKeyFor = (chain, userId, fingerprintHex) =>
  Object.entries(chain.keys)
    .map(([id, k]) => ({ userId: k.user_id ?? id, ...k }))
    .find((k) => k.userId === userId && k.key_fingerprint_hex === fingerprintHex) ??
  chain.keys[userId];
const fromHex = (h) => Uint8Array.from(h.match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256Bytes = async (u8) => new Uint8Array(await crypto.subtle.digest("SHA-256", u8));

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

const PAYLOAD_FIELD_ORDER = {
  genesis: ["enc_pub_hex", "sig_pub_hex"],
  add_member: [
    "target_user_id",
    "enc_pub_hex",
    "sig_pub_hex",
    "role",
    "scope_kind",
    "scope_environments_lp_hex",
  ],
  remove_member: ["target_user_id"],
  change_role: ["target_user_id", "new_role", "scope_kind", "scope_environments_lp_hex"],
  create_environment: ["environment_id", "dek_commitment_hex"],
  rotate_epoch: ["environment_id", "new_epoch", "reason", "dek_commitment_hex"],
  grant_server: [
    "server_enc_pub_hex",
    "server_key_fingerprint_hex",
    "scope_environments_lp_hex",
    "lease_policy_lp_hex",
  ],
  revoke_server: ["server_key_fingerprint_hex"],
  checkpoint: ["environments_lp_hex", "audit_head_hash_hex"],
  set_approval_policy: ["ops_lp_hex", "required_approvals"],
  propose: ["inner_op", "inner_payload_lp_hex", "expires_at_ms"],
  approve: ["proposal_hash_hex"],
  withdraw: ["proposal_hash_hex"],
  add_device: ["enc_pub_hex", "sig_pub_hex", "role_cap", "scope_kind", "scope_environments_lp_hex"],
  revoke_device: ["target_user_id", "device_fingerprints_lp_hex"],
  delete_environment: ["environment_id"],
};

const stringListLp = (items) => lpEncode(items);
const innerPayloadLp = (innerOp, innerPayload) =>
  lpEncode(PAYLOAD_FIELD_ORDER[innerOp].map((k) => innerPayload[k]));

function checkpointEnvironmentsLp(environments) {
  return lpEncode(
    environments.map((e) =>
      lpEncode([
        e.environment_id,
        e.epoch,
        e.manifest_version,
        e.manifest_sig_hash_hex,
        e.values_digest_hex,
      ]),
    ),
  );
}

function envValuesDigestInput(entries) {
  const enc = new TextEncoder();
  const ordered = entries.toSorted((a, b) => {
    const ba = enc.encode(a.variable_id);
    const bb = enc.encode(b.variable_id);
    for (let i = 0; i < Math.min(ba.length, bb.length); i += 1) {
      if (ba[i] !== bb[i]) {
        return ba[i] - bb[i];
      }
    }
    return ba.length - bb.length;
  });
  return lpEncode([
    "maruhi/v1/env-values-digest",
    ...ordered.map((v) => lpEncode([v.variable_id, v.version, v.value_sig_hash_hex])),
  ]);
}

function leasePolicyLp(policy) {
  return lpEncode(
    policy.map((element) =>
      lpEncode([
        element.issuer_url,
        element.audience,
        lpEncode(element.claim_constraints.map((c) => lpEncode([c.claim_name, c.claim_value]))),
      ]),
    ),
  );
}
const VAR_SIGNED_FIELDS_ORDER = [
  "domain",
  "project_id",
  "environment_id",
  "variable_id",
  "name",
  "status",
  "meta_version",
  "prev_meta_sig_hash_hex",
  "author_user_id",
  "chain_head_hash_hex",
  "chain_head_seq",
];
const ENV_SIGNED_FIELDS_ORDER = VAR_SIGNED_FIELDS_ORDER.filter((f) => f !== "variable_id");
const RETIRED_VAR_V2_SIGNED_FIELDS_ORDER = [
  "domain",
  "project_id",
  "environment_id",
  "variable_id",
  "name",
  "status",
  "var_type",
  "required",
  "description",
  "meta_version",
  "prev_meta_sig_hash_hex",
  "author_user_id",
  "chain_head_hash_hex",
  "chain_head_seq",
];
const VAR_V3_SIGNED_FIELDS_ORDER = [
  "domain",
  "project_id",
  "environment_id",
  "variable_id",
  "name",
  "status",
  "var_type",
  "required",
  "description",
  "max_age_days",
  "meta_version",
  "prev_meta_sig_hash_hex",
  "author_user_id",
  "chain_head_hash_hex",
  "chain_head_seq",
];
const sameOrder = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const expectedMetaDomain = (ctx) => {
  const layout = ctx.layout_version ?? 1;
  if (layout === 3) {
    return `${ctx.suite}/var-meta-sig-v3`;
  }
  return `${ctx.suite}/${ctx.kind === "variable" ? "var" : "env"}-meta-sig`;
};

{
  const doc = read("encoding.json");
  for (const c of doc.cases) {
    check(`encoding: ${c.name}`, toHex(lpEncode(c.fields)) === c.expected_hex);
  }
}

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

{
  const doc = read("chain-entries.json");
  const declared = doc.canonicalization.payload_field_order;
  check(
    "chain: payload_field_order matches spec",
    sameOrder(Object.keys(declared).toSorted(), Object.keys(PAYLOAD_FIELD_ORDER).toSorted()) &&
      Object.entries(PAYLOAD_FIELD_ORDER).every(([op, fields]) => sameOrder(declared[op], fields)),
  );
  const order = PAYLOAD_FIELD_ORDER;
  let prevHash = "0".repeat(64);
  const sha256 = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  const keyRecords = (extKeys) =>
    [...Object.entries(doc.keys), ...Object.entries(extKeys ?? {})].map(([id, k]) => ({
      userId: k.user_id ?? id,
      ...k,
    }));
  const signerKeyFor = (e, extKeys) =>
    keyRecords(extKeys).find(
      (k) => k.userId === e.actor.user_id && k.key_fingerprint_hex === e.actor.key_fingerprint_hex,
    ) ?? doc.keys[e.actor.user_id];
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
    const sigPubHex = signerKeyFor(e, undefined).sig_pub_hex;
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
  for (const [uid, k] of Object.entries(doc.keys)) {
    const cat = new Uint8Array([...fromHex(k.enc_pub_hex), ...fromHex(k.sig_pub_hex)]);
    const fp = (await sha256(cat)).slice(0, 32);
    check(`chain: fingerprint ${uid}`, fp === k.key_fingerprint_hex);
  }
  for (const [chainName, ext] of Object.entries(doc.extended_chains ?? {})) {
    for (const [uid, k] of Object.entries(ext.keys ?? {})) {
      const cat = new Uint8Array([...fromHex(k.enc_pub_hex), ...fromHex(k.sig_pub_hex)]);
      const fp = (await sha256(cat)).slice(0, 32);
      check(`chain extended ${chainName}: fingerprint ${uid}`, fp === k.key_fingerprint_hex);
    }
  }
  {
    const fp = (await sha256(fromHex(doc.server_key.enc_pub_hex))).slice(0, 32);
    check("chain: server key fingerprint", fp === doc.server_key.key_fingerprint_hex);
  }
  {
    const e7 = doc.entries.find((e) => e.op === "grant_server");
    check(
      "chain: grant_server scope nested LP",
      toHex(lpEncode(e7.payload.scope_environments)) === e7.payload.scope_environments_lp_hex,
    );
    check(
      "chain: grant_server lease_policy nested LP",
      toHex(leasePolicyLp(e7.payload.lease_policy)) === e7.payload.lease_policy_lp_hex,
    );
    check("chain: empty lease_policy encodes to empty hex", toHex(leasePolicyLp([])) === "");
  }
  {
    const allEntries = [
      ...doc.entries,
      ...Object.values(doc.extended_chains ?? {}).flatMap((ext) => ext.entries),
      ...doc.valid_appends.map((a) => a.entry),
      ...doc.negative.map((n) => n.entry).filter((e) => e !== undefined),
    ];
    const negativeEntries = new Set(
      doc.negative.map((n) => n.entry).filter((e) => e !== undefined),
    );
    let scoped = 0;
    let policies = 0;
    let proposals = 0;
    for (const e of allEntries) {
      const label = `chain ${e.op} seq ${e.seq} (${e.actor.user_id})`;
      if (e.op === "add_member" || e.op === "change_role") {
        scoped += 1;
        const p = e.payload;
        check(
          `${label}: scope nested LP`,
          toHex(stringListLp(p.scope_environments)) === p.scope_environments_lp_hex &&
            (negativeEntries.has(e) || p.scope_kind === "all" || p.scope_kind === "listed"),
        );
      } else if (e.op === "add_device") {
        scoped += 1;
        const p = e.payload;
        check(
          `${label}: device scope nested LP`,
          toHex(stringListLp(p.scope_environments)) === p.scope_environments_lp_hex &&
            (negativeEntries.has(e) ||
              (["reader", "member", "admin", "owner"].includes(p.role_cap) &&
                (p.scope_kind === "all" || p.scope_kind === "listed"))),
        );
      } else if (e.op === "revoke_device") {
        const p = e.payload;
        check(
          `${label}: device fingerprints nested LP`,
          toHex(stringListLp(p.device_fingerprints)) === p.device_fingerprints_lp_hex &&
            (negativeEntries.has(e) ||
              (p.device_fingerprints.length >= 1 &&
                new Set(p.device_fingerprints).size === p.device_fingerprints.length &&
                p.device_fingerprints.every((fp) => /^[0-9a-f]{32}$/.test(fp)))),
        );
      } else if (e.op === "set_approval_policy") {
        policies += 1;
        check(
          `${label}: ops nested LP`,
          toHex(stringListLp(e.payload.ops)) === e.payload.ops_lp_hex,
        );
      } else if (e.op === "propose") {
        proposals += 1;
        const p = e.payload;
        const decodable =
          Object.hasOwn(PAYLOAD_FIELD_ORDER, p.inner_op) &&
          PAYLOAD_FIELD_ORDER[p.inner_op].every((k) => Object.hasOwn(p.inner_payload, k));
        check(
          `${label}: inner payload nested LP`,
          decodable
            ? toHex(innerPayloadLp(p.inner_op, p.inner_payload)) === p.inner_payload_lp_hex
            : p.inner_payload_lp_hex === "",
        );
      }
    }
    check("chain: scoped member vectors exist", scoped > 0 && policies > 0 && proposals > 0);
    check(
      "chain: canonical all-scope entries carry the empty list",
      doc.entries
        .filter((e) => e.op === "add_member" || e.op === "change_role")
        .every((e) => e.payload.scope_kind !== "all" || e.payload.scope_environments_lp_hex === ""),
    );
    const propose21 = doc.entries[20];
    check(
      "chain: approve 22 references propose 21 / withdraw 24 references propose 23",
      doc.entries[21].op === "approve" &&
        doc.entries[21].payload.proposal_hash_hex === propose21.entry_hash_hex &&
        doc.entries[23].op === "withdraw" &&
        doc.entries[23].payload.proposal_hash_hex === doc.entries[22].entry_hash_hex,
    );
  }
  {
    const full = doc.extended_chains["device-ops"];
    check("chain: device-ops derived chain exists", full !== undefined && full.base_seq === 24);
    for (const name of [
      "device-added",
      "device-dead-vote",
      "device-revote-applied",
      "device-recovered",
    ]) {
      const prefix = doc.extended_chains[name];
      check(
        `chain: ${name} is a byte-identical prefix of device-ops`,
        prefix !== undefined &&
          prefix.entries.every((e, i) => JSON.stringify(e) === JSON.stringify(full.entries[i])),
      );
    }
    const deviceKeys = keyRecords(undefined).filter((k) => k.label !== undefined);
    for (const e of full.entries.filter((x) => x.op === "add_device")) {
      const registered = deviceKeys.find(
        (k) => k.enc_pub_hex === e.payload.enc_pub_hex && k.sig_pub_hex === e.payload.sig_pub_hex,
      );
      check(
        `chain device-ops seq ${e.seq}: add_device key is a registered device key of the actor`,
        registered !== undefined && registered.userId === e.actor.user_id,
      );
    }
    const canonicalFps = new Set(Object.values(doc.keys).map((k) => k.key_fingerprint_hex));
    for (const e of full.entries.filter((x) => x.op === "revoke_device")) {
      check(
        `chain device-ops seq ${e.seq}: revoked fingerprints are known device keys`,
        e.payload.device_fingerprints.every((fp) => canonicalFps.has(fp)),
      );
    }
  }
  {
    const positives = [
      ...Object.entries(doc.extended_chains ?? {}).map(([name, ext]) => ({
        name,
        chain: [...doc.entries.slice(0, ext.base_seq), ...ext.entries],
      })),
      ...doc.valid_appends.map((a) => ({
        name: a.name,
        chain: [
          ...(a.chain === undefined
            ? doc.entries.slice(0, a.entry.seq - 1)
            : [
                ...doc.entries.slice(0, doc.extended_chains[a.chain].base_seq),
                ...doc.extended_chains[a.chain].entries,
              ]),
          a.entry,
        ],
      })),
    ];
    let deletions = 0;
    for (const { name, chain } of positives) {
      const created = new Set();
      const deleted = new Set();
      for (const e of chain) {
        if (e.op === "create_environment") created.add(e.payload.environment_id);
        if (e.op !== "delete_environment") continue;
        deletions += 1;
        const id = e.payload.environment_id;
        check(
          `chain ${name} seq ${e.seq}: delete_environment follows its create and is the only one`,
          typeof id === "string" && id.length > 0 && created.has(id) && !deleted.has(id),
        );
        deleted.add(id);
      }
    }
    check("chain: delete_environment positives exist", deletions > 0);
  }
  {
    const checkpointEntries = [
      ...Object.values(doc.extended_chains ?? {}).flatMap((ext) => ext.entries),
      ...doc.valid_appends.map((a) => a.entry),
      ...doc.negative.map((n) => n.entry).filter((e) => e !== undefined),
    ].filter((e) => e.op === "checkpoint");
    check("chain: checkpoint vectors exist", checkpointEntries.length > 0);
    for (const e of checkpointEntries) {
      check(
        `chain checkpoint seq ${e.seq} (${e.actor.user_id}): environments nested LP`,
        toHex(checkpointEnvironmentsLp(e.payload.environments)) === e.payload.environments_lp_hex,
      );
    }
    check(
      "chain: empty checkpoint environments encode to empty hex",
      toHex(checkpointEnvironmentsLp([])) === "",
    );
  }
  for (const digestCase of doc.values_digests ?? []) {
    check(
      `chain values-digest ${digestCase.name}`,
      (await sha256(envValuesDigestInput(digestCase.entries))) === digestCase.values_digest_hex,
    );
  }
  {
    const projectId = doc.entries[0].entry_hash_hex;
    for (const [environmentId, perEnv] of Object.entries(doc.environment_deks)) {
      for (const [epoch, info] of Object.entries(perEnv)) {
        const computed = await sha256(
          lpEncode(["maruhi/v1/dek-commit", projectId, environmentId, epoch, info.dek_hex]),
        );
        check(
          `chain: dek commitment ${environmentId}#${epoch}`,
          computed === info.dek_commitment_hex,
        );
      }
    }
    for (const e of doc.entries) {
      if (e.op === "create_environment") {
        check(
          `chain seq ${e.seq}: create_environment carries epoch-1 commitment`,
          e.payload.dek_commitment_hex ===
            doc.environment_deks[e.payload.environment_id]["1"].dek_commitment_hex,
        );
      } else if (e.op === "rotate_epoch") {
        check(
          `chain seq ${e.seq}: rotate_epoch carries new-epoch commitment`,
          e.payload.dek_commitment_hex ===
            doc.environment_deks[e.payload.environment_id][e.payload.new_epoch].dek_commitment_hex,
        );
      }
    }
  }
  for (const a of doc.valid_appends) {
    const e = a.entry;
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
      await importSigPub(signerKeyFor(e, undefined).sig_pub_hex),
      fromHex(e.signature_hex),
      signed,
    );
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
    const expectedPrev =
      a.chain === undefined
        ? doc.entries[e.seq - 2].entry_hash_hex
        : doc.extended_chains[a.chain].entries.at(-1).entry_hash_hex;
    check(
      `chain valid append: ${a.name} (signature must be VALID)`,
      sigOk &&
        toHex(payloadBytes) === e.payload_bytes_hex &&
        toHex(signed) === e.signed_bytes_hex &&
        e.prev_hash_hex === expectedPrev &&
        toHex(entryBytes) === e.entry_bytes_hex &&
        (await sha256(entryBytes)) === e.entry_hash_hex,
    );
  }
  for (const [chainName, ext] of Object.entries(doc.extended_chains ?? {})) {
    let prev = doc.entries[ext.base_seq - 1].entry_hash_hex;
    let seq = ext.base_seq;
    for (const e of ext.entries) {
      seq += 1;
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
      const signerKey = signerKeyFor(e, ext.keys);
      const sigOk = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(signerKey.sig_pub_hex),
        fromHex(e.signature_hex),
        signed,
      );
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
      const referenced =
        e.op === "approve" || e.op === "withdraw"
          ? [...doc.entries.slice(0, ext.base_seq), ...ext.entries].find(
              (x) => x.op === "propose" && x.entry_hash_hex === e.payload.proposal_hash_hex,
            )
          : true;
      check(
        `chain extended ${chainName} seq ${e.seq} (signature must be VALID)`,
        referenced !== undefined &&
          sigOk &&
          e.seq === seq &&
          e.prev_hash_hex === prev &&
          toHex(payloadBytes) === e.payload_bytes_hex &&
          toHex(signed) === e.signed_bytes_hex &&
          toHex(entryBytes) === e.entry_bytes_hex &&
          (await sha256(entryBytes)) === e.entry_hash_hex,
      );
      prev = e.entry_hash_hex;
    }
  }
  for (const n of doc.negative) {
    if (n.name === "prev-hash-mismatch") {
      check(`chain negative: ${n.name}`, n.claimed_prev_hash_hex !== n.expected_prev_hash_hex);
      continue;
    }
    if (n.kind === "authorization") {
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
      const expectedPrev =
        n.chain === undefined ? null : doc.extended_chains[n.chain].entries.at(-1).entry_hash_hex;
      check(
        `chain authz negative: ${n.name} (signature must be VALID)`,
        sigOk &&
          toHex(signed) === e.signed_bytes_hex &&
          (expectedPrev === null || e.prev_hash_hex === expectedPrev),
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

{
  const doc = read("dek-wrap-signature.json");
  const dekWrap = read("dek-wrap.json");
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  const signedBytes = (ctx) =>
    lpEncode([
      ctx.domain,
      ctx.project_id,
      ctx.environment_id,
      ctx.epoch,
      ctx.recipient_user_id,
      ctx.recipient_enc_pub_hex,
      ctx.enc_hex,
      ctx.ciphertext_hex,
      ctx.signer_user_id,
    ]);
  const base = doc.vectors[0];
  check(
    "dek-wrap-sig: wrap body matches dek-wrap.json",
    base.enc_hex === dekWrap.vectors[0].enc_hex &&
      base.ciphertext_hex === dekWrap.vectors[0].ciphertext_hex &&
      base.recipient_enc_pub_hex === dekWrap.recipient_keypair.pkRm_hex,
  );
  const serverVector = doc.vectors.find((v) => v.name === "server-basic");
  const serverWrap = dekWrap.vectors.find((v) => v.name === "server-basic");
  check(
    "dek-wrap-sig: server wrap body matches dek-wrap.json",
    serverVector.enc_hex === serverWrap.enc_hex &&
      serverVector.ciphertext_hex === serverWrap.ciphertext_hex &&
      serverVector.recipient_enc_pub_hex === dekWrap.server_keypair.pkSm_hex &&
      serverVector.recipient_user_id === dekWrap.server_keypair.server_key_fingerprint_hex,
  );
  for (const v of doc.vectors) {
    const bytes = signedBytes(v);
    check(
      `dek-wrap-sig: ${v.name} signed bytes reconstruction`,
      toHex(bytes) === v.signed_bytes_hex,
    );
    check(`dek-wrap-sig: ${v.name} domain embeds suite`, v.domain === `${v.suite}/dek-wrap-sig`);
    check(`dek-wrap-sig: ${v.name} signer identity bound`, v.signer_user_id === doc.signer.user_id);
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(doc.signer.sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`dek-wrap-sig: ${v.name} Ed25519 signature`, ok);
  }
  for (const n of doc.negative) {
    const reconstructed = signedBytes(n.context);
    const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
    const verified = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      reconstructed,
    );
    check(`dek-wrap-sig negative: ${n.name}`, bytesMatch && verified === false);
  }
}

{
  const doc = read("invite-accept-signature.json");
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  const signedBytes = (ctx) =>
    lpEncode([
      ctx.domain,
      ctx.project_id,
      ctx.link_pub_hex,
      ctx.invitee_user_id,
      ctx.invitee_enc_pub_hex,
      ctx.invitee_sig_pub_hex,
    ]);
  const base = doc.vectors[0];
  check(
    "invite-accept-sig: invitee keys bound",
    base.invitee_enc_pub_hex === doc.invitee.enc_pub_hex &&
      base.invitee_sig_pub_hex === doc.invitee.sig_pub_hex &&
      base.invitee_user_id === doc.invitee.user_id,
  );
  const pkcs8Prefix = fromHex("302e020100300506032b657004220420");
  const derivePub = async (seedHex) => {
    const der = new Uint8Array(48);
    der.set(pkcs8Prefix, 0);
    der.set(fromHex(seedHex), 16);
    const key = await crypto.subtle.importKey("pkcs8", der, "Ed25519", true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const b64 = jwk.x.replaceAll("-", "+").replaceAll("_", "/");
    return toHex(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  };
  check(
    "invite-accept-sig: link key derived from seed",
    (await derivePub(doc.link_key.seed_hex)) === doc.link_key.pub_hex &&
      base.link_pub_hex === doc.link_key.pub_hex,
  );
  check(
    "invite-accept-sig: other link key derived from seed",
    (await derivePub(doc.other_link_key.seed_hex)) === doc.other_link_key.pub_hex,
  );
  for (const v of doc.vectors) {
    const bytes = signedBytes(v);
    check(
      `invite-accept-sig: ${v.name} signed bytes reconstruction`,
      toHex(bytes) === v.signed_bytes_hex,
    );
    check(
      `invite-accept-sig: ${v.name} domain embeds suite (v2)`,
      v.domain === `${v.suite}/invite-accept-v2`,
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(v.invitee_sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`invite-accept-sig: ${v.name} Ed25519 accept signature`, ok);
    const linkOk = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(v.link_pub_hex),
      fromHex(v.link_signature_hex),
      bytes,
    );
    check(`invite-accept-sig: ${v.name} Ed25519 link signature`, linkOk);
  }
  const runNegatives = async (list, keyField, label) => {
    for (const n of list) {
      const reconstructed = signedBytes(n.context);
      const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
      const selfBound = n.verify_key_hex === n.context[keyField];
      const verified = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(n.verify_key_hex),
        fromHex(n.signature_hex),
        reconstructed,
      );
      if (n.name === "legacy-domain") {
        const v2Bytes = signedBytes({
          ...n.context,
          domain: `${n.context.suite}/invite-accept-v2`,
        });
        const v2Verified = await crypto.subtle.verify(
          "Ed25519",
          await importSigPub(n.verify_key_hex),
          fromHex(n.signature_hex),
          v2Bytes,
        );
        check(
          `${label} negative: ${n.name}`,
          bytesMatch && selfBound && verified === true && v2Verified === false,
        );
        continue;
      }
      check(`${label} negative: ${n.name}`, bytesMatch && selfBound && verified === false);
    }
  };
  await runNegatives(doc.negative, "invitee_sig_pub_hex", "invite-accept-sig");
  await runNegatives(doc.link_negative, "link_pub_hex", "invite-link-sig");
}

{
  const doc = read("invite-link.json");
  const chain = read("chain-entries.json");
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  const signedBytes = (ctx) =>
    lpEncode([
      ctx.domain,
      ctx.invite_id,
      ctx.project_id,
      ctx.link_pub_hex,
      ctx.head_hash_hex,
      ctx.head_seq,
      ctx.role,
      ctx.inviter_user_id,
      ctx.inviter_enc_pub_hex,
      ctx.inviter_sig_pub_hex,
      ctx.scope_kind,
      ctx.scope_environments_lp_hex,
    ]);
  const base = doc.issue.vectors[0];
  const head = chain.entries[chain.entries.length - 1];
  for (const v of doc.issue.vectors) {
    check(
      `invite-issue-sig: ${v.name} scope nested LP`,
      toHex(lpEncode(v.scope_environments)) === v.scope_environments_lp_hex &&
        (v.scope_kind !== "all" || v.scope_environments_lp_hex === ""),
    );
  }
  check(
    "invite-issue-sig: inviter is the chain owner and head is the canonical head",
    base.inviter_sig_pub_hex === chain.keys["user-owner-0001"].sig_pub_hex &&
      base.inviter_enc_pub_hex === chain.keys["user-owner-0001"].enc_pub_hex &&
      base.head_hash_hex === head.entry_hash_hex &&
      base.head_seq === head.seq &&
      base.link_pub_hex === doc.link_key.pub_hex,
  );
  const accept = read("invite-accept-signature.json");
  check(
    "invite-issue-sig: link key shared with invite-accept-signature.json",
    doc.link_key.seed_hex === accept.link_key.seed_hex &&
      doc.link_key.pub_hex === accept.link_key.pub_hex,
  );
  for (const v of doc.issue.vectors) {
    const bytes = signedBytes(v);
    check(
      `invite-issue-sig: ${v.name} signed bytes reconstruction`,
      toHex(bytes) === v.signed_bytes_hex,
    );
    check(
      `invite-issue-sig: ${v.name} domain embeds suite`,
      v.domain === `${v.suite}/invite-issue`,
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(v.inviter_sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`invite-issue-sig: ${v.name} Ed25519 signature`, ok);
  }
  for (const n of doc.issue.negative) {
    const selfBound = n.verify_key_hex === n.context.inviter_sig_pub_hex;
    if (n.kind === "encoding") {
      const differs = toHex(signedBytes(n.context)) !== n.verify_signed_bytes_hex;
      const verified = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(n.verify_key_hex),
        fromHex(n.signature_hex),
        fromHex(n.verify_signed_bytes_hex),
      );
      check(`invite-issue-sig negative: ${n.name}`, differs && selfBound && verified === false);
      continue;
    }
    const reconstructed = signedBytes(n.context);
    const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
    const verified = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      reconstructed,
    );
    check(`invite-issue-sig negative: ${n.name}`, bytesMatch && selfBound && verified === false);
  }
  const encodeLine = (pubHex) => {
    const blob = lpEncode([new TextEncoder().encode("ssh-ed25519"), fromHex(pubHex)]);
    return `ssh-ed25519 ${btoa(String.fromCharCode(...blob))}`;
  };
  const parseLine = (line) => {
    const parts = line.trimEnd().split(" ");
    if (parts.length < 2 || parts[0] !== "ssh-ed25519") return null;
    let blob;
    try {
      blob = Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0));
    } catch {
      return null;
    }
    const view = new DataView(blob.buffer);
    if (blob.length < 4) return null;
    const typeLen = view.getUint32(0, false);
    const type = new TextDecoder().decode(blob.slice(4, 4 + typeLen));
    if (type !== "ssh-ed25519" || blob.length < 8 + typeLen) return null;
    const keyLen = view.getUint32(4 + typeLen, false);
    if (keyLen !== 32 || blob.length !== 8 + typeLen + keyLen) return null;
    return toHex(blob.slice(8 + typeLen));
  };
  for (const e of doc.openssh.encode) {
    check(`openssh: encode ${e.name}`, encodeLine(e.public_key_hex) === e.expected_line);
  }
  for (const c of doc.openssh.parse) {
    check(`openssh: parse ${c.name}`, parseLine(c.line) === c.expected_public_key_hex);
  }
  for (const n of doc.openssh.parse_negative) {
    check(`openssh: parse negative ${n.name}`, parseLine(n.line) === null);
  }
}

{
  const doc = read("dek-commitment.json");
  const dekWrap = read("dek-wrap.json");
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const preimage = (ctx) =>
    lpEncode([ctx.domain, ctx.project_id, ctx.environment_id, ctx.epoch, ctx.dek_hex]);
  for (const v of doc.vectors) {
    const bytes = preimage(v);
    check(`dek-commitment: ${v.name} preimage`, toHex(bytes) === v.preimage_hex);
    check(`dek-commitment: ${v.name} commitment`, (await sha256hex(bytes)) === v.commitment_hex);
    check(`dek-commitment: ${v.name} domain embeds suite`, v.domain === `${v.suite}/dek-commit`);
  }
  const basic = doc.vectors[0];
  const wrapBase = dekWrap.vectors[0];
  check(
    "dek-commitment: coordinates match dek-wrap.json",
    basic.dek_hex === wrapBase.dek_hex &&
      basic.project_id === wrapBase.project_id &&
      basic.environment_id === wrapBase.environment_id &&
      basic.epoch === wrapBase.epoch,
  );
  check(
    "dek-commitment: rewrap invariance references basic",
    doc.rewrap_invariance.dek_hex === basic.dek_hex &&
      doc.rewrap_invariance.commitment_hex === basic.commitment_hex,
  );
  for (const n of doc.negative) {
    const computed = await sha256hex(preimage(n.context));
    check(
      `dek-commitment negative: ${n.name}`,
      computed === n.computed_commitment_hex &&
        computed !== n.expected_commitment_hex &&
        n.expected_commitment_hex === basic.commitment_hex,
    );
  }
}

{
  const doc = read("value-signature.json");
  const chain = read("chain-entries.json");
  const projectId = chain.entries[0].entry_hash_hex;
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  const signedBytes = (ctx) =>
    lpEncode([
      ctx.domain,
      ctx.project_id,
      ctx.environment_id,
      ctx.epoch,
      ctx.variable_id,
      ctx.version,
      ctx.nonce_hex,
      ctx.ciphertext_hex,
      ctx.prev_value_sig_hash_hex,
      ctx.writer_user_id,
      ctx.chain_head_hash_hex,
      ctx.chain_head_seq,
    ]);
  const byName = new Map(doc.vectors.map((v) => [v.name, v]));

  for (const v of doc.vectors) {
    const ctx = v.context;
    const bytes = signedBytes(ctx);
    check(`value-sig ${v.name}: signed bytes`, toHex(bytes) === v.signed_bytes_hex);
    check(
      `value-sig ${v.name}: signed bytes sha256`,
      (await sha256hex(bytes)) === v.signed_bytes_sha256_hex,
    );
    check(`value-sig ${v.name}: domain embeds suite`, ctx.domain === `${ctx.suite}/value-sig`);
    check(`value-sig ${v.name}: project id is genesis hash`, ctx.project_id === projectId);
    check(
      `value-sig ${v.name}: head hash matches chain`,
      ctx.chain_head_hash_hex === chainHeadHash(chain, v.chain, ctx.chain_head_seq),
    );
    const writerKeys = chainKeyFor(chain, ctx.writer_user_id, v.writer_key_fingerprint_hex);
    check(
      `value-sig ${v.name}: writer fingerprint matches chain keys`,
      writerKeys.key_fingerprint_hex === v.writer_key_fingerprint_hex,
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(writerKeys.sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`value-sig ${v.name}: Ed25519 signature`, ok);
    if (v.prev_base !== undefined) {
      check(
        `value-sig ${v.name}: prev links to ${v.prev_base}`,
        ctx.prev_value_sig_hash_hex === byName.get(v.prev_base)?.signed_bytes_sha256_hex,
      );
    } else {
      check(`value-sig ${v.name}: version 1 has empty prev`, ctx.prev_value_sig_hash_hex === "");
    }
    const aad = lpEncode([
      ctx.suite,
      ctx.project_id,
      ctx.environment_id,
      ctx.epoch,
      ctx.variable_id,
      ctx.version,
    ]);
    check(`value-sig ${v.name}: aad reconstruction`, toHex(aad) === v.aad_hex);
    const dekHex =
      chain.environment_deks[v.dek_ref.environment_id][String(v.dek_ref.epoch)].dek_hex;
    const pt = await aesGcmDecrypt(dekHex, ctx.nonce_hex, v.aad_hex, ctx.ciphertext_hex);
    check(
      `value-sig ${v.name}: ciphertext decrypts`,
      new TextDecoder().decode(pt) === v.plaintext_utf8,
    );
  }

  {
    const [a, b] = doc.fork_same_version.branches;
    for (const branch of [a, b]) {
      const bytes = signedBytes(branch.context);
      const ok = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(chain.keys[branch.context.writer_user_id].sig_pub_hex),
        fromHex(branch.signature_hex),
        bytes,
      );
      check(`value-sig fork ${branch.name}: signature must be VALID`, ok);
      check(
        `value-sig fork ${branch.name}: signed bytes`,
        toHex(bytes) === branch.signed_bytes_hex,
      );
    }
    const sameCoordinate =
      a.context.variable_id === b.context.variable_id &&
      a.context.version === b.context.version &&
      a.context.environment_id === b.context.environment_id &&
      a.context.epoch === b.context.epoch &&
      a.context.prev_value_sig_hash_hex === b.context.prev_value_sig_hash_hex;
    check(
      "value-sig fork: same coordinate, distinct signed bytes (equivocation evidence)",
      sameCoordinate && a.signed_bytes_sha256_hex !== b.signed_bytes_sha256_hex,
    );
  }

  {
    const e = doc.tenure_extension.entry;
    const payloadBytes = lpEncode(PAYLOAD_FIELD_ORDER[e.op].map((k) => e.payload[k]));
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
      await importSigPub(chain.keys[e.actor.user_id].sig_pub_hex),
      fromHex(e.signature_hex),
      signed,
    );
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
    check(
      "value-sig tenure-extension: entry is a valid append",
      sigOk &&
        toHex(payloadBytes) === e.payload_bytes_hex &&
        toHex(signed) === e.signed_bytes_hex &&
        e.prev_hash_hex === chain.entries.at(-1).entry_hash_hex &&
        toHex(entryBytes) === e.entry_bytes_hex &&
        (await sha256hex(entryBytes)) === e.entry_hash_hex,
    );
    check(
      "value-sig tenure-extension: rejoined member key differs from tenure 1",
      e.payload.sig_pub_hex !== chain.keys["user-member-0002"].sig_pub_hex &&
        e.payload.sig_pub_hex === doc.tenure_extension.rejoined_member.sig_pub_hex,
    );
  }

  for (const n of doc.negative) {
    if (n.kind === "authorization") {
      const bytes = signedBytes(n.context);
      const ok = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(n.verify_key_hex),
        fromHex(n.signature_hex),
        bytes,
      );
      check(
        `value-sig rule negative: ${n.name} (signature must be VALID)`,
        ok && toHex(bytes) === n.signed_bytes_hex,
      );
      continue;
    }
    const reconstructed = signedBytes(n.context);
    const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
    const verified = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      reconstructed,
    );
    check(`value-sig negative: ${n.name}`, bytesMatch && verified === false);
  }
}

{
  const doc = read("metadata-signature.json");
  const chain = read("chain-entries.json");
  const projectId = chain.entries[0].entry_hash_hex;
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  check(
    "meta-sig: var_signed_fields_order matches spec",
    sameOrder(doc.var_signed_fields_order, VAR_SIGNED_FIELDS_ORDER),
  );
  check(
    "meta-sig: env_signed_fields_order matches spec",
    sameOrder(doc.env_signed_fields_order, ENV_SIGNED_FIELDS_ORDER),
  );
  check(
    "meta-sig: var_v3_signed_fields_order matches spec",
    sameOrder(doc.var_v3_signed_fields_order, VAR_V3_SIGNED_FIELDS_ORDER),
  );
  check(
    "meta-sig: retired_var_v2_signed_fields_order matches the retired layout",
    sameOrder(doc.retired_var_v2_signed_fields_order, RETIRED_VAR_V2_SIGNED_FIELDS_ORDER),
  );
  const orderOf = (ctx) => {
    const layout = ctx.layout_version ?? 1;
    if (layout === 3) {
      return VAR_V3_SIGNED_FIELDS_ORDER;
    }
    if (layout === 2) {
      return RETIRED_VAR_V2_SIGNED_FIELDS_ORDER;
    }
    return ctx.kind === "variable" ? VAR_SIGNED_FIELDS_ORDER : ENV_SIGNED_FIELDS_ORDER;
  };
  const signedBytes = (ctx) =>
    lpEncode(orderOf(ctx).map((key) => (key === "max_age_days" ? (ctx[key] ?? "") : ctx[key])));
  const byName = new Map(doc.vectors.map((v) => [v.name, v]));

  const verifyStatement = async (v, label) => {
    const ctx = v.context;
    const bytes = signedBytes(ctx);
    check(`meta-sig ${label}: signed bytes`, toHex(bytes) === v.signed_bytes_hex);
    check(
      `meta-sig ${label}: signed bytes sha256`,
      (await sha256hex(bytes)) === v.signed_bytes_sha256_hex,
    );
    check(
      `meta-sig ${label}: domain embeds suite and layout/kind`,
      ctx.domain === expectedMetaDomain(ctx),
    );
    check(`meta-sig ${label}: project id is genesis hash`, ctx.project_id === projectId);
    check(`meta-sig ${label}: name is NFC-normal`, ctx.name.normalize("NFC") === ctx.name);
    const authorKeys = chainKeyFor(chain, ctx.author_user_id, v.author_key_fingerprint_hex);
    check(
      `meta-sig ${label}: author fingerprint matches chain keys`,
      authorKeys.key_fingerprint_hex === v.author_key_fingerprint_hex,
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(authorKeys.sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`meta-sig ${label}: Ed25519 signature`, ok);
  };

  for (const v of doc.vectors) {
    await verifyStatement(v, v.name);
    check(
      `meta-sig ${v.name}: head hash matches chain`,
      v.context.chain_head_hash_hex === chainHeadHash(chain, v.chain, v.context.chain_head_seq),
    );
    if (v.prev_base !== undefined) {
      check(
        `meta-sig ${v.name}: prev links to ${v.prev_base}`,
        v.context.prev_meta_sig_hash_hex === byName.get(v.prev_base)?.signed_bytes_sha256_hex,
      );
    } else {
      check(
        `meta-sig ${v.name}: metaVersion 1 has empty prev`,
        v.context.prev_meta_sig_hash_hex === "",
      );
    }
  }
  check(
    "meta-sig: no positive environment statement is deleted",
    doc.vectors.every((v) => v.context.kind !== "environment" || v.context.status === "active"),
  );
  check(
    "meta-sig: env-status-deleted is an invalid-input negative",
    doc.negative.some(
      (n) =>
        n.name === "env-status-deleted" &&
        n.kind === "invalid-input" &&
        n.context.kind === "environment" &&
        n.context.status === "deleted",
    ),
  );
  {
    const del = byName.get("var-delete");
    const rename = byName.get("var-rename");
    check(
      "meta-sig var-delete: keeps last active name",
      del.context.status === "deleted" && del.context.name === rename.context.name,
    );
  }

  {
    const [a, b] = doc.rename_fork.branches;
    for (const branch of [a, b]) {
      await verifyStatement(branch, `fork ${branch.name}`);
    }
    const sameCoordinate =
      a.context.variable_id === b.context.variable_id &&
      a.context.meta_version === b.context.meta_version &&
      a.context.environment_id === b.context.environment_id &&
      a.context.prev_meta_sig_hash_hex === b.context.prev_meta_sig_hash_hex;
    check(
      "meta-sig rename-fork: same coordinate, distinct signed bytes (equivocation evidence)",
      sameCoordinate && a.signed_bytes_sha256_hex !== b.signed_bytes_sha256_hex,
    );
  }

  {
    for (const statement of doc.name_swap.statements) {
      await verifyStatement(statement, `swap ${statement.name}`);
    }
    for (const swapped of doc.name_swap.swapped) {
      const reconstructed = signedBytes(swapped.context);
      const bytesMatch = toHex(reconstructed) === swapped.verify_signed_bytes_hex;
      const verified = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(swapped.verify_key_hex),
        fromHex(swapped.signature_hex),
        reconstructed,
      );
      check(`meta-sig name-swap: ${swapped.name}`, bytesMatch && verified === false);
    }
  }

  {
    const e = doc.tenure_extension.entry;
    const payloadBytes = lpEncode(PAYLOAD_FIELD_ORDER[e.op].map((k) => e.payload[k]));
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
      await importSigPub(chain.keys[e.actor.user_id].sig_pub_hex),
      fromHex(e.signature_hex),
      signed,
    );
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
    check(
      "meta-sig tenure-extension: entry is a valid append",
      sigOk &&
        toHex(payloadBytes) === e.payload_bytes_hex &&
        toHex(signed) === e.signed_bytes_hex &&
        e.prev_hash_hex === chain.entries.at(-1).entry_hash_hex &&
        toHex(entryBytes) === e.entry_bytes_hex &&
        (await sha256hex(entryBytes)) === e.entry_hash_hex,
    );
  }

  for (const n of doc.negative) {
    if (
      n.kind === "authorization" ||
      n.kind === "invalid-input" ||
      n.kind === "unsupported-layout"
    ) {
      const bytes = signedBytes(n.context);
      const ok = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(n.verify_key_hex),
        fromHex(n.signature_hex),
        bytes,
      );
      check(
        `meta-sig rule negative: ${n.name} (signature must be VALID)`,
        ok && toHex(bytes) === n.signed_bytes_hex,
      );
      continue;
    }
    const reconstructed = signedBytes(n.context);
    const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
    const verified = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      reconstructed,
    );
    check(`meta-sig negative: ${n.name}`, bytesMatch && verified === false);
  }
  {
    const declared = byName.get("var-v3-create-no-max-age");
    const activation = byName.get("var-v3-activation");
    check(
      "meta-sig v3: activation links declared -> active",
      declared.context.status === "declared" &&
        activation.context.status === "active" &&
        activation.context.layout_version === 3 &&
        activation.context.prev_meta_sig_hash_hex === declared.signed_bytes_sha256_hex,
    );
    const upgraded = byName.get("var-v3-upgrade-from-v1");
    const predecessor = byName.get(upgraded.prev_base);
    const created = byName.get("var-v3-create-expiring");
    const deleted = byName.get("var-v3-delete-keeps-max-age");
    check(
      "meta-sig v3: upgrade links a v1 predecessor",
      (predecessor.context.layout_version ?? 1) === 1 &&
        upgraded.context.layout_version === 3 &&
        upgraded.context.prev_meta_sig_hash_hex === predecessor.signed_bytes_sha256_hex,
    );
    check(
      "meta-sig v3: delete keeps max_age_days and the schema fields",
      deleted.context.status === "deleted" &&
        deleted.context.name === created.context.name &&
        deleted.context.var_type === created.context.var_type &&
        deleted.context.required === created.context.required &&
        deleted.context.description === created.context.description &&
        deleted.context.max_age_days === created.context.max_age_days,
    );
    const negativeContext = (name) => doc.negative.find((n) => n.name === name).context;
    check(
      "meta-sig v3: v3-missing-max-age omits the field on a layout-3 context",
      negativeContext("v3-missing-max-age").layout_version === 3 &&
        !("max_age_days" in negativeContext("v3-missing-max-age")),
    );
    check(
      "meta-sig v3: leading-zero and out-of-range values are outside 1..3650 canonical form",
      !/^(?:[1-9][0-9]{0,3})$/.test(negativeContext("v3-max-age-leading-zero").max_age_days) &&
        Number(negativeContext("v3-max-age-out-of-range").max_age_days) > 3650,
    );
    check(
      "meta-sig v3: v3-empty-required carries an empty required on a layout-3 context",
      negativeContext("v3-empty-required").layout_version === 3 &&
        negativeContext("v3-empty-required").required === "",
    );
    const retired = doc.negative.find((n) => n.name === "v2-layout-unsupported");
    check(
      "meta-sig v2-layout-unsupported: declares the retired layout under its domain",
      retired.kind === "unsupported-layout" &&
        retired.expected_error === "UnsupportedMetaLayout" &&
        retired.context.layout_version === 2 &&
        retired.context.domain === `${retired.context.suite}/var-meta-sig-v2` &&
        !("max_age_days" in retired.context),
    );
  }
  {
    const nfc = doc.negative.find((n) => n.name === "nfc-variant");
    check(
      "meta-sig nfc-variant: negative name is non-NFC variant of the signed name",
      nfc.context.name.normalize("NFC") === byName.get("var-nfc-name").context.name &&
        nfc.context.name !== byName.get("var-nfc-name").context.name,
    );
  }
}

{
  const doc = read("env-manifest.json");
  const chain = read("chain-entries.json");
  const projectId = chain.entries[0].entry_hash_hex;
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  const MANIFEST_SIGNED_FIELDS_ORDER = [
    "domain",
    "project_id",
    "environment_id",
    "epoch",
    "manifest_version",
    "variables_digest_hex",
    "env_meta_version",
    "env_meta_sig_hash_hex",
    "prev_manifest_sig_hash_hex",
    "issuer_user_id",
    "chain_head_hash_hex",
    "chain_head_seq",
  ];
  const DIGEST_ENTRY_FIELDS_ORDER = ["variable_id", "status", "meta_version", "meta_sig_hash_hex"];
  check(
    "env-manifest: manifest_signed_fields_order matches spec",
    sameOrder(doc.manifest_signed_fields_order, MANIFEST_SIGNED_FIELDS_ORDER),
  );
  check(
    "env-manifest: digest_entry_fields_order matches spec",
    sameOrder(doc.digest_entry_fields_order, DIGEST_ENTRY_FIELDS_ORDER),
  );
  const signedBytes = (ctx) => lpEncode(MANIFEST_SIGNED_FIELDS_ORDER.map((key) => ctx[key]));
  const encoder = new TextEncoder();
  const byteCompare = (a, b) => {
    const ba = encoder.encode(a);
    const bb = encoder.encode(b);
    const n = Math.min(ba.length, bb.length);
    for (let i = 0; i < n; i += 1) {
      if (ba[i] !== bb[i]) return ba[i] - bb[i];
    }
    return ba.length - bb.length;
  };
  const digestInput = (entries, sort = true) => {
    const ordered = sort
      ? entries.toSorted((a, b) => byteCompare(a.variable_id, b.variable_id))
      : entries;
    return lpEncode([
      "maruhi/v1/env-manifest-vars",
      ...ordered.map((e) => lpEncode(DIGEST_ENTRY_FIELDS_ORDER.map((key) => e[key]))),
    ]);
  };
  const digestHex = async (entries, sort = true) => sha256hex(digestInput(entries, sort));

  for (const c of doc.digests) {
    check(
      `env-manifest digest ${c.name}: input reconstruction`,
      toHex(digestInput(c.entries)) === c.digest_input_hex,
    );
    check(
      `env-manifest digest ${c.name}: sha256`,
      (await digestHex(c.entries)) === c.variables_digest_hex,
    );
  }
  {
    const order = doc.digests.find((c) => c.name === "byte-ascending-order");
    check(
      "env-manifest digest byte-ascending-order: uppercase sorts before lowercase",
      order.entries[0].variable_id.startsWith("Z") && order.entries[1].variable_id.startsWith("a"),
    );
  }

  const byName = new Map(doc.vectors.map((v) => [v.name, v]));
  const verifyManifest = async (v, label) => {
    const ctx = v.context;
    const bytes = signedBytes(ctx);
    check(`env-manifest ${label}: signed bytes`, toHex(bytes) === v.signed_bytes_hex);
    check(
      `env-manifest ${label}: signed bytes sha256`,
      (await sha256hex(bytes)) === v.signed_bytes_sha256_hex,
    );
    check(
      `env-manifest ${label}: domain embeds suite`,
      ctx.domain === `${ctx.suite}/env-manifest-sig`,
    );
    check(`env-manifest ${label}: project id is genesis hash`, ctx.project_id === projectId);
    check(
      `env-manifest ${label}: variables digest recomputation`,
      (await digestHex(v.entries)) === ctx.variables_digest_hex,
    );
    const issuerKeys = chainKeyFor(chain, ctx.issuer_user_id, v.issuer_key_fingerprint_hex);
    check(
      `env-manifest ${label}: issuer fingerprint matches chain keys`,
      issuerKeys.key_fingerprint_hex === v.issuer_key_fingerprint_hex,
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(issuerKeys.sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`env-manifest ${label}: Ed25519 signature`, ok);
  };

  for (const v of doc.vectors) {
    await verifyManifest(v, v.name);
    check(
      `env-manifest ${v.name}: head hash matches chain`,
      v.context.chain_head_hash_hex === chainHeadHash(chain, v.chain, v.context.chain_head_seq),
    );
    if (v.prev_base !== undefined) {
      check(
        `env-manifest ${v.name}: prev links to ${v.prev_base}`,
        v.context.prev_manifest_sig_hash_hex === byName.get(v.prev_base)?.signed_bytes_sha256_hex,
      );
    } else {
      check(
        `env-manifest ${v.name}: manifestVersion 1 has empty prev`,
        v.context.prev_manifest_sig_hash_hex === "" && v.context.manifest_version === 1,
      );
    }
  }
  {
    const del = byName.get("manifest-var-delete");
    check(
      "env-manifest manifest-var-delete: digest includes the tombstone",
      del.entries.some((e) => e.status === "deleted"),
    );
  }

  {
    const [a, b] = doc.manifest_fork.branches;
    for (const branch of [a, b]) {
      await verifyManifest(branch, `fork ${branch.name}`);
    }
    const sameCoordinate =
      a.context.environment_id === b.context.environment_id &&
      a.context.manifest_version === b.context.manifest_version &&
      a.context.prev_manifest_sig_hash_hex === b.context.prev_manifest_sig_hash_hex;
    check(
      "env-manifest fork: same coordinate, distinct signed bytes (equivocation evidence)",
      sameCoordinate && a.signed_bytes_sha256_hex !== b.signed_bytes_sha256_hex,
    );
  }

  for (const n of doc.negative) {
    if (n.kind === "authorization") {
      const bytes = signedBytes(n.context);
      const ok = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(n.verify_key_hex),
        fromHex(n.signature_hex),
        bytes,
      );
      check(
        `env-manifest rule negative: ${n.name} (signature must be VALID)`,
        ok && toHex(bytes) === n.signed_bytes_hex,
      );
      if (n.verify_entries !== undefined) {
        check(
          `env-manifest rule negative: ${n.name} (verify-side digest differs)`,
          (await digestHex(n.verify_entries)) !== n.context.variables_digest_hex,
        );
      }
      continue;
    }
    const reconstructed = signedBytes(n.context);
    const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
    const verified = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      reconstructed,
    );
    check(`env-manifest negative: ${n.name}`, bytesMatch && verified === false);
  }
  {
    const swap = doc.negative.find((n) => n.name === "digest-order-swap");
    check(
      "env-manifest digest-order-swap: signed digest is the descending-order value",
      (await digestHex(swap.entries.toReversed(), false)) === swap.context.variables_digest_hex &&
        (await digestHex(swap.entries)) !== swap.context.variables_digest_hex,
    );
  }
}

{
  const doc = read("audit-head.json");
  const sha256 = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const NULLABLE = new Set([
    "row_id",
    "client_ts",
    "actor_user_id",
    "actor_key_fingerprint",
    "actor_api_token_id",
    "target_user_id",
    "target_key_fingerprint",
    "environment_id",
    "variable_id",
    "epoch",
    "version",
    "chain_seq",
    "payload",
  ]);
  const COLUMNS = [
    "seq",
    "row_id",
    "server_ts",
    "client_ts",
    "event",
    "actor_type",
    "actor_user_id",
    "actor_key_fingerprint",
    "actor_api_token_id",
    "target_user_id",
    "target_key_fingerprint",
    "environment_id",
    "variable_id",
    "epoch",
    "version",
    "chain_seq",
    "payload",
  ];
  check("audit-head: column order matches spec", sameOrder(doc.row_columns_order, COLUMNS));
  check("audit-head: domain embeds suite", doc.domain === "maruhi/v1/audit-head");
  check("audit-head: initial head is the empty string", doc.initial_head === "");
  const rowDigest = async (row) =>
    sha256(
      lpEncode(
        COLUMNS.map((column) => {
          const value = row[column];
          if (!NULLABLE.has(column)) {
            return value;
          }
          if (value === null) {
            return Uint8Array.of(0x00);
          }
          const body = new TextEncoder().encode(String(value));
          const tagged = new Uint8Array(1 + body.length);
          tagged[0] = 0x01;
          tagged.set(body, 1);
          return tagged;
        }),
      ),
    );
  let head = doc.initial_head;
  for (const c of doc.chain) {
    const digest = await rowDigest(c.row);
    check(`audit-head: seq ${c.row.seq} row digest`, digest === c.expected_row_digest_hex);
    head = await sha256(lpEncode([doc.domain, head, c.row.seq, digest]));
    check(`audit-head: seq ${c.row.seq} head hash`, head === c.expected_head_hash_hex);
  }
  const nullDigest = await rowDigest(doc.null_vs_empty.null_row);
  const emptyDigest = await rowDigest(doc.null_vs_empty.empty_row);
  check("audit-head: null row digest", nullDigest === doc.null_vs_empty.null_row_digest_hex);
  check("audit-head: empty row digest", emptyDigest === doc.null_vs_empty.empty_row_digest_hex);
  check("audit-head: null and empty string differ", nullDigest !== emptyDigest);
}

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

{
  const doc = read("dek-wrap.json");
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  const keyPairs = {
    basic: {
      privateKey: await suite.DeserializePrivateKey(fromHex(doc.recipient_keypair.skRm_hex), false),
      publicKey: await suite.DeserializePublicKey(fromHex(doc.recipient_keypair.pkRm_hex)),
    },
    "server-basic": {
      privateKey: await suite.DeserializePrivateKey(fromHex(doc.server_keypair.skSm_hex), false),
      publicKey: await suite.DeserializePublicKey(fromHex(doc.server_keypair.pkSm_hex)),
    },
  };
  const vectorByName = (name) => doc.vectors.find((v) => v.name === name);
  const open = (baseName, infoHex, encHex, ctHex) =>
    suite.Open(keyPairs[baseName], fromHex(encHex), fromHex(ctHex), {
      info: fromHex(infoHex),
      aad: fromHex(vectorByName(baseName).aad_hex),
    });
  for (const v of doc.vectors) {
    const dek = await open(v.name, v.info_hex, v.enc_hex, v.ciphertext_hex);
    check(`dek-wrap: ${v.name} panva open == DEK`, toHex(new Uint8Array(dek)) === v.dek_hex);
  }
  {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", fromHex(doc.server_keypair.pkSm_hex)),
    );
    const fp = toHex(digest.slice(0, 16));
    const serverVector = vectorByName("server-basic");
    check(
      "dek-wrap: server key fingerprint",
      fp === doc.server_keypair.server_key_fingerprint_hex &&
        toHex(
          lpEncode([
            serverVector.domain,
            serverVector.project_id,
            serverVector.environment_id,
            serverVector.epoch,
            fp,
          ]),
        ) === serverVector.info_hex,
    );
  }
  for (const n of doc.negative) {
    const base = vectorByName(n.base);
    let failed = false;
    try {
      await open(
        n.base,
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

{
  const doc = read("lease-wrap.json");
  const dekWrap = read("dek-wrap.json");
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  const workloadKeyPair = {
    privateKey: await suite.DeserializePrivateKey(fromHex(doc.workload_keypair.skWm_hex), false),
    publicKey: await suite.DeserializePublicKey(fromHex(doc.workload_keypair.pkWm_hex)),
  };
  const vectorByName = (name) => doc.vectors.find((v) => v.name === name);

  const digestOf = async (sub) => {
    const lp = lpEncode([doc.claims.domain, doc.claims.issuer_url, sub, doc.claims.audience]);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", lp));
    return { lpHex: toHex(lp), digestHex: toHex(digest) };
  };
  {
    const primary = await digestOf(doc.claims.subject);
    const other = await digestOf(doc.claims.other_subject);
    check(
      "lease-wrap: claims_digest LP + SHA-256",
      primary.lpHex === doc.claims.lp_hex &&
        primary.digestHex === doc.claims.claims_digest_hex &&
        other.lpHex === doc.claims.other_lp_hex &&
        other.digestHex === doc.claims.other_claims_digest_hex,
    );
    check(
      "lease-wrap: claims_digest domain embeds suite",
      doc.claims.domain === "maruhi/v1/lease-claims",
    );
  }

  {
    const serverWrap = dekWrap.vectors.find((v) => v.name === "server-basic");
    const basic = vectorByName("basic");
    check(
      "lease-wrap: coordinates and DEK match dek-wrap.json server-basic",
      basic.project_id === serverWrap.project_id &&
        basic.environment_id === serverWrap.environment_id &&
        basic.epoch === serverWrap.epoch &&
        basic.dek_hex === serverWrap.dek_hex,
    );
  }

  for (const v of doc.vectors) {
    check(
      `lease-wrap: ${v.name} info reconstruction`,
      toHex(lpEncode([v.domain, v.project_id, v.environment_id, v.epoch, v.claims_digest_hex])) ===
        v.info_hex,
    );
    check(`lease-wrap: ${v.name} domain embeds suite`, v.domain === "maruhi/v1/lease-wrap");
    const dek = await suite.Open(workloadKeyPair, fromHex(v.enc_hex), fromHex(v.ciphertext_hex), {
      info: fromHex(v.info_hex),
      aad: fromHex(v.aad_hex),
    });
    check(`lease-wrap: ${v.name} panva open == DEK`, toHex(new Uint8Array(dek)) === v.dek_hex);
  }

  for (const n of doc.negative) {
    const base = vectorByName(n.base);
    let failed = false;
    try {
      await suite.Open(
        workloadKeyPair,
        fromHex(n.enc_hex ?? base.enc_hex),
        fromHex(n.ciphertext_hex ?? base.ciphertext_hex),
        { info: fromHex(n.open_info_hex ?? base.info_hex), aad: fromHex(base.aad_hex) },
      );
    } catch {
      failed = true;
    }
    check(`lease-wrap negative: ${n.name}`, failed === n.must_fail);
  }
}

{
  const doc = read("sealed-value.json");
  const dekWrap = read("dek-wrap.json");
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  const recipientKeyPair = {
    privateKey: await suite.DeserializePrivateKey(
      fromHex(dekWrap.recipient_keypair.skRm_hex),
      false,
    ),
    publicKey: await suite.DeserializePublicKey(fromHex(dekWrap.recipient_keypair.pkRm_hex)),
  };
  const vectorByName = (name) => doc.vectors.find((v) => v.name === name);
  const basicWrap = dekWrap.vectors.find((v) => v.name === "basic");
  const basic = vectorByName("basic");
  check(
    "sealed-value: recipient and coordinates match dek-wrap.json basic",
    basic.project_id === basicWrap.project_id &&
      basic.environment_id === basicWrap.environment_id &&
      basic.recipient_user_id === basicWrap.recipient_user_id,
  );
  check(
    "sealed-value: proposal id form (32 lowercase hex) and companion shares it",
    /^[0-9a-f]{32}$/.test(doc.proposal.proposal_id) &&
      vectorByName("companion").proposal_id === basic.proposal_id &&
      vectorByName("companion").variable_id !== basic.variable_id,
  );
  for (const v of doc.vectors) {
    check(
      `sealed-value: ${v.name} info reconstruction`,
      toHex(
        lpEncode([
          v.domain,
          v.project_id,
          v.environment_id,
          v.proposal_id,
          v.variable_id,
          v.base_version,
          v.recipient_user_id,
        ]),
      ) === v.info_hex,
    );
    check(`sealed-value: ${v.name} domain embeds suite`, v.domain === "maruhi/v1/sealed-value");
    const opened = await suite.Open(
      recipientKeyPair,
      fromHex(v.enc_hex),
      fromHex(v.ciphertext_hex),
      { info: fromHex(v.info_hex), aad: fromHex(v.aad_hex) },
    );
    check(
      `sealed-value: ${v.name} panva open == plaintext`,
      toHex(new Uint8Array(opened)) === v.plaintext_hex,
    );
  }
  for (const n of doc.negative) {
    const base = vectorByName(n.base);
    let failed = false;
    try {
      await suite.Open(
        recipientKeyPair,
        fromHex(n.enc_hex ?? base.enc_hex),
        fromHex(n.ciphertext_hex ?? base.ciphertext_hex),
        { info: fromHex(n.open_info_hex ?? base.info_hex), aad: fromHex(base.aad_hex) },
      );
    } catch {
      failed = true;
    }
    check(`sealed-value negative: ${n.name}`, failed === n.must_fail);
  }
}

{
  const doc = read("checkpoint-digest.json");
  const sha256 = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  for (const digestCase of doc.cases) {
    const actives = digestCase.variables.filter((v) => v.status === "active");
    const nonActives = digestCase.variables.filter((v) => v.status !== "active");
    check(
      `checkpoint-digest ${digestCase.name}: entries are exactly the active variables`,
      actives.length === digestCase.values_digest_entries.length &&
        actives.every((v, i) => {
          const entry = digestCase.values_digest_entries[i];
          return (
            entry.variable_id === v.variable_id &&
            entry.version === v.version &&
            entry.value_sig_hash_hex === v.value_sig_hash_hex
          );
        }),
    );
    check(
      `checkpoint-digest ${digestCase.name}: non-active variables carry no value coordinates`,
      nonActives.every(
        (v) =>
          (v.status === "declared" || v.status === "deleted") &&
          v.version === undefined &&
          v.value_sig_hash_hex === undefined,
      ),
    );
    const input = envValuesDigestInput(digestCase.values_digest_entries);
    check(
      `checkpoint-digest ${digestCase.name}: digest input`,
      toHex(input) === digestCase.digest_input_hex,
    );
    check(
      `checkpoint-digest ${digestCase.name}: values digest`,
      (await sha256(input)) === digestCase.values_digest_hex,
    );
  }
  {
    const chain = read("chain-entries.json");
    const emptySet = (chain.values_digests ?? []).find((c) => c.name === "empty-set");
    const allDeclared = doc.cases.find((c) => c.name === "all-declared-empty");
    check(
      "checkpoint-digest all-declared-empty: equals the empty-set digest",
      emptySet !== undefined && allDeclared.values_digest_hex === emptySet.values_digest_hex,
    );
  }
}

const scopeIncludes = (scope, environmentId) =>
  scope.kind === "all" || scope.environments.includes(environmentId);
const recipientSet = (entries) =>
  JSON.stringify(
    entries
      .map((entry) =>
        JSON.stringify([
          entry.recipient_class,
          entry.recipient_id,
          entry.key_fingerprint_hex ?? null,
          entry.recipient_enc_pub_hex,
        ]),
      )
      .toSorted(),
  );
const memberRecipient = ({ person, device }) => ({
  recipient_class: "member",
  recipient_id: person.user_id,
  key_fingerprint_hex: device.key_fingerprint_hex,
  recipient_enc_pub_hex: device.enc_pub_hex,
});
const holdsEncKeyOf = (person, grant) =>
  person.devices.some((device) => device.enc_pub_hex === grant.server_enc_pub_hex);
{
  const doc = read("recipient-sets.json");
  const rank = { reader: 0, member: 1, admin: 2, owner: 3 };
  for (const [name, fixture] of Object.entries(doc.fixtures)) {
    for (const person of fixture.members) {
      for (const device of person.devices) {
        const fingerprint = (
          await sha256Bytes(fromHex(device.enc_pub_hex + device.sig_pub_hex))
        ).slice(0, 16);
        check(
          `recipient-sets ${name}: ${device.label} fingerprint (§3)`,
          toHex(fingerprint) === device.key_fingerprint_hex,
        );
      }
    }
    for (const grant of fixture.server_grants) {
      const fingerprint = (await sha256Bytes(fromHex(grant.server_enc_pub_hex))).slice(0, 16);
      check(
        `recipient-sets ${name}: ${grant.label} fingerprint (§9)`,
        toHex(fingerprint) === grant.server_key_fingerprint_hex,
      );
    }
    const devices = fixture.members.flatMap((person) => person.devices);
    check(
      `recipient-sets ${name}: no two devices share a key (§6.2 key uniqueness)`,
      new Set(devices.map((device) => device.enc_pub_hex)).size === devices.length &&
        new Set(devices.map((device) => device.sig_pub_hex)).size === devices.length,
    );
    check(
      `recipient-sets ${name}: no device holds a grant's enc key (§6.2 key uniqueness)`,
      fixture.server_grants.every(
        (grant) => !fixture.members.some((person) => holdsEncKeyOf(person, grant)),
      ),
    );
  }
  for (const recipientCase of doc.cases) {
    const fixture = doc.fixtures[recipientCase.fixture];
    const environmentId = recipientCase.environment_id;
    const receiving = fixture.members.flatMap((person) =>
      person.devices
        .filter(
          (device) =>
            scopeIncludes(person.scope, environmentId) &&
            scopeIncludes(device.scope, environmentId),
        )
        .map((device) => ({ person, device })),
    );
    check(
      `recipient-sets ${recipientCase.name}: R(E)`,
      recipientSet([
        ...receiving.map(memberRecipient),
        ...fixture.server_grants
          .filter((grant) => grant.scope_environments.includes(environmentId))
          .map((grant) => ({
            recipient_class: "server",
            recipient_id: grant.server_key_fingerprint_hex,
            recipient_enc_pub_hex: grant.server_enc_pub_hex,
          })),
      ]) === recipientSet(recipientCase.expected_wrap_recipients),
    );
    const proposalRecipients = receiving
      .filter(
        ({ person, device }) => Math.min(rank[person.role], rank[device.role_cap]) >= rank.member,
      )
      .map(memberRecipient);
    check(
      `recipient-sets ${recipientCase.name}: W(E)`,
      recipientSet(proposalRecipients) === recipientSet(recipientCase.expected_proposal_recipients),
    );
    const wrapSet = new Set(JSON.parse(recipientSet(recipientCase.expected_wrap_recipients)));
    check(
      `recipient-sets ${recipientCase.name}: W(E) ⊆ R(E)`,
      JSON.parse(recipientSet(recipientCase.expected_proposal_recipients)).every((entry) =>
        wrapSet.has(entry),
      ),
    );
  }
  {
    const named = doc.fixtures["fingerprint-named-member"];
    const [serverZ] = named.server_grants;
    check(
      "recipient-sets fingerprint-named-member: a member named by server-z's fingerprint has a device",
      named.members.some(
        (person) =>
          person.user_id === serverZ.server_key_fingerprint_hex && person.devices.length > 0,
      ),
    );
  }
}

{
  const doc = read("master-key-wrap.json");
  const recovery = read("recovery-wrap.json");
  const sha256 = sha256Bytes;
  const MASTER_WRAP_DOMAIN = "maruhi/v1/master-wrap";
  const masterAad = (kind, ref, mode) =>
    lpEncode([MASTER_WRAP_DOMAIN, doc.user_id, kind, ref, mode]);
  const guardianInfo = (groupId, mode, index, guardian) =>
    lpEncode(["maruhi/v1/guardian-wrap", doc.user_id, groupId, mode, index, guardian]);
  const handoffInfo = (requestId, source, index, approver) =>
    lpEncode(["maruhi/v1/handoff-wrap", doc.user_id, requestId, source, index, approver]);
  const xorHex = (...hexes) => {
    const arrays = hexes.map(fromHex);
    const out = new Uint8Array(arrays[0].length);
    for (const a of arrays) for (let i = 0; i < out.length; i++) out[i] ^= a[i];
    return toHex(out);
  };
  check(
    "master-wrap: B and user_id inherit recovery-wrap.json",
    doc.user_id === recovery.vectors[0].user_id &&
      doc.master_secret_blob_hex === recovery.vectors[0].master_secret_blob_hex,
  );
  const vectorByName = (name) => doc.vectors.find((v) => v.name === name);
  const passkey = vectorByName("passkey-prf-basic");
  {
    const ikm = await crypto.subtle.importKey("raw", fromHex(passkey.prf_out_hex), "HKDF", false, [
      "deriveBits",
    ]);
    const kek = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: new TextEncoder().encode(doc.passkey.hkdf.info_utf8),
        },
        ikm,
        256,
      ),
    );
    check("master-wrap: passkey KEK derivation (salt empty)", toHex(kek) === passkey.kek_hex);
    check(
      "master-wrap: passkey aad reconstruction",
      toHex(masterAad("passkey-prf", passkey.wrap_id, "")) === passkey.aad_hex,
    );
    const pt = await aesGcmDecrypt(
      passkey.kek_hex,
      passkey.nonce_hex,
      passkey.aad_hex,
      passkey.ciphertext_hex,
    );
    check("master-wrap: passkey decrypt == B", toHex(pt) === doc.master_secret_blob_hex);
  }
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  const keyPairOf = async (k) => ({
    privateKey: await suite.DeserializePrivateKey(fromHex(k.sk_hex), false),
    publicKey: await suite.DeserializePublicKey(fromHex(k.pk_hex)),
  });
  const guardianPairs = {};
  for (const [id, k] of Object.entries(doc.guardian_keypairs)) {
    guardianPairs[id] = await keyPairOf(k);
  }
  const ephemeralPair = await keyPairOf(doc.ephemeral_keypair);
  const open = (pair, infoHex, encHex, ctHex) =>
    suite.Open(pair, fromHex(encHex), fromHex(ctHex), {
      info: fromHex(infoHex),
      aad: new Uint8Array(0),
    });
  for (const g of [vectorByName("guardian-any-2"), vectorByName("guardian-all-3")]) {
    check(
      `master-wrap: ${g.name} aad reconstruction`,
      toHex(masterAad("guardian", g.group_id, g.mode)) === g.aad_hex,
    );
    const pt = await aesGcmDecrypt(g.kek_hex, g.nonce_hex, g.aad_hex, g.ciphertext_hex);
    check(`master-wrap: ${g.name} decrypt == B`, toHex(pt) === doc.master_secret_blob_hex);
    const opened = [];
    for (const s of g.shares) {
      check(
        `master-wrap: ${g.name} share ${s.share_index} info reconstruction`,
        toHex(guardianInfo(g.group_id, g.mode, s.share_index, s.guardian_user_id)) === s.info_hex,
      );
      const v = await open(
        guardianPairs[s.guardian_user_id],
        s.info_hex,
        s.enc_hex,
        s.ciphertext_hex,
      );
      check(
        `master-wrap: ${g.name} share ${s.share_index} panva open == share`,
        toHex(new Uint8Array(v)) === s.share_hex,
      );
      opened.push(s.share_hex);
    }
    if (g.mode === "any") {
      check(
        `master-wrap: ${g.name} every share equals KEK`,
        opened.every((h) => h === g.kek_hex),
      );
    } else {
      check(`master-wrap: ${g.name} XOR of all shares == KEK`, xorHex(...opened) === g.kek_hex);
      check(
        `master-wrap: ${g.name} shares are ${g.shares.length} distinct values`,
        new Set(opened).size === g.shares.length,
      );
    }
  }
  {
    const pk = fromHex(doc.handoff.ephemeral_pub_hex);
    const lp = lpEncode([doc.handoff.request_id_domain, doc.handoff.ephemeral_pub_hex]);
    check("master-wrap: handoff request_id LP", toHex(lp) === doc.handoff.request_id_lp_hex);
    check(
      "master-wrap: handoff request_id",
      toHex(await sha256(lp)) === doc.handoff.request_id_hex,
    );
    const checksum = (await sha256(pk)).slice(0, 4);
    check("master-wrap: handoff code checksum", toHex(checksum) === doc.handoff.code.checksum_hex);
    const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const payload = fromHex(doc.handoff.code.payload_hex);
    let bits = 0;
    let acc = 0;
    let symbols = "";
    for (const byte of payload) {
      acc = (acc << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        symbols += B32[(acc >> bits) & 31];
        acc &= (1 << bits) - 1;
      }
    }
    if (bits > 0) symbols += B32[(acc << (5 - bits)) & 31];
    check(
      "master-wrap: handoff code symbols",
      symbols.length === 58 && symbols === doc.handoff.code.symbols,
    );
    check(
      "master-wrap: handoff code display grouping",
      (symbols.match(/.{1,4}/g) ?? []).join("-") === doc.handoff.code.display,
    );
    check(
      "master-wrap: other ephemeral has a different request_id",
      doc.handoff.other_ephemeral.request_id_hex !== doc.handoff.request_id_hex,
    );
  }
  for (const h of [vectorByName("handoff-guardian-share")]) {
    check(
      `master-wrap: ${h.name} info reconstruction`,
      toHex(handoffInfo(h.request_id_hex, h.source, h.share_index, h.approver_user_id)) ===
        h.info_hex,
    );
    const v = await open(ephemeralPair, h.info_hex, h.enc_hex, h.ciphertext_hex);
    check(`master-wrap: ${h.name} panva open == value`, toHex(new Uint8Array(v)) === h.value_hex);
  }
  {
    const h = vectorByName("handoff-guardian-share");
    const all3 = vectorByName("guardian-all-3");
    check(
      "master-wrap: handoff-guardian-share re-seals share 1 of guardian-all-3",
      h.source === all3.group_id && h.value_hex === all3.shares[0].share_hex,
    );
    check(
      "master-wrap: no device kind remains (DK)",
      doc.vectors.every(
        (v) => v.kind === undefined || v.kind === "passkey-prf" || v.kind === "guardian",
      ) && doc.vectors.every((v) => v.source !== "device"),
    );
  }
  for (const n of doc.negative) {
    const base = vectorByName(n.base);
    let failed = false;
    try {
      if (n.code_symbols !== undefined) {
        const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        if (n.code_symbols.length !== 58) throw new Error("length");
        const out = new Uint8Array(36);
        let bits = 0;
        let acc = 0;
        let off = 0;
        for (const s of n.code_symbols) {
          const v = B32.indexOf(s);
          if (v < 0) throw new Error("alphabet");
          acc = (acc << 5) | v;
          bits += 5;
          if (bits >= 8) {
            bits -= 8;
            out[off++] = (acc >> bits) & 0xff;
            acc &= (1 << bits) - 1;
          }
        }
        if (acc !== 0) throw new Error("padding");
        const sum = (await sha256(out.slice(0, 32))).slice(0, 4);
        if (toHex(sum) !== toHex(out.slice(32))) throw new Error("checksum");
      } else if (n.open_info_hex !== undefined || n.open_enc_hex !== undefined) {
        if (base.class === "H") {
          await open(
            ephemeralPair,
            n.open_info_hex ?? base.info_hex,
            n.open_enc_hex ?? base.enc_hex,
            base.ciphertext_hex,
          );
        } else {
          const share = base.shares.find((s) => s.share_index === n.share_index);
          await open(
            guardianPairs[share.guardian_user_id],
            n.open_info_hex,
            share.enc_hex,
            share.ciphertext_hex,
          );
        }
      } else {
        await aesGcmDecrypt(
          n.decrypt_kek_hex ?? base.kek_hex,
          base.nonce_hex,
          n.decrypt_aad_hex ?? base.aad_hex,
          base.ciphertext_hex,
        );
      }
    } catch {
      failed = true;
    }
    check(`master-wrap negative: ${n.name}`, failed === n.must_fail);
  }
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall vectors verified");
