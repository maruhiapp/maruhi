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

// 正規化・署名のフィールド順は仕様のハードコードを正とし、ベクター JSON の
// 宣言はそれとの一致を検査する(JSON 由来の順序で検証すると、宣言の改変ごと
// 検証が通ってしまい、順序を独立に固定できない — session-15 レビュー③)。
// チェーン payload の正規化フィールド順(CRYPTO_SPEC §6.1 / §6.2)
const PAYLOAD_FIELD_ORDER = {
  genesis: ["enc_pub_hex", "sig_pub_hex"],
  add_member: ["target_user_id", "enc_pub_hex", "sig_pub_hex", "role"],
  remove_member: ["target_user_id"],
  change_role: ["target_user_id", "new_role"],
  create_environment: ["environment_id", "dek_commitment_hex"],
  rotate_epoch: ["environment_id", "new_epoch", "reason", "dek_commitment_hex"],
  // 2026-08-12(CRYPTO_SPEC 0.5-draft §6.2): lease_policy_lp_hex を末尾に追加した
  // 4 フィールドが正規形
  grant_server: [
    "server_enc_pub_hex",
    "server_key_fingerprint_hex",
    "scope_environments_lp_hex",
    "lease_policy_lp_hex",
  ],
  revoke_server: ["server_key_fingerprint_hex"],
  // 2026-08-27(CRYPTO_SPEC 0.6-draft §6.2 checkpoint op — PR-F3a): 環境エントリの
  // リストは scope_environments と同じ入れ子 LP の hex 文字列 1 フィールド
  checkpoint: ["environments_lp_hex", "audit_head_hash_hex"],
};

// checkpoint の環境エントリの入れ子 LP(§6.2 — generate_reference.py と同一定義):
//   entry = LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
//              values_digest_hex)、environments_lp_hex = lower_hex(LP(entry...))
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

// checkpoint の values_digest(§6.2): v_j = LP(variable_id, version,
// value_sig_hash_hex) を variable_id の UTF-8 バイト昇順で並べ、
// LP("maruhi/v1/env-values-digest", v_1, …, v_m) を SHA-256 する
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

// grant_server の lease_policy の入れ子 LP(§6.2 — 3 段。generate_reference.py と同一定義)
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
// メタステートメントの署名フィールド順(CRYPTO_SPEC §4.2 の LP 引数列)
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
const sameOrder = (a, b) => JSON.stringify(a) === JSON.stringify(b);

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
  // 検証は仕様ハードコードの順序で行い、JSON の宣言はそれとの一致を検査する
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
    // lease_policy: 3 段の入れ子 LP(§6.2)。構造化表現からの再構築が lp_hex と一致する
    check(
      "chain: grant_server lease_policy nested LP",
      toHex(leasePolicyLp(e7.payload.lease_policy)) === e7.payload.lease_policy_lp_hex,
    );
    // 空ポリシーは空バイト列の hex = 空文字列(regrant-lease-policy-revised が使う形)
    check("chain: empty lease_policy encodes to empty hex", toHex(leasePolicyLp([])) === "");
  }
  // checkpoint(§6.2 — PR-F3a): 構造化表現(environments)からの入れ子 LP 再構築が
  // environments_lp_hex と一致する。対象は checkpoint op を含む全エントリ
  // (extended_chains / valid_appends / negative の entry)
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
        toHex(checkpointEnvironmentsLp(e.payload.environments)) ===
          e.payload.environments_lp_hex,
      );
    }
    // 環境エントリ 0 件は空バイト列の hex = 空文字列(checkpoint-empty-environments)
    check("chain: empty checkpoint environments encode to empty hex", toHex(checkpointEnvironmentsLp([])) === "");
  }
  // checkpoint の values_digest 正規形(values_digests セクション): 非正規順の
  // entries からバイト昇順の再計算が期待ダイジェストと一致する
  for (const digestCase of doc.values_digests ?? []) {
    check(
      `chain values-digest ${digestCase.name}`,
      (await sha256(envValuesDigestInput(digestCase.entries))) === digestCase.values_digest_hex,
    );
  }
  // §5.2 の DEK コミットメント: environment_deks のダミー DEK からの再計算が
  // 掲載値と一致し、create_environment / rotate_epoch の payload がそれを載せている
  {
    const projectId = doc.entries[0].entry_hash_hex; // = genesis ハッシュ(§6.4)
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
  // valid_appends: 合意規則の許容側の境界(§6.2 の禁止範囲 = 現メンバー集合のみ)。
  // 署名・正規化・prev_hash(= 正規チェーン最終エントリのハッシュ)が有効である
  // ことを確認する。受理されること自体の検査は実装テストが担う
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
      await importSigPub(doc.keys[e.actor.user_id].sig_pub_hex),
      fromHex(e.signature_hex),
      signed,
    );
    // 受理後のヘッドとして意味を持つ entry_bytes / entry_hash も正規チェーンの
    // エントリと同水準で検査する(第三者実装がこのハッシュへ追記を連鎖させても
    // 陳腐値が黙って通らないように — レビューループ 2)
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
      `chain valid append: ${a.name} (signature must be VALID)`,
      sigOk &&
        toHex(payloadBytes) === e.payload_bytes_hex &&
        toHex(signed) === e.signed_bytes_hex &&
        // 追記の接続点は seq が指す正規エントリの直後(seq 13 = 末尾ヘッド、
        // seq 10 = seq 9 ヘッドへの再 grant 追記 — regrant-lease-policy-revised)
        e.prev_hash_hex === doc.entries[e.seq - 2].entry_hash_hex &&
        toHex(entryBytes) === e.entry_bytes_hex &&
        (await sha256(entryBytes)) === e.entry_hash_hex,
    );
  }
  // extended_chains: 正規チェーンの途中ヘッドへ追記した派生チェーン(認可 negative の
  // 前提状態)。エントリ自体の正規化・署名・接続点を正規チェーンと同水準で検査する
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
      const sigOk = await crypto.subtle.verify(
        "Ed25519",
        await importSigPub(doc.keys[e.actor.user_id].sig_pub_hex),
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
        `chain extended ${chainName} seq ${e.seq} (signature must be VALID)`,
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
      // chain 指定つきは派生チェーン(extended_chains)の末尾へ接続する negative。
      // 接続点の prev が派生チェーンの最終エントリと一致することも固定する
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

// --- dek-wrap-signature.json --------------------------------------------------
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
  // ラップ本体が dek-wrap.json の basic ベクターと同一であること(一続きの実データ)
  check(
    "dek-wrap-sig: wrap body matches dek-wrap.json",
    base.enc_hex === dekWrap.vectors[0].enc_hex &&
      base.ciphertext_hex === dekWrap.vectors[0].ciphertext_hex &&
      base.recipient_enc_pub_hex === dekWrap.recipient_keypair.pkRm_hex,
  );
  // 受信者クラス server(§9 / §12-6): recipient 位置 = サーバー鍵 FP、
  // recipient_enc_pub = サーバー enc 公開鍵、ラップ本体は server-basic と同一
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

// --- invite-accept-signature.json ---------------------------------------------
{
  const doc = read("invite-accept-signature.json");
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  // 署名フィールド順は仕様のハードコードを正とする(dek-wrap-sig と同じ規律)
  const signedBytes = (ctx) =>
    lpEncode([
      ctx.domain,
      ctx.project_id,
      ctx.invite_token_hash_hex,
      ctx.invitee_user_id,
      ctx.invitee_enc_pub_hex,
      ctx.invitee_sig_pub_hex,
    ]);
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const base = doc.vectors[0];
  // invite_token_hash_hex がダミートークン生値の SHA-256 であること(導出の固定)
  check(
    "invite-accept-sig: token hash derivation",
    (await sha256hex(fromHex(doc.invite_token_hex))) === base.invite_token_hash_hex,
  );
  // 受諾者の宣言鍵が invitee ブロックと一致(署名者 = invitee の自己束縛)
  check(
    "invite-accept-sig: invitee keys bound",
    base.invitee_enc_pub_hex === doc.invitee.enc_pub_hex &&
      base.invitee_sig_pub_hex === doc.invitee.sig_pub_hex &&
      base.invitee_user_id === doc.invitee.user_id,
  );
  for (const v of doc.vectors) {
    const bytes = signedBytes(v);
    check(
      `invite-accept-sig: ${v.name} signed bytes reconstruction`,
      toHex(bytes) === v.signed_bytes_hex,
    );
    check(
      `invite-accept-sig: ${v.name} domain embeds suite`,
      v.domain === `${v.suite}/invite-accept`,
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(v.invitee_sig_pub_hex),
      fromHex(v.signature_hex),
      bytes,
    );
    check(`invite-accept-sig: ${v.name} Ed25519 signature`, ok);
  }
  for (const n of doc.negative) {
    const reconstructed = signedBytes(n.context);
    const bytesMatch = toHex(reconstructed) === n.verify_signed_bytes_hex;
    // 検証鍵は常に署名対象内の宣言鍵(§6.5 の自己束縛)であることを固定する
    const selfBound = n.verify_key_hex === n.context.invitee_sig_pub_hex;
    const verified = await crypto.subtle.verify(
      "Ed25519",
      await importSigPub(n.verify_key_hex),
      fromHex(n.signature_hex),
      reconstructed,
    );
    check(`invite-accept-sig negative: ${n.name}`, bytesMatch && selfBound && verified === false);
  }
}

// --- dek-commitment.json -------------------------------------------------------
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
  // DEK・座標が dek-wrap.json の basic と同一(ラップ → §5.2 照合が一続きの実データ)
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

// --- value-signature.json ------------------------------------------------------
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
    // チェーン参照の整合: project_id = genesis ハッシュ、head = entries[seq-1] のハッシュ
    check(`value-sig ${v.name}: project id is genesis hash`, ctx.project_id === projectId);
    check(
      `value-sig ${v.name}: head hash matches chain`,
      ctx.chain_head_hash_hex === chain.entries[ctx.chain_head_seq - 1].entry_hash_hex,
    );
    // writer 鍵(chain-entries の keys)で Ed25519 検証
    const writerKeys = chain.keys[ctx.writer_user_id];
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
    // prev 連鎖: prev_base を持つベクターは直前 version の signed_bytes ハッシュへ連鎖
    if (v.prev_base !== undefined) {
      check(
        `value-sig ${v.name}: prev links to ${v.prev_base}`,
        ctx.prev_value_sig_hash_hex === byName.get(v.prev_base)?.signed_bytes_sha256_hex,
      );
    } else {
      check(`value-sig ${v.name}: version 1 has empty prev`, ctx.prev_value_sig_hash_hex === "");
    }
    // ciphertext は environment_deks の DEK による実 AES-GCM 暗号文(AAD = §4 の LP)
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

  // fork-same-version: 両 branch とも署名有効・同一座標・prev 同一で signed_bytes が異なる
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

  // tenure-extension: 派生チェーンの seq 13 エントリ自体が有効(正規化・署名・prev 連鎖)
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
    // re-add は新鍵(旧鍵と異なる = 別 tenure の鍵束縛)
    check(
      "value-sig tenure-extension: rejoined member key differs from tenure 1",
      e.payload.sig_pub_hex !== chain.keys["user-member-0002"].sig_pub_hex &&
        e.payload.sig_pub_hex === doc.tenure_extension.rejoined_member.sig_pub_hex,
    );
  }

  for (const n of doc.negative) {
    if (n.kind === "authorization") {
      // 検証規則系は「暗号学的には有効(署名が正しい)」ことを確認する。
      // expected_reason での拒否は実装テスト(§6.3 の履歴検証)が担う
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

// --- metadata-signature.json ---------------------------------------------------
{
  const doc = read("metadata-signature.json");
  const chain = read("chain-entries.json");
  const projectId = chain.entries[0].entry_hash_hex;
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  // 検証は仕様ハードコードの順序で行い、JSON の宣言はそれとの一致を検査する
  check(
    "meta-sig: var_signed_fields_order matches spec",
    sameOrder(doc.var_signed_fields_order, VAR_SIGNED_FIELDS_ORDER),
  );
  check(
    "meta-sig: env_signed_fields_order matches spec",
    sameOrder(doc.env_signed_fields_order, ENV_SIGNED_FIELDS_ORDER),
  );
  const signedBytes = (ctx) =>
    lpEncode(
      (ctx.kind === "variable" ? VAR_SIGNED_FIELDS_ORDER : ENV_SIGNED_FIELDS_ORDER).map(
        (key) => ctx[key],
      ),
    );
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
      `meta-sig ${label}: domain embeds suite and kind`,
      ctx.domain === `${ctx.suite}/${ctx.kind === "variable" ? "var" : "env"}-meta-sig`,
    );
    check(`meta-sig ${label}: project id is genesis hash`, ctx.project_id === projectId);
    check(`meta-sig ${label}: name is NFC-normal`, ctx.name.normalize("NFC") === ctx.name);
    const authorKeys = chain.keys[ctx.author_user_id];
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
    // チェーン参照の整合(rule negative は bogus ヘッドを持つため positive のみ)
    check(
      `meta-sig ${v.name}: head hash matches chain`,
      v.context.chain_head_hash_hex === chain.entries[v.context.chain_head_seq - 1].entry_hash_hex,
    );
    // prev 連鎖: prev_base を持つベクターは直前 metaVersion の signed_bytes ハッシュへ連鎖
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
  // 削除ステートメントは直前 active 名を保持する(§4.2 — name を削除で空にしない)
  {
    const del = byName.get("var-delete");
    const rename = byName.get("var-rename");
    check(
      "meta-sig var-delete: keeps last active name",
      del.context.status === "deleted" && del.context.name === rename.context.name,
    );
  }

  // rename-fork: 両 branch とも署名有効・同一座標・prev 同一で signed_bytes が異なる
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

  // name-swap: 正規 2 本は有効、name フィールドだけ入れ替えたバイト列では署名失敗
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

  // tenure-extension: 派生チェーンの seq 13 エントリ自体が有効(value-signature と同一内容)
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
    if (n.kind === "authorization") {
      // 検証規則系は「暗号学的には有効(署名が正しい)」ことを確認する。
      // expected_reason での拒否は実装テスト(§6.3 の履歴検証)が担う
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
  // nfc-variant: NFC 正規形で署名された name の NFD 変種は byte 列が異なることの固定
  {
    const nfc = doc.negative.find((n) => n.name === "nfc-variant");
    check(
      "meta-sig nfc-variant: negative name is non-NFC variant of the signed name",
      nfc.context.name.normalize("NFC") === byName.get("var-nfc-name").context.name &&
        nfc.context.name !== byName.get("var-nfc-name").context.name,
    );
  }
}

// --- env-manifest.json ---------------------------------------------------------
{
  const doc = read("env-manifest.json");
  const chain = read("chain-entries.json");
  const projectId = chain.entries[0].entry_hash_hex;
  const sha256hex = async (u8) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", u8)));
  const importSigPub = (hex) =>
    crypto.subtle.importKey("raw", fromHex(hex), "Ed25519", false, ["verify"]);
  // 検証は仕様ハードコードの順序で行い、JSON の宣言はそれとの一致を検査する
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

  // ダイジェストの LP 正規形(空集合・単一・tombstone・バイト昇順)
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
    // ダイジェスト再計算(§4.3 (3)): entries はマニフェストが署名した集合の正規形
    check(
      `env-manifest ${label}: variables digest recomputation`,
      (await digestHex(v.entries)) === ctx.variables_digest_hex,
    );
    const issuerKeys = chain.keys[ctx.issuer_user_id];
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
      v.context.chain_head_hash_hex === chain.entries[v.context.chain_head_seq - 1].entry_hash_hex,
    );
    // prev 連鎖: prev_base を持つベクターは直前 manifestVersion の signed_bytes ハッシュへ連鎖
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
  // tombstone 込みダイジェスト(§4.3): manifest-var-delete は deleted entry を列挙に含む
  {
    const del = byName.get("manifest-var-delete");
    check(
      "env-manifest manifest-var-delete: digest includes the tombstone",
      del.entries.some((e) => e.status === "deleted"),
    );
  }

  // fork: 両 branch とも署名有効・同一座標・prev 同一で signed_bytes が異なる
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
      // 検証規則系は「暗号学的には有効(署名が正しい)」ことを確認する。
      // expected_reason での拒否は実装テスト(§6.3 の履歴検証)が担う
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
      // ダイジェスト系: verify_entries(検証側集合)での再計算は署名済み
      // ダイジェストと一致しない(欠落・tombstone 隠し・順序違反の固定)
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
  // digest-order-swap: 署名されたダイジェストは同一集合の**非正規順**での計算値
  {
    const swap = doc.negative.find((n) => n.name === "digest-order-swap");
    check(
      "env-manifest digest-order-swap: signed digest is the descending-order value",
      (await digestHex(swap.entries.toReversed(), false)) === swap.context.variables_digest_hex &&
        (await digestHex(swap.entries)) !== swap.context.variables_digest_hex,
    );
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
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  // KeyPair 渡しの Open を標準とする(CRYPTO_SPEC §2。非抽出鍵と両立する経路)。
  // 受信者クラスごとに鍵ペアを解決する(basic = メンバー鍵、server-basic = サーバー鍵)
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
  // サーバー鍵 FP: SHA-256(pkSm)[:16](§9)と info の recipient 位置の一致
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

// --- lease-wrap.json(panva hpke で Open)-------------------------------------
// §9.1 のリースラップ。dek-wrap と同じ「生成 = hpke-js / 検証 = panva」の
// 突き合わせに加えて、(1) claims_digest の LP + SHA-256 を WebCrypto で独立に
// 再計算し、(2) info が仕様のフィールド順で組まれていること、(3) 座標と DEK が
// dek-wrap.json の server-basic を引き継いでいること(サーバーが自分宛ラップを
// 開封して再ラップした形)を検査する
{
  const doc = read("lease-wrap.json");
  const dekWrap = read("dek-wrap.json");
  const suite = new HPKE.CipherSuite(
    HPKE.KEM_DHKEM_X25519_HKDF_SHA256,
    HPKE.KDF_HKDF_SHA256,
    HPKE.AEAD_AES_256_GCM,
  );
  // KeyPair 渡しの Open(CRYPTO_SPEC §2。非抽出鍵と両立する経路)
  const workloadKeyPair = {
    privateKey: await suite.DeserializePrivateKey(fromHex(doc.workload_keypair.skWm_hex), false),
    publicKey: await suite.DeserializePublicKey(fromHex(doc.workload_keypair.pkWm_hex)),
  };
  const vectorByName = (name) => doc.vectors.find((v) => v.name === name);

  // claims_digest = lower_hex(SHA-256(LP(domain, issuer_url, subject, audience)))
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

  // 座標・DEK の引き継ぎ(§9.1 の「サーバーは DEK の仲介者」の実データ表現)
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
    // info はベクター宣言でなく仕様のフィールド順から組み直して照合する
    // (JSON 由来の順序で検証すると順序を独立に固定できない — session-15 レビュー③)
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

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall vectors verified");
