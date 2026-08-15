// lease-wrap.json(CRYPTO_SPEC §9.1)の参照生成器。
// dek-wrap.json と同じ理由で hpke-js を使う: 製品実装が採用する panva hpke とは
// 独立の実装系であり、ekm による derandomize で Seal 方向を決定論的に固定できる
// (panva では不可。docs/notes/spike-c.md)。
// 使い捨ての参照ツールであり、製品コードではない。鍵・値はすべてダミー。
//
// dek-wrap.json を読み、その `server-basic`(サーバー鍵宛の永続ラップ)と
// **同一の座標・同一の DEK** をワークロード一時鍵へ再ラップする形で生成する。
// 「サーバーが自分宛ラップを開封し、同じ DEK をワークロードへ再ラップした」
// という受け渡しがベクター上で追跡でき、レビュー時に文脈が閉じる(§9.1 の
// 「サーバーは値を復号しない = DEK の仲介者」の実データ表現)。
//
// 再生成: bun install && bun run generate(このディレクトリで実行。
// generate-dek-wrap.mjs → 本ファイル → generate_reference.py の順が正)
import { readFileSync, writeFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

// CRYPTO_SPEC §2.1 の長さプレフィックス付きエンコーディング
// (generate-dek-wrap.mjs / generate_reference.py / verify_reference.mjs と同一定義。
// tools/ は使い捨てのため、共有モジュール化せず各ファイルに独立の定義を置く既存慣行に従う)
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

// --- dek-wrap.json から座標と DEK を引き継ぐ ---------------------------------
const dekWrapDoc = JSON.parse(readFileSync(new URL("../dek-wrap.json", import.meta.url), "utf8"));
const serverWrap = dekWrapDoc.vectors.find((v) => v.name === "server-basic");
if (serverWrap === undefined) {
  throw new Error("dek-wrap.json is missing the server-basic vector");
}
const projectId = serverWrap.project_id;
const environmentId = serverWrap.environment_id;
const epoch = serverWrap.epoch;
const dek = fromHex(serverWrap.dek_hex);

// 応答内の過去エポック分(§14-2: 最新値が使用する全エポック + 現エポック)を
// 表す 2 本目の正例。エポックごとに DEK は独立であることを実データで示す
const priorEpoch = epoch - 1;
const priorDek = pat(0xe0, 32);

// --- ワークロードの一時鍵(§9.1: メモリ内生成・ジョブ終了で破棄)-------------
// ベクターでは決定論のため固定 ikm からの DeriveKeyPair とする(実運用の一時鍵は
// 毎回ランダム生成される — 決定論化はベクター固有の都合であり仕様ではない)
const ikmW = pat(0xd0, 32);
const kpW = await suite.kem.deriveKeyPair(ikmW.slice().buffer);
const pkWm = new Uint8Array(await suite.kem.serializePublicKey(kpW.publicKey));
const skWm = new Uint8Array(await suite.kem.serializePrivateKey(kpW.privateKey));

// --- claims_digest(§9.1)-----------------------------------------------------
// claims_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/lease-claims",
//                                          issuer_url, subject, audience)))
const CLAIMS_DOMAIN = "maruhi/v1/lease-claims";
const issuerUrl = "https://token.actions.githubusercontent.com";
const audience = "https://maruhi.example";
const subject = "repo:maruhi-example/demo:ref:refs/heads/main";
// 別ワークロード文脈(同一 issuer / audience・別ブランチ)。リース応答の転用が
// 復号失敗になることを固定する負例の材料
const otherSubject = "repo:maruhi-example/demo:ref:refs/heads/feature-x";

async function claimsDigest(sub) {
  const lp = lpEncode([CLAIMS_DOMAIN, issuerUrl, sub, audience]);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", lp.slice()));
  return { lpHex: hex(lp), digestHex: hex(digest) };
}

const claims = await claimsDigest(subject);
const otherClaims = await claimsDigest(otherSubject);

// --- リースラップ(§9.1)------------------------------------------------------
// info = LP("maruhi/v1/lease-wrap", project_id, environment_id, epoch, claims_digest_hex)
const LEASE_DOMAIN = "maruhi/v1/lease-wrap";
const DEK_WRAP_DOMAIN = "maruhi/v1/dek-wrap";
const leaseInfo = (proj, env, ep, digestHex) => lpEncode([LEASE_DOMAIN, proj, env, ep, digestHex]);

const info = leaseInfo(projectId, environmentId, epoch, claims.digestHex);
const priorInfo = leaseInfo(projectId, environmentId, priorEpoch, claims.digestHex);
const aad = new Uint8Array(0); // §5 と同じ: 文脈束縛は info が担う。aad は空

const ikmE = pat(0xf0, 32);
const ikmE2 = pat(0x40, 32); // Seal ごとに独立の ekm

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
    "CRYPTO_SPEC §9.1: ワークロードリースのリースラップ(HPKE Base mode 単発 Seal、§5 と同一プリミティブ)。info に claims_digest を束縛し、リース応答の別ワークロード文脈への転用を復号失敗にする。Seal は hpke-js の ekm derandomize で固定(panva 実装は Open 方向 + ラウンドトリップで検証する)",
  info_fields_order: ["domain", "project_id", "environment_id", "epoch", "claims_digest_hex"],
  claims_digest_fields_order: ["domain", "issuer_url", "subject", "audience"],
  persistence_note:
    "リースラップは永続化しない(dek_wraps に入らない — §9.1)。応答スコープのみに存在するため、§5.1 の登録署名は伴わない(署名者はチェーン上のメンバーであり、サーバー生成のラップに帰属署名は存在しえない)",
  provenance_note:
    "座標(project / environment / epoch)と basic の DEK は dek-wrap.json の server-basic と同一。サーバーが自分宛ラップを開封し、同じ DEK をワークロード一時鍵へ再ラップした形を実データで表す(§9.1 — サーバーは値を復号しない)",
  workload_keypair: {
    ikmW_hex: hex(ikmW),
    skWm_hex: hex(skWm),
    pkWm_hex: hex(pkWm),
    note: "ワークロードの一時 X25519 鍵。ベクターの決定論のため DeriveKeyPair(ikmW) で固定するが、実運用では毎回ランダム生成しジョブ終了とともに破棄する(§9.1)",
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
    note: "claims_digest_hex = lower_hex(SHA-256(LP(domain, issuer_url, subject, audience)))。検証済み OIDC トークンの issuer / sub / aud から、サーバーとワークロードが独立に同じ値を計算する。other_* は同一 issuer / audience・別 subject(別ブランチ)の文脈で、info-claims-digest-mismatch の材料",
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
      note: "現エポックのリースラップ。DEK は dek-wrap.json の server-basic と同一(サーバーが開封して再ラップした DEK)",
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
      note: "同一リース応答に含まれる過去エポック分(§14-2: 最新値が使用する全エポック + 現エポック)。エポックごとに DEK も info も独立であることを固定する",
    },
  ],
  negative: [
    {
      name: "info-project-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo("proj-0002", environmentId, epoch, claims.digestHex)),
      must_fail: true,
      note: "別プロジェクトへの移植は Open 失敗",
    },
    {
      name: "info-environment-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo(projectId, "env-dev-0002", epoch, claims.digestHex)),
      must_fail: true,
      note: "別環境への移植は Open 失敗(開示スコープを跨いだ再利用の遮断)",
    },
    {
      name: "info-epoch-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo(projectId, environmentId, epoch + 1, claims.digestHex)),
      must_fail: true,
      note: "別エポックへの移植は Open 失敗",
    },
    {
      name: "info-claims-digest-mismatch",
      base: "basic",
      open_info_hex: hex(leaseInfo(projectId, environmentId, epoch, otherClaims.digestHex)),
      must_fail: true,
      note: "別ワークロード文脈(同一 issuer / audience・別 subject)の claims_digest では Open 失敗。リース応答を別ジョブへ転用できないことの中核(§9.1)",
    },
    {
      name: "info-dek-wrap-domain",
      base: "basic",
      open_info_hex: hex(
        lpEncode([DEK_WRAP_DOMAIN, projectId, environmentId, epoch, claims.digestHex]),
      ),
      must_fail: true,
      note: "ドメイン文字列を §5 の dek-wrap に差し替えた info では Open 失敗(永続ラップとリースラップのドメイン分離)",
    },
  ],
};

writeFileSync(
  new URL("../lease-wrap.json", import.meta.url),
  `${JSON.stringify(vector, null, 2)}\n`,
);
console.log("wrote lease-wrap.json");
