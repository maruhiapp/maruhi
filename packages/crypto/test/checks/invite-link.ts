// CRYPTO_SPEC §6.5(IV — リンク鍵の導出・発行署名・OpenSSH 公開鍵行)のチェック。
// 発行署名は Ed25519 の決定論性により署名方向もベクターと完全一致で検証する。
// negative は「ベクターの verify_signed_bytes_hex を実装の正規化が再現し、その上で
// 元の署名が検証に失敗する」ことを固定する。OpenSSH の解析は第三者データ
// (GitHub 応答)の復号なので、受理境界(種別・鍵長・blob 内種別・余分なバイト・
// base64)をベクターで固定する。

import {
  buildInviteIssueSignedBytes,
  deriveInviteLinkKeyPair,
  encodeOpenSshEd25519PublicKey,
  generateInviteLinkSeed,
  generateSigningKeyPair,
  importSigningKeyPair,
  importSigningPublicKey,
  INVITE_LINK_SEED_BYTES,
  type InviteIssueContext,
  parseOpenSshEd25519PublicKey,
  type ScopeKind,
  signInviteIssue,
  verifyInviteIssueSignature,
} from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import vectors from "../../test-vectors/invite-link.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = vectors.issue.vectors[0];
if (baseVector === undefined) {
  throw new Error("invite-link.json: basic issue vector missing");
}
const base = baseVector;

interface VectorContext {
  readonly suite: string;
  readonly invite_id: string;
  readonly project_id: string;
  readonly link_pub_hex: string;
  readonly head_hash_hex: string;
  readonly head_seq: number;
  readonly role: string;
  readonly inviter_user_id: string;
  readonly inviter_enc_pub_hex: string;
  readonly inviter_sig_pub_hex: string;
  readonly scope_kind: string;
  readonly scope_environments: readonly string[];
}

function contextOf(v: VectorContext): InviteIssueContext {
  return {
    suite: v.suite,
    inviteId: v.invite_id,
    projectId: v.project_id,
    linkPubHex: v.link_pub_hex,
    headHashHex: v.head_hash_hex,
    headSeq: v.head_seq,
    role: v.role,
    inviterUserId: v.inviter_user_id,
    inviterEncPubHex: v.inviter_enc_pub_hex,
    inviterSigPubHex: v.inviter_sig_pub_hex,
    // scope(2026-09-14 ES — §6.5 の発行文末尾 2 フィールド)
    scopeKind: v.scope_kind as ScopeKind,
    scopeEnvironmentIds: v.scope_environments,
  };
}

async function linkKeyChecks(c: Checks): Promise<void> {
  for (const [label, key] of [
    ["link_key", vectors.link_key],
    ["other_link_key", vectors.other_link_key],
  ] as const) {
    const derived = await deriveInviteLinkKeyPair(fromHex(key.seed_hex));
    c.push(
      `invite-link: ${label} derived from seed`,
      derived.ok && toHex(derived.value.publicKeyRaw) === key.pub_hex,
    );
    // 導出した公開鍵オブジェクトも raw と一致する(2 回の import の整合)
    if (derived.ok) {
      const exported = new Uint8Array(
        await crypto.subtle.exportKey("raw", derived.value.publicKey),
      );
      c.push(`invite-link: ${label} public CryptoKey matches raw`, toHex(exported) === key.pub_hex);
    }
  }
  const generated = generateInviteLinkSeed();
  c.push(
    "invite-link: generated seed length",
    generated.length === INVITE_LINK_SEED_BYTES && generated.some((b) => b !== 0),
  );
  const short = await deriveInviteLinkKeyPair(new Uint8Array(31));
  c.push("invite-link: short seed rejected", !short.ok && short.error.kind === "InvalidInput");
}

async function issueVectorChecks(c: Checks): Promise<void> {
  const ownerKeys = chainVectors.keys["user-owner-0001"];
  const inviter = await importSigningKeyPair({
    publicKey: fromHex(ownerKeys.sig_pub_hex),
    privateSeed: fromHex(ownerKeys.sig_sk_seed_hex),
  });
  if (!inviter.ok) {
    c.push("invite-issue-sig: vector keys", false, "inviter key import failed");
    return;
  }
  const head = chainVectors.entries[chainVectors.entries.length - 1];
  c.push(
    "invite-issue-sig: inviter and head come from the canonical chain",
    base.inviter_sig_pub_hex === ownerKeys.sig_pub_hex &&
      base.inviter_enc_pub_hex === ownerKeys.enc_pub_hex &&
      head !== undefined &&
      base.head_hash_hex === head.entry_hash_hex &&
      base.head_seq === head.seq,
  );
  await issuePositiveChecks(c, inviter.value.privateKey);
  await issueNegativeChecks(c);
}

async function issuePositiveChecks(c: Checks, signingKey: CryptoKey): Promise<void> {
  for (const vector of vectors.issue.vectors) {
    const context = contextOf(vector);
    const signed = await signInviteIssue({ context, signingKey });
    const verified = await verifyInviteIssueSignature({
      context,
      signatureHex: vector.signature_hex,
    });
    c.push(
      `invite-issue-sig: ${vector.name} signed bytes construction`,
      toHex(buildInviteIssueSignedBytes(context)) === vector.signed_bytes_hex,
    );
    c.push(
      `invite-issue-sig: ${vector.name} sign == signature`,
      signed.ok && signed.value === vector.signature_hex,
    );
    c.push(`invite-issue-sig: ${vector.name} verify`, verified.ok);
  }
}

interface IssueNegative {
  readonly name: string;
  /** "encoding" = この実装からは生成されないバイト列(旧形式・平坦化)。無指定 = 改竄・移植。 */
  readonly kind?: string;
  readonly context: VectorContext;
  readonly signature_hex: string;
  readonly verify_key_hex: string;
  readonly verify_signed_bytes_hex: string;
}

async function issueNegativeChecks(c: Checks): Promise<void> {
  const seenKinds = new Set<string>();
  for (const negative of vectors.issue.negative as readonly IssueNegative[]) {
    seenKinds.add(negative.kind ?? "signature");
    if (negative.kind === "encoding") {
      await issueEncodingNegativeCheck(c, negative);
      continue;
    }
    const context = contextOf(negative.context);
    const result = await verifyInviteIssueSignature({
      context,
      signatureHex: negative.signature_hex,
    });
    c.push(
      `invite-issue-sig negative: ${negative.name}`,
      toHex(buildInviteIssueSignedBytes(context)) === negative.verify_signed_bytes_hex &&
        negative.verify_key_hex === negative.context.inviter_sig_pub_hex &&
        !result.ok &&
        result.error.kind === "InviteIssueSignatureInvalid",
    );
  }
  c.push(
    "invite-issue-sig negative: kind vocabulary is exhaustive",
    [...seenKinds].every((kind) => kind === "signature" || kind === "encoding"),
  );
}

/**
 * 符号化系 negative(scope を欠く旧 10 フィールド形式・scope の平坦連結): 正規化は
 * ベクターのバイト列を**生まず**、かつそのバイト列上では正規の発行署名が検証に失敗する
 * ことを固定する(README 規約 27 — 互換受理の経路を持たない。chain-entries の
 * flat-concat と同型)
 */
async function issueEncodingNegativeCheck(c: Checks, negative: IssueNegative): Promise<void> {
  const context = contextOf(negative.context);
  const differs = toHex(buildInviteIssueSignedBytes(context)) !== negative.verify_signed_bytes_hex;
  const key = await importSigningPublicKey(fromHex(negative.verify_key_hex));
  if (!key.ok) {
    c.push(`invite-issue-sig negative: ${negative.name}`, false, "verify key import failed");
    return;
  }
  const verified = await crypto.subtle.verify(
    "Ed25519",
    key.value,
    fromHex(negative.signature_hex) as BufferSource,
    fromHex(negative.verify_signed_bytes_hex) as BufferSource,
  );
  c.push(
    `invite-issue-sig negative: ${negative.name}`,
    differs && negative.verify_key_hex === negative.context.inviter_sig_pub_hex && !verified,
  );
}

async function issueInvalidInputChecks(c: Checks): Promise<void> {
  const pair = await generateSigningKeyPair();
  const badContexts: readonly { name: string; context: InviteIssueContext }[] = [
    { name: "empty suite", context: { ...contextOf(base), suite: "" } },
    { name: "empty invite id", context: { ...contextOf(base), inviteId: "" } },
    { name: "empty role", context: { ...contextOf(base), role: "" } },
    { name: "empty inviter", context: { ...contextOf(base), inviterUserId: "" } },
    {
      name: "uppercase link pub",
      context: { ...contextOf(base), linkPubHex: base.link_pub_hex.toUpperCase() },
    },
    { name: "short head hash", context: { ...contextOf(base), headHashHex: "ab" } },
    { name: "zero head seq", context: { ...contextOf(base), headSeq: 0 } },
    { name: "fractional head seq", context: { ...contextOf(base), headSeq: 1.5 } },
    {
      name: "unsafe head seq",
      context: { ...contextOf(base), headSeq: Number.MAX_SAFE_INTEGER + 1 },
    },
    { name: "short inviter enc pub", context: { ...contextOf(base), inviterEncPubHex: "ab" } },
    { name: "short inviter sig pub", context: { ...contextOf(base), inviterSigPubHex: "ab" } },
    // scope の構造規則(§6.2 と同じ — all ⇒ 空リスト、重複なし、閉集合の kind、非空 id)
    {
      name: "all scope with environments",
      context: { ...contextOf(base), scopeKind: "all", scopeEnvironmentIds: ["env-dev-0002"] },
    },
    {
      name: "duplicate scope environment",
      context: {
        ...contextOf(base),
        scopeKind: "listed",
        scopeEnvironmentIds: ["env-dev-0002", "env-dev-0002"],
      },
    },
    {
      name: "empty scope environment id",
      context: { ...contextOf(base), scopeKind: "listed", scopeEnvironmentIds: [""] },
    },
    {
      name: "unknown scope kind",
      context: { ...contextOf(base), scopeKind: "some" as ScopeKind, scopeEnvironmentIds: [] },
    },
    // id の上限(§6.1 の 1024 バイト — チェーン側の add_member と対称)
    {
      name: "oversized scope environment id",
      context: {
        ...contextOf(base),
        scopeKind: "listed",
        scopeEnvironmentIds: ["e".repeat(1025)],
      },
    },
  ];
  for (const bad of badContexts) {
    const signed = await signInviteIssue({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyInviteIssueSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
    });
    c.push(
      `invite-issue-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  const shortSignature = await verifyInviteIssueSignature({
    context: contextOf(base),
    signatureHex: "ab".repeat(63),
  });
  c.push(
    "invite-issue-sig invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

async function issueRoundtripChecks(c: Checks): Promise<void> {
  const inviter = await generateSigningKeyPair();
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", inviter.publicKey));
  const context: InviteIssueContext = { ...contextOf(base), inviterSigPubHex: toHex(rawPub) };
  const signed = await signInviteIssue({ context, signingKey: inviter.privateKey });
  if (!signed.ok) {
    c.push("invite-issue-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyInviteIssueSignature({ context, signatureHex: signed.value });
  c.push("invite-issue-sig: roundtrip", verified.ok);
  // 別の招待 id へ移植すると検証失敗(サーバーが発行文を別行へ移植できない)
  const transplanted = await verifyInviteIssueSignature({
    context: { ...context, inviteId: "invite-other" },
    signatureHex: signed.value,
  });
  c.push("invite-issue-sig: roundtrip transplanted invite id rejected", !transplanted.ok);
  // ゴースト追加者の形: 宣言鍵を招待者の公開鍵にしても、別鍵の署名は通らない
  const ghost = await generateSigningKeyPair();
  const ghostSigned = await signInviteIssue({ context, signingKey: ghost.privateKey });
  const ghostVerified = ghostSigned.ok
    ? await verifyInviteIssueSignature({ context, signatureHex: ghostSigned.value })
    : ghostSigned;
  c.push("invite-issue-sig: roundtrip ghost signer rejected", !ghostVerified.ok);
}

function opensshChecks(c: Checks): void {
  opensshVectorChecks(c);
  opensshRoundtripChecks(c);
  // 解析の拒否(規約 21: 実装ハーネスで固定 — ベクターの負例に無い形)
  for (const [name, input] of rejectedOpenSshInputs()) {
    const rejectedParse = parseOpenSshEd25519PublicKey(input as string);
    c.push(
      `openssh: parse rejects ${name}`,
      !rejectedParse.ok && rejectedParse.error.kind === "InvalidInput",
    );
  }
}

function opensshVectorChecks(c: Checks): void {
  for (const vector of vectors.openssh.encode) {
    const encoded = encodeOpenSshEd25519PublicKey(fromHex(vector.public_key_hex));
    c.push(`openssh: encode ${vector.name}`, encoded.ok && encoded.value === vector.expected_line);
  }
  for (const vector of vectors.openssh.parse) {
    const parsed = parseOpenSshEd25519PublicKey(vector.line);
    c.push(
      `openssh: parse ${vector.name}`,
      parsed.ok && toHex(parsed.value) === vector.expected_public_key_hex,
    );
  }
  for (const negative of vectors.openssh.parse_negative) {
    const parsed = parseOpenSshEd25519PublicKey(negative.line);
    c.push(
      `openssh: parse negative ${negative.name}`,
      !parsed.ok && parsed.error.kind === "InvalidInput",
    );
  }
}

function opensshRoundtripChecks(c: Checks): void {
  // 符号化 → 解析の往復(生成鍵)と、鍵長違いの符号化拒否
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const encoded = encodeOpenSshEd25519PublicKey(raw);
  const parsed = encoded.ok ? parseOpenSshEd25519PublicKey(encoded.value) : encoded;
  c.push("openssh: roundtrip", parsed.ok && toHex(parsed.value) === toHex(raw));
  const shortKey = encodeOpenSshEd25519PublicKey(new Uint8Array(31));
  c.push("openssh: encode short key rejected", !shortKey.ok);
}

/** ベクターの正例を素材にした拒否入力(型ずれ・長さ・アルファベット・空白)。 */
function rejectedOpenSshInputs(): readonly (readonly [string, unknown])[] {
  const good = vectors.openssh.parse[0];
  if (good === undefined) {
    throw new Error("openssh parse vector missing");
  }
  const [type = "", text = ""] = good.line.split(" ");
  const line = `${type} ${text}`;
  const blob = base64ToBytes(text);
  const withBlob = (bytes: Uint8Array) => `${type} ${bytesToBase64(bytes)}`;
  // 33 バイトの鍵(内側の長さ接頭辞も 33 に合わせる)
  const longKey = new Uint8Array(blob.length + 1);
  longKey.set(blob);
  longKey[4 + 11 + 3] = 33;
  // 内側の種別長さ接頭辞だけ 10 にし、全長は保つ
  const badInnerLength = new Uint8Array(blob);
  badInnerLength[3] = 10;
  return [
    ["non-string input (null)", null],
    ["non-string input (number)", 42],
    ["33-byte key", withBlob(longKey)],
    ["inner type length mismatch with same total length", withBlob(badInnerLength)],
    // base64url だけの文字(- _)は標準アルファベット外(長さは保つ)
    ["base64url alphabet", `${type} -_${text.slice(2)}`],
    ["whitespace inside the base64", `${type} ${text.slice(0, 10)} ${text.slice(10)}`],
    ["leading space", ` ${line}`],
    ["tab separator", line.replace(" ", "\t")],
    ["newline inside the line", `${type}\n${text}`],
    ["oversize base64 (rejected before decoding)", `${type} ${"A".repeat(4 * 1024 * 1024)}`],
  ];
}

function base64ToBytes(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export async function inviteLinkChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await linkKeyChecks(c);
  await issueVectorChecks(c);
  await issueInvalidInputChecks(c);
  await issueRoundtripChecks(c);
  opensshChecks(c);
  return c.results;
}
