// CRYPTO_SPEC §6.5(招待受諾署名)のチェック。
// Ed25519 は RFC 8032 の決定論的署名なので、署名方向もベクターと完全一致で検証する。
// negative は「ベクターの verify_signed_bytes_hex を実装の正規化が再現し、
// その上で元の署名が検証に失敗する」ことを固定する(改竄・別招待への移植・
// 鍵不一致・署名者不一致・suite 不一致)。検証鍵は署名対象内の
// invitee_sig_pub_hex から実装が自分で導く(自己束縛 — 外から鍵を渡す口はない)。

import {
  buildInviteAcceptSignedBytes,
  generateSigningKeyPair,
  importSigningKeyPair,
  type InviteAcceptSignatureContext,
  signInviteAccept,
  verifyInviteAcceptSignature,
} from "../../src/index.ts";
import vectors from "../../test-vectors/invite-accept-signature.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = vectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("invite-accept-signature.json: basic vector missing");
}
const base = baseVector;

interface VectorContext {
  readonly suite: string;
  readonly project_id: string;
  readonly invite_token_hash_hex: string;
  readonly invitee_user_id: string;
  readonly invitee_enc_pub_hex: string;
  readonly invitee_sig_pub_hex: string;
}

function contextOf(v: VectorContext): InviteAcceptSignatureContext {
  return {
    suite: v.suite,
    projectId: v.project_id,
    inviteTokenHashHex: v.invite_token_hash_hex,
    inviteeUserId: v.invitee_user_id,
    inviteeEncPubHex: v.invitee_enc_pub_hex,
    inviteeSigPubHex: v.invitee_sig_pub_hex,
  };
}

async function vectorChecks(c: Checks): Promise<void> {
  const invitee = await importSigningKeyPair({
    publicKey: fromHex(vectors.invitee.sig_pub_hex),
    privateSeed: fromHex(vectors.invitee.sig_sk_seed_hex),
  });
  if (!invitee.ok) {
    c.push("invite-accept-sig: vector keys", false, "invitee key import failed");
    return;
  }
  // トークンハッシュの導出(SHA-256(生トークン))がベクターの宣言と一致
  const tokenHash = toHex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", fromHex(vectors.invite_token_hex) as BufferSource),
    ),
  );
  c.push("invite-accept-sig: token hash derivation", tokenHash === base.invite_token_hash_hex);
  // Ed25519 は決定論的なので署名方向も完全一致(算出 → まとめて判定の順)
  for (const vector of vectors.vectors) {
    const builtHex = toHex(buildInviteAcceptSignedBytes(contextOf(vector)));
    const signed = await signInviteAccept({
      context: contextOf(vector),
      signingKey: invitee.value.privateKey,
    });
    const verified = await verifyInviteAcceptSignature({
      context: contextOf(vector),
      signatureHex: vector.signature_hex,
    });
    c.push(
      `invite-accept-sig: ${vector.name} signed bytes construction`,
      builtHex === vector.signed_bytes_hex,
    );
    c.push(
      `invite-accept-sig: ${vector.name} sign == signature`,
      signed.ok && signed.value === vector.signature_hex,
    );
    c.push(`invite-accept-sig: ${vector.name} verify`, verified.ok);
  }
}

async function negativeChecks(c: Checks): Promise<void> {
  for (const negative of vectors.negative) {
    const context = contextOf(negative.context);
    const result = await verifyInviteAcceptSignature({
      context,
      signatureHex: negative.signature_hex,
    });
    // (1) 実装の正規化がベクターの検証側バイト列を再現し、(2) 検証鍵は常に
    // 署名対象内の宣言鍵(ベクター側の自己束縛不変条件の再確認)、(3) その上で
    // 検証が InviteAcceptSignatureInvalid で失敗すること
    c.push(
      `invite-accept-sig negative: ${negative.name}`,
      toHex(buildInviteAcceptSignedBytes(context)) === negative.verify_signed_bytes_hex &&
        negative.verify_key_hex === negative.context.invitee_sig_pub_hex &&
        !result.ok &&
        result.error.kind === "InviteAcceptSignatureInvalid",
    );
  }
}

async function invalidInputChecks(c: Checks): Promise<void> {
  const pair = await generateSigningKeyPair();
  // hex が大文字・長さ不正 / suite・invitee_user_id が空なら InvalidInput
  const badContexts: readonly { name: string; context: InviteAcceptSignatureContext }[] = [
    {
      name: "uppercase token hash",
      context: {
        ...contextOf(base),
        inviteTokenHashHex: base.invite_token_hash_hex.toUpperCase(),
      },
    },
    { name: "short token hash", context: { ...contextOf(base), inviteTokenHashHex: "ab" } },
    { name: "short enc pub", context: { ...contextOf(base), inviteeEncPubHex: "ab" } },
    { name: "short sig pub", context: { ...contextOf(base), inviteeSigPubHex: "ab" } },
    { name: "empty suite", context: { ...contextOf(base), suite: "" } },
    { name: "empty invitee", context: { ...contextOf(base), inviteeUserId: "" } },
  ];
  for (const bad of badContexts) {
    const signed = await signInviteAccept({ context: bad.context, signingKey: pair.privateKey });
    const verified = await verifyInviteAcceptSignature({
      context: bad.context,
      signatureHex: base.signature_hex,
    });
    c.push(
      `invite-accept-sig invalid input: ${bad.name}`,
      !signed.ok &&
        signed.error.kind === "InvalidInput" &&
        !verified.ok &&
        verified.error.kind === "InvalidInput",
    );
  }
  // 署名 hex の長さ不正も InvalidInput(64 バイト固定)
  const shortSignature = await verifyInviteAcceptSignature({
    context: contextOf(base),
    signatureHex: "ab".repeat(63),
  });
  c.push(
    "invite-accept-sig invalid input: short signature",
    !shortSignature.ok && shortSignature.error.kind === "InvalidInput",
  );
}

async function roundtripChecks(c: Checks): Promise<void> {
  // 新規生成鍵での往復: 宣言鍵 = 生成鍵の公開鍵、で署名 → 検証が通る
  const invitee = await generateSigningKeyPair();
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", invitee.publicKey));
  const context: InviteAcceptSignatureContext = {
    ...contextOf(base),
    inviteeSigPubHex: toHex(rawPub),
  };
  const signed = await signInviteAccept({ context, signingKey: invitee.privateKey });
  if (!signed.ok) {
    c.push("invite-accept-sig: roundtrip", false, "sign failed");
    return;
  }
  const verified = await verifyInviteAcceptSignature({ context, signatureHex: signed.value });
  c.push("invite-accept-sig: roundtrip", verified.ok);

  // 宣言鍵を別の鍵にすると検証失敗(自己束縛 — 署名鍵と宣言鍵の不一致は通らない)
  const other = await generateSigningKeyPair();
  const otherPub = new Uint8Array(await crypto.subtle.exportKey("raw", other.publicKey));
  const declaredOther = await verifyInviteAcceptSignature({
    context: { ...context, inviteeSigPubHex: toHex(otherPub) },
    signatureHex: signed.value,
  });
  c.push("invite-accept-sig: roundtrip declared-key swap rejected", !declaredOther.ok);

  // 文脈差し替えは検証失敗(別招待への移植の実装側再確認)
  const wrongContext = await verifyInviteAcceptSignature({
    context: { ...context, projectId: "proj-other" },
    signatureHex: signed.value,
  });
  c.push("invite-accept-sig: roundtrip wrong context rejected", !wrongContext.ok);
}

export async function inviteAcceptSignatureChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorChecks(c);
  await negativeChecks(c);
  await invalidInputChecks(c);
  await roundtripChecks(c);
  return c.results;
}
