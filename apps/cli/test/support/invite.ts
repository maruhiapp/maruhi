// 招待テスト用の固定材料(CRYPTO_SPEC §6.5 — 2026-09-13 IV 改訂・v2)。
//
// invite / member add / redacted の各テストが同じ形で「招待者が署名した発行文」と
// 「受諾者 + リンク鍵の共同署名つき受諾ブロック」を作れるようにする。種・鍵は
// すべてテスト専用の固定値か生成値(本物のシークレットは置かない)。

import {
  decodeHex,
  deriveInviteLinkKeyPair,
  encodeHex,
  signInviteAccept,
  signInviteIssue,
  signInviteLink,
  SUITE_ID,
} from "@maruhi/crypto";
import { Redacted } from "effect";

import { buildInviteLink, type InviteLinkData, type InviteRole } from "../../src/invite-link.ts";
import type { TestUser } from "./crypto.ts";

/** 固定の招待 id(ULID 形式 — api-schema の InviteIdSchema を満たす)。 */
export const INVITE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
/** 固定のリンク鍵の種(テスト専用のパターン値)。 */
export const LINK_SEED_HEX = "d0".repeat(32);

export interface IssuedInviteFixture {
  /** リンクが運ぶデータ(発行署名済み)。 */
  readonly link: InviteLinkData;
  /** 種から導出したリンク公開鍵(hex)。 */
  readonly linkPubHex: string;
  /** サーバー行の発行文(一覧行 `issuance` にそのまま載せる形)。 */
  readonly issuance: {
    readonly linkPubHex: string;
    readonly headHashHex: string;
    readonly headSeq: number;
    readonly issueSignatureHex: string;
  };
}

/** 招待者のチェーン sig 鍵で発行署名した招待(リンク + 発行文)を作る。 */
export async function issueInviteFixture(input: {
  readonly inviter: TestUser;
  readonly projectId: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly role?: InviteRole;
  readonly inviteId?: string;
  readonly seedHex?: string;
  readonly inviterLogin?: string | null;
}): Promise<IssuedInviteFixture> {
  const role = input.role ?? "member";
  const inviteId = input.inviteId ?? INVITE_ID;
  const seedHex = input.seedHex ?? LINK_SEED_HEX;
  const seed = decodeHex(seedHex);
  if (seed === null) throw new Error("bad seed hex");
  const derived = await deriveInviteLinkKeyPair(seed);
  if (!derived.ok) throw new Error("link key derivation failed");
  const linkPubHex = encodeHex(derived.value.publicKeyRaw);
  const signed = await signInviteIssue({
    context: {
      suite: SUITE_ID,
      inviteId,
      projectId: input.projectId,
      linkPubHex,
      headHashHex: input.headHashHex,
      headSeq: input.headSeq,
      role,
      inviterUserId: input.inviter.userId,
      inviterEncPubHex: input.inviter.encPubHex,
      inviterSigPubHex: input.inviter.sigPubHex,
    },
    signingKey: input.inviter.sigKeyPair.privateKey,
  });
  if (!signed.ok) throw new Error("issue signature failed");
  return {
    link: {
      inviteId,
      linkSeedHex: Redacted.make(seedHex, { label: "invite-link-seed" }),
      projectId: input.projectId,
      headHashHex: input.headHashHex,
      headSeq: input.headSeq,
      inviterUserId: input.inviter.userId,
      inviterEncPubHex: input.inviter.encPubHex,
      inviterSigPubHex: input.inviter.sigPubHex,
      role,
      inviterLogin: input.inviterLogin ?? null,
      issueSignatureHex: signed.value,
    },
    linkPubHex,
    issuance: {
      linkPubHex,
      headHashHex: input.headHashHex,
      headSeq: input.headSeq,
      issueSignatureHex: signed.value,
    },
  };
}

/** 発行済み招待のリンク文字列(表示形)。 */
export function inviteLinkText(origin: string, issued: IssuedInviteFixture): string {
  return Redacted.value(buildInviteLink({ origin, link: issued.link }));
}

/** サーバー一覧行の受諾ブロック(ワイヤ形)。 */
export interface AcceptanceFixture {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

/**
 * 受諾ブロック(受諾署名 + リンク署名の共同署名)。宣言する鍵・署名鍵は既定で
 * 受諾者本人のものだが、鍵流用の形を作るために上書きできる(署名対象は上書き後
 * の宣言鍵で組む — 検証側が「宣言鍵で検証する」ことの固定に使う)。
 */
export async function acceptanceFixture(input: {
  readonly projectId: string;
  readonly issued: IssuedInviteFixture;
  readonly invitee: TestUser;
  readonly inviteeUserId?: string;
  readonly declared?: { readonly encPubHex: string; readonly sigPubHex: string };
  readonly signer?: TestUser;
}): Promise<AcceptanceFixture> {
  const seed = decodeHex(Redacted.value(input.issued.link.linkSeedHex));
  if (seed === null) throw new Error("bad seed hex");
  const derived = await deriveInviteLinkKeyPair(seed);
  if (!derived.ok) throw new Error("link key derivation failed");
  const context = {
    suite: SUITE_ID,
    projectId: input.projectId,
    linkPubHex: input.issued.linkPubHex,
    inviteeUserId: input.inviteeUserId ?? input.invitee.userId,
    inviteeEncPubHex: input.declared?.encPubHex ?? input.invitee.encPubHex,
    inviteeSigPubHex: input.declared?.sigPubHex ?? input.invitee.sigPubHex,
  };
  const signature = await signInviteAccept({
    context,
    signingKey: (input.signer ?? input.invitee).sigKeyPair.privateKey,
  });
  const linkSignature = await signInviteLink({
    context,
    linkPrivateKey: derived.value.privateKey,
  });
  if (!signature.ok || !linkSignature.ok) throw new Error("acceptance signatures failed");
  return {
    inviteeUserId: context.inviteeUserId,
    inviteeEncPubHex: context.inviteeEncPubHex,
    inviteeSigPubHex: context.inviteeSigPubHex,
    signatureHex: signature.value,
    linkSignatureHex: linkSignature.value,
    acceptedAtMs: 1755300000000,
  };
}

/** 署名 hex の先頭バイトを反転する(改竄した署名の形)。 */
export function flipHex(hex: string): string {
  const first = Number.parseInt(hex.slice(0, 2), 16) ^ 0x01;
  return first.toString(16).padStart(2, "0") + hex.slice(2);
}
