// `maruhi invite create|accept|list|revoke`(AUTH_SPEC §15 / CRYPTO_SPEC §6.5 —
// 2026-09-13 IV 改訂)。
//
// - create: 招待 id の採番 → リンク鍵(種 → Ed25519)の生成 → 発行文への発行署名
//   (自分のチェーン sig 鍵)→ 発行(発行文をサーバーへ。秘密は送らない)→ §15-3
//   リンクの組み立て(種 + 発行文 + 署名。アンカー = 発行時点の検証済みヘッド)
//   → 発行ピンの保存(link_pub / role / 宛先 login — member add 時の追加突合)
// - accept: リンク解釈 → 発行署名の検証(機械。失敗 = 受諾しない)→ 招待者 FP の
//   相互確認(§6.5 受諾者側 — チェーンとの機械照合は add_member 後の初回同期 =
//   context.ts)→ 鍵生成〔未生成時・ガード付き〕→ 受諾の共同署名(自分の sig 鍵 +
//   リンク鍵)→ 受諾 → アンカーのピン留め(§6.3 (a) — 受諾成立後のみ)
// - list: 発行文の検証(チェーン導出の招待者鍵)+ 受諾ブロックの §6.5 独立検証
//   (受諾署名 + リンク署名)+ FP ワード表示 + 発行ピン突合
// - revoke: 失効
//
// リンク鍵の種はワイヤ(リンク)と表示にのみ存在し、永続化しない(発行ピンは
// 公開鍵のみ)。サーバーは種を一度も受け取らない。

import {
  ForbiddenError,
  InviteConflictError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
} from "@maruhi/api-schema";
import { ulid } from "@maruhi/core";
import {
  type ChainMember,
  computeUserKeyFingerprint,
  decodeHex,
  deriveInviteLinkKeyPair,
  effectivePermissionOf,
  encodeHex,
  generateInviteLinkSeed,
  type InviteAcceptSignatureContext,
  type MemberScope,
  type ScopeKind,
  type ScopePayloadFields,
  scopePayloadFieldsOf,
  signInviteAccept,
  signInviteIssue,
  signInviteLink,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { Effect, Redacted, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import type { IdentityBacking } from "./config.ts";
import type { CliServices } from "./context.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { devicesOf, ownDeviceByKeys } from "./device-key.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import { buildInviteLink, type InviteLinkData, type InviteRole } from "./invite-link.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { offerGithubRegistration } from "./key-publish.ts";
import { Keychain, masterKeyEntryName } from "./keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { logNote, logWarning } from "./notice.ts";
import { type InvitePins, issuedPinOf, PinStore } from "./pins.ts";
import { describeScope, requireScopeEnvironmentsExist, sameScope, scopeContains } from "./scope.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";
import type { VerifiedProject } from "./sync.ts";

/** アンカーのピン留め失敗の警告(SHOULD 水準の劣化 — 受諾自体は成立済み)。 */
const warnUnpinned = (detail: string) =>
  logWarning(
    `could not pin the invite link anchor (${detail}). The machine check on first sync (CRYPTO_SPEC §6.3 (a)) will not run — be sure to perform the ceremony with the inviter (out-of-band FP word comparison)`,
  );

/** 発行文(一覧応答の行 — §15-1。旧行は null)。 */
export interface InviteIssuance {
  readonly linkPubHex: string;
  readonly headHashHex: string;
  readonly headSeq: number;
  readonly issueSignatureHex: string;
}

/** 招待の受諾ブロック(一覧応答の行 — §15-1)。 */
export interface InviteAcceptance {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly linkSignatureHex: string;
  readonly acceptedAtMs: number;
}

/** 一覧応答の 1 行(api-schema の InvitationSummary と同形)。 */
export interface InvitationRow {
  readonly id: string;
  readonly projectId: string;
  readonly role: InviteRole;
  /** 付与予定 scope(2026-09-14 ES — 発行文の一部。add_member はこの scope で署名する)。 */
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
  readonly status: "pending" | "accepted" | "completed" | "revoked";
  readonly inviterUserId: string;
  readonly issuance: InviteIssuance;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly acceptance: InviteAcceptance | null;
}

/** 招待一覧の取得(invite list / member add の共有プロローグ)。 */
export function listInvitations(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly InvitationRow[], CliError> {
  return client.invites.list({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.invitations),
  );
}

/** 発行文の検証結果(理由は文言へ写す)。 */
export type IssuanceVerdict =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "inviter-not-member" | "signature" };

/**
 * 発行文の検証(CRYPTO_SPEC §6.5): 一覧行の発行文 + 発行署名を、**チェーン導出の
 * 招待者の現鍵**で検証する。招待者が自分なら自分の鍵で「自分が発行した行か」を
 * 確かめることになり(発行ピンに依存しない — 補足 21 裁定 A ⑦)、別の admin が
 * `member add` する場合も同じ検査で行のすり替えを検出できる。
 */
export function verifyIssuance(input: {
  readonly verified: VerifiedProject;
  readonly row: InvitationRow;
}): Effect.Effect<IssuanceVerdict, CliError> {
  return Effect.gen(function* () {
    const { issuance } = input.row;
    const inviter = input.verified.state.members.get(input.row.inviterUserId);
    if (inviter === undefined) {
      return { ok: false, reason: "inviter-not-member" } as const;
    }
    // 発行署名の検証鍵 = 招待者の**現端末のいずれか**(DK K4-16 — 発行文は端末の鍵対を
    // 名指しするので、有効な端末を全部回して 1 つでも検証が通れば本物。失効した端末で
    // 発行された行は通らない = 招待者が発行し直す)
    for (const inviterDevice of devicesOf(inviter)) {
      const verified = yield* Effect.tryPromise({
        try: () =>
          verifyInviteIssueSignature({
            context: {
              suite: SUITE_ID,
              inviteId: input.row.id,
              projectId: input.verified.projectId,
              linkPubHex: issuance.linkPubHex,
              headHashHex: issuance.headHashHex,
              headSeq: issuance.headSeq,
              role: input.row.role,
              inviterUserId: inviter.userId,
              inviterEncPubHex: inviterDevice.encPubHex,
              inviterSigPubHex: inviterDevice.sigPubHex,
              scopeKind: input.row.scopeKind,
              scopeEnvironmentIds: input.row.scopeEnvironmentIds,
            },
            signatureHex: issuance.issueSignatureHex,
          }),
        catch: () => cliError("Failed to verify the issue signature (crypto error)"),
      });
      if (verified.ok) {
        return { ok: true } as const;
      }
    }
    return { ok: false, reason: "signature" } as const;
  });
}

/** 発行文の検証失敗の文言(list / member add で共用)。 */
export function issuanceFailureText(
  reason: Exclude<IssuanceVerdict, { ok: true }>["reason"],
): string {
  switch (reason) {
    case "inviter-not-member":
      return "names an inviter who is not a current member of this project, so its issue signature cannot be checked — revoke it and issue a new one";
    case "signature":
      return "has an issue signature that does not verify under the inviter's chain key (CRYPTO_SPEC §6.5). The row may have been swapped or tampered with — do not use it; revoke the invite";
  }
}

/**
 * 受諾ブロックの §6.5 独立検証: signed_bytes を一覧の材料 + 検証済み文脈の
 * projectId から**自分で再構成**し、受諾署名(宣言鍵)とリンク署名(発行文の
 * リンク公開鍵)を検証する(サーバー申告の検証結果を信用しない)。
 */
export function verifyAcceptanceBlock(input: {
  readonly projectId: string;
  readonly issuance: InviteIssuance;
  readonly acceptance: InviteAcceptance;
}): Effect.Effect<
  | { readonly ok: true; readonly fingerprintHex: string }
  | { readonly ok: false; readonly which: "accept" | "link" | "keys" },
  CliError
> {
  return Effect.gen(function* () {
    const context: InviteAcceptSignatureContext = {
      suite: SUITE_ID,
      projectId: input.projectId,
      linkPubHex: input.issuance.linkPubHex,
      inviteeUserId: input.acceptance.inviteeUserId,
      inviteeEncPubHex: input.acceptance.inviteeEncPubHex,
      inviteeSigPubHex: input.acceptance.inviteeSigPubHex,
    };
    const linkVerified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteLinkSignature({
          context,
          linkSignatureHex: input.acceptance.linkSignatureHex,
        }),
      catch: () => cliError("Failed to verify the link signature (crypto error)"),
    });
    if (!linkVerified.ok) {
      return { ok: false, which: "link" } as const;
    }
    const verified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteAcceptSignature({ context, signatureHex: input.acceptance.signatureHex }),
      catch: () => cliError("Failed to verify the acceptance signature (crypto error)"),
    });
    if (!verified.ok) {
      return { ok: false, which: "accept" } as const;
    }
    const enc = decodeHex(input.acceptance.inviteeEncPubHex);
    const sig = decodeHex(input.acceptance.inviteeSigPubHex);
    if (enc === null || sig === null) {
      return { ok: false, which: "keys" } as const;
    }
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(enc, sig),
      catch: () => cliError("Failed to compute the acceptance key's fingerprint (crypto error)"),
    });
    if (!fingerprint.ok) {
      return { ok: false, which: "keys" } as const;
    }
    return { ok: true, fingerprintHex: encodeHex(fingerprint.value) } as const;
  });
}

/** 受諾ブロックの検証失敗の文言(list / member add で共用)。 */
export function acceptanceFailureText(which: "accept" | "link" | "keys"): string {
  switch (which) {
    case "link":
      return "the link signature failed verification (CRYPTO_SPEC §6.5) — the acceptance was not made with the link you issued (the server or someone in between may have substituted the key)";
    case "accept":
      return "the acceptance signature failed verification (CRYPTO_SPEC §6.5)";
    case "keys":
      return "the acceptance keys are malformed";
  }
}

// ---------------------------------------------------------------------------
// invite create
// ---------------------------------------------------------------------------

export interface InviteCreateSummary {
  readonly id: string;
  /** 発行リンク(リンク鍵の種を内包する — 表示以外の用途で剥がさない)。 */
  readonly link: Redacted.Redacted<string>;
  readonly role: InviteRole;
  readonly expiresAtMs: number;
}

function ensureInviteLinkDisplayAllowed(
  io: CliIoShape,
): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "An AI agent environment was detected, so the invite was not issued (the invite link's secret would persist in execution logs and transcripts). Run `maruhi invite create` on a human interactive terminal",
    terminalError:
      "Invite-link display is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/** 発行の受理エラーの文言(理由コードを運用手順に翻訳する)。 */
function issueErrorToCliError(error: unknown): CliError {
  if (error instanceof InvitePendingLimitError) {
    return cliError(
      `Pending invites have reached the limit (${error.limit}). Revoke unneeded invites with \`maruhi invite revoke\`, then issue again`,
    );
  }
  if (error instanceof InviteRateLimitedError) {
    return cliError(
      `Invite issuance hit the rate limit. Retry in about ${error.retryAfterSeconds} seconds`,
    );
  }
  if (error instanceof InviteConflictError) {
    // id / リンク鍵は乱数で、衝突は事実上起きない — 起きたら再実行で採番し直す
    return cliError(
      "The server already has an invite with the same id or link key (an astronomically unlikely collision). Re-run `maruhi invite create` to draw a new one",
    );
  }
  return toCliError(error);
}

/**
 * 招待の発行 + 発行署名 + リンクの組み立て + 発行ピンの保存。発行の認可は
 * サーバーが強制するが、role 規則(§6.2 と同水準: 発行は admin 以上・role=admin は
 * owner のみ)は通信前に手前で落とす(明確な文言のため)。
 */
/**
 * 発行の前提検査(通信前): 招待者の role 規則(§6.2 と同水準: 発行は admin 以上・
 * role=admin は owner のみ)と、手元の master 鍵がチェーン上の自分の鍵と一致する
 * こと(一致しなければ、受諾者・自分の後段の検証が通らない発行文になる)。
 * 戻り値はチェーン上の自分(発行文の招待者鍵)。
 */
function ensureCanIssue(input: {
  readonly verified: VerifiedProject;
  readonly sessionUserId: string;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    const inviter = input.verified.state.members.get(input.sessionUserId);
    if (inviter === undefined) {
      return yield* Effect.fail(
        cliError("Only admins and above can issue invites (AUTH_SPEC §15-2)"),
      );
    }
    // 手元の鍵が招待者の端末鍵の 1 つであること(2026-09-19 DK — 署名者は端末単位)。
    // 端末が引けて初めて実効権限(人 ∩ 端末 cap — §6.2)が定まるため、権限の検査は
    // この後で行う(cap が絞られた端末からの発行は、受諾後の add_member が合意で
    // 落ちる罠を儀式の両側に作る — 発行しない)
    const device = ownDeviceByKeys(
      inviter,
      input.masterKeys.record.encPubHex,
      input.masterKeys.record.sigPubHex,
    );
    if (device === undefined) {
      return yield* Effect.fail(
        cliError(
          "This machine's key is not one of your registered devices on this project's chain, so an issue signature made here would not verify. Issue the invite from a device that is registered here (`maruhi device list` shows them) or have an owner re-add you",
        ),
      );
    }
    const permission = effectivePermissionOf(inviter, device);
    if (ROLE_RANK[permission.role] < ROLE_RANK.admin) {
      return yield* Effect.fail(
        cliError("Only admins and above can issue invites (AUTH_SPEC §15-2)"),
      );
    }
    if (input.role === "admin" && permission.role !== "owner") {
      return yield* Effect.fail(
        cliError(
          "Only an owner can issue a role=admin invite (same level as the add_member permission table in CRYPTO_SPEC §6.2)",
        ),
      );
    }
    // scope(2026-09-15 ES K4 — 設計録 K4-G): `--env` の各 id はチェーン上に存在し
    // (`unknown-environment`)、実効 scope が招待 scope を包含する
    // (`scope-not-contained` — 原則 1: add_member の権限変化の環境集合 = 新 scope)
    // ことを通信前に検査する。サーバーは検査しない(AUTH_SPEC §15-2)が、通っても
    // 受諾後の add_member が合意規則で落ちる = 受諾者を無駄に儀式へ進ませる罠なので
    // 発行しない(逃げ道は置かない — scope = all の admin / owner に頼めばよい)
    yield* requireScopeEnvironmentsExist(input.verified, input.scope);
    if (!scopeContains(permission.scope, input.scope)) {
      return yield* Effect.fail(
        cliError(
          `Your environment scope (${describeScope(permission.scope)}) does not contain the invite's scope (${describeScope(input.scope)}), so the add_member after acceptance would be rejected (CRYPTO_SPEC §6.2 scope-not-contained). Invite only environments in your own scope, or ask an owner / all-scope admin to issue this invite`,
        ),
      );
    }
    return inviter;
  });
}

/** 発行文の材料(id・種・リンク公開鍵)と発行署名。 */
interface SignedIssuance {
  readonly inviteId: string;
  readonly seed: Uint8Array;
  readonly linkPubHex: string;
  readonly issueSignatureHex: string;
}

/** id の採番 → 種の生成 → リンク鍵の導出 → 発行署名(CRYPTO_SPEC §6.5)。 */
function signIssuance(input: {
  readonly verified: VerifiedProject;
  readonly inviter: ChainMember;
  /** The inviter's signing device (its keys — the local master-key record — go into the issuance). */
  readonly inviterKeys: { readonly encPubHex: string; readonly sigPubHex: string };
  readonly role: InviteRole;
  readonly scope: ScopePayloadFields;
  readonly signingKey: MasterKeys["sigKeyPair"]["privateKey"];
}): Effect.Effect<SignedIssuance, CliError> {
  return Effect.gen(function* () {
    const inviteId = ulid();
    const seed = generateInviteLinkSeed();
    const linkKey = yield* Effect.tryPromise({
      try: () => deriveInviteLinkKeyPair(seed),
      catch: () => cliError("Failed to derive the invite link key (crypto error)"),
    });
    if (!linkKey.ok) {
      return yield* Effect.fail(cliError("Failed to derive the invite link key"));
    }
    const linkPubHex = encodeHex(linkKey.value.publicKeyRaw);
    const signed = yield* Effect.tryPromise({
      try: () =>
        signInviteIssue({
          context: {
            suite: SUITE_ID,
            inviteId,
            projectId: input.verified.projectId,
            linkPubHex,
            headHashHex: input.verified.state.headHashHex,
            headSeq: input.verified.state.headSeq,
            role: input.role,
            inviterUserId: input.inviter.userId,
            inviterEncPubHex: input.inviterKeys.encPubHex,
            inviterSigPubHex: input.inviterKeys.sigPubHex,
            scopeKind: input.scope.scopeKind,
            scopeEnvironmentIds: input.scope.scopeEnvironmentIds,
          },
          signingKey: input.signingKey,
        }),
      catch: () => cliError("Failed to create the issue signature (crypto error)"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("Failed to create the issue signature"));
    }
    return { inviteId, seed, linkPubHex, issueSignatureHex: signed.value };
  });
}

/** 発行後の案内(リンクは stdout、説明は stderr)。 */
function reportIssued(input: {
  readonly link: Redacted.Redacted<string>;
  readonly inviteId: string;
  readonly role: InviteRole;
  readonly scope: MemberScope;
  readonly expiresAtMs: number;
  readonly expectedGithubLogin: string | null;
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 剥がす理由: リンクの表示がこのコマンドの機能そのもの。表示可否は
    // inviteCreateOp 冒頭の TTY + エージェントゲートで判定済みで、剥がすのはその後ろ
    yield* io.log(Redacted.value(input.link));
    yield* io.logError(
      `Issued an invite (id=${displayText(input.inviteId)}, role=${input.role}, scope=${describeScope(input.scope)}, expires=${formatDateTimeUtc(input.expiresAtMs)})`,
    );
    yield* io.logError(
      "This link is shown only once (the server holds only the link's public key and cannot rebuild it). Hand it to the invitee over a person-to-person channel",
    );
    yield* io.logError(
      input.expectedGithubLogin === null
        ? "After they accept: run `maruhi member add`. The acceptance is checked against the link you issued; confirm the acceptor's FP words with them out of band (e.g. a call) unless it can be verified through their GitHub signing keys"
        : `After they accept: run \`maruhi member add\`. The acceptance is checked against the link you issued and against github.com/${input.expectedGithubLogin}'s signing keys — no call is needed when both pass`,
    );
  });
}

/**
 * 招待の発行 + 発行署名 + リンクの組み立て + 発行ピンの保存。発行の認可は
 * サーバーが強制するが、role 規則は通信前に手前で落とす(明確な文言のため)。
 */
export function inviteCreateOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly origin: string;
  readonly role: InviteRole;
  /** 付与予定 scope(`--env` 反復 → listed、省略 = all — AUTH_SPEC §15-3 / 設計録 裁定 K)。 */
  readonly scope: MemberScope;
  readonly sessionUserId: string;
  readonly masterKeys: MasterKeys;
  /** 宛先の GitHub login(`--github` — 裏付け元の照合先。発行ピンにのみ保持)。 */
  readonly expectedGithubLogin: string | null;
  /** 自分の GitHub login(リンクの `il=` — 受諾者側の裏付け元照合の材料)。 */
  readonly inviterLogin: string | null;
}): Effect.Effect<InviteCreateSummary, CliError, CliIo | PinStore | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const pinStore = yield* PinStore;
    // 招待リンクの種はリンクとして表示される(それが機能)が、AI エージェント
    // 環境では表示 = トランスクリプトへの残留であり、人対人チャネルで渡す前に
    // 第三者(エージェント基盤・ログ)へ漏れる経路になる。種は再表示不可の
    // ため「発行して表示しない」形は取れない — 発行そのものを拒否する
    yield* ensureInviteLinkDisplayAllowed(io);
    const inviter = yield* ensureCanIssue(input);
    // 発行文・発行 body・リンク・発行ピンの 4 か所に同じ scope を載せる(2026-09-15
    // ES K4 — `--env` 反復 = listed、省略 = all。生成は昇順・重複なし — scope.ts)
    const scope: ScopePayloadFields = scopePayloadFieldsOf(input.scope);
    // 発行する端末 = 手元の鍵(ensureCanIssue が招待者の端末鍵の 1 つであることを検査済み)
    const inviterKeys = {
      encPubHex: input.masterKeys.record.encPubHex,
      sigPubHex: input.masterKeys.record.sigPubHex,
    };
    const signed = yield* signIssuance({
      verified: input.verified,
      inviter,
      inviterKeys,
      role: input.role,
      scope,
      signingKey: input.masterKeys.sigKeyPair.privateKey,
    });
    const headHashHex = input.verified.state.headHashHex;
    const headSeq = input.verified.state.headSeq;
    const issued = yield* input.client.invites
      .issue({
        params: { projectId: input.verified.projectId },
        payload: {
          id: signed.inviteId,
          role: input.role,
          scopeKind: scope.scopeKind,
          scopeEnvironmentIds: scope.scopeEnvironmentIds,
          linkPubHex: signed.linkPubHex,
          headHashHex,
          headSeq,
          issueSignatureHex: signed.issueSignatureHex,
        },
      })
      .pipe(Effect.mapError(issueErrorToCliError));
    const link = buildInviteLink({
      origin: input.origin,
      link: {
        inviteId: signed.inviteId,
        linkSeedHex: Redacted.make(encodeHex(signed.seed), { label: "invite-link-seed" }),
        projectId: input.verified.projectId,
        headHashHex,
        headSeq,
        inviterUserId: inviter.userId,
        inviterEncPubHex: inviterKeys.encPubHex,
        inviterSigPubHex: inviterKeys.sigPubHex,
        role: input.role,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
        inviterLogin: input.inviterLogin,
        issueSignatureHex: signed.issueSignatureHex,
      },
    });
    // 発行ピン(SHOULD): member add 時にサーバー申告の行(link_pub・role)と突合する
    // 追加材料 + 宛先 login の保持(pins.ts)。種は保存しない。保存失敗で成立済みの
    // 発行を失敗扱いにしない(リンクは一度しか表示できない)
    yield* pinStore
      .saveIssuedPin(input.verified.projectId, signed.inviteId, {
        linkPubHex: signed.linkPubHex,
        role: input.role,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
        expiresAtMs: issued.expiresAtMs,
        expectedGithubLogin: input.expectedGithubLogin,
      })
      .pipe(
        Effect.catch((error) =>
          logWarning(
            `could not save the issuance pin (${error.message}). member add still verifies your issue signature on the server's row; only the extra pin cross-check and the addressee login are lost`,
          ),
        ),
      );
    yield* reportIssued({
      link,
      inviteId: signed.inviteId,
      role: input.role,
      scope: input.scope,
      expiresAtMs: issued.expiresAtMs,
      expectedGithubLogin: input.expectedGithubLogin,
    });
    return { id: signed.inviteId, link, role: input.role, expiresAtMs: issued.expiresAtMs };
  });
}

// createdAtMs / expiresAtMs はサーバー申告の無制限 number(B4): total な共有
// フォーマッタで表示し、Date 範囲外の値が defect(RangeError)にならないように
// する(invite create / list を型なしクラッシュで終了させない)
const formatDateTimeUtc = formatUtcMinutes;

// ---------------------------------------------------------------------------
// invite accept
// ---------------------------------------------------------------------------

export interface InviteAcceptSummary {
  readonly projectId: string;
  readonly role: InviteRole;
}

/** 招待者 FP(`ie` ‖ `is` から §3 のとおり導出)。 */
function inviterFingerprintOf(link: InviteLinkData): Effect.Effect<string, CliError> {
  return Effect.gen(function* () {
    const enc = decodeHex(link.inviterEncPubHex);
    const sig = decodeHex(link.inviterSigPubHex);
    if (enc === null || sig === null) {
      return yield* Effect.fail(cliError("The link's inviter keys (ie= / is=) are malformed"));
    }
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(enc, sig),
      catch: () => cliError("Failed to compute the inviter's key fingerprint (crypto error)"),
    });
    if (!fingerprint.ok) {
      return yield* Effect.fail(cliError("The link's inviter keys (ie= / is=) are malformed"));
    }
    return encodeHex(fingerprint.value);
  });
}

/** リンク鍵の導出(種 → 鍵ペア + 公開鍵 hex)。 */
function resolveLinkKey(link: InviteLinkData) {
  return Effect.gen(function* () {
    // 剥がす理由: 鍵導出にはバイト列そのものが要る。種はここで消費され、以後は
    // CryptoKey(非抽出)と公開鍵だけが流れる
    const seed = decodeHex(Redacted.value(link.linkSeedHex));
    if (seed === null) {
      return yield* Effect.fail(cliError("The link's key seed (k=) is malformed"));
    }
    const derived = yield* Effect.tryPromise({
      try: () => deriveInviteLinkKeyPair(seed),
      catch: () => cliError("Failed to derive the invite link key (crypto error)"),
    });
    if (!derived.ok) {
      return yield* Effect.fail(cliError("Failed to derive the invite link key"));
    }
    return { keyPair: derived.value, linkPubHex: encodeHex(derived.value.publicKeyRaw) };
  });
}

/**
 * 発行署名の検証(CRYPTO_SPEC §6.5 — 受諾者側の最初の検査)。失敗 = 受諾しない
 * (帯域外照合で上書きしない): リンク経路上の改竄か、招待者の公開鍵をゴースト
 * 追加した第三者のリンク。link_pub は種から導出した値を使う(リンクは運ばない)。
 */
function verifyLinkIssuanceWith(
  link: InviteLinkData,
  linkPubHex: string,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const verified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteIssueSignature({
          context: {
            suite: SUITE_ID,
            inviteId: link.inviteId,
            projectId: link.projectId,
            linkPubHex,
            headHashHex: link.headHashHex,
            headSeq: link.headSeq,
            role: link.role,
            inviterUserId: link.inviterUserId,
            inviterEncPubHex: link.inviterEncPubHex,
            inviterSigPubHex: link.inviterSigPubHex,
            scopeKind: link.scopeKind,
            scopeEnvironmentIds: link.scopeEnvironmentIds,
          },
          signatureHex: link.issueSignatureHex,
        }),
      catch: () => cliError("Failed to verify the link's issue signature (crypto error)"),
    });
    if (!verified.ok) {
      return yield* Effect.fail(
        cliError(
          "The invite link's issue signature does not verify under the inviter key it names (CRYPTO_SPEC §6.5). The link was altered in transit, or it was not issued by the holder of that key — do not accept it; ask the inviter to reissue over a trusted channel",
        ),
      );
    }
  });
}

/**
 * 受諾者側の相互確認(§6.5): リンクの招待者鍵から FP のワード列を表示し、
 * 帯域外照合の明示確認を要求する。チェーンとの機械照合は受諾時には**できない**
 * (非メンバーへのチェーン GET は一律 404 — AUTH_SPEC §11-2)ため、add_member
 * 後の初回同期で行う(context.ts のアンカー検査)。
 *
 * - `--inviter-fingerprint <hex>`: 帯域外で控えた招待者 FP をリンクの鍵と機械
 *   照合する(非対話の明示確認 + リンク改竄の第二経路検出)
 * - 対話: 12 語を表示し、最終語の再入力を要求する(server-grant と同じ儀式)
 * - エージェント環境ではフラグなしの儀式代行を拒否する(帳のヒットでも)
 * - 検証済み指紋帳(KF — known-fingerprints.ts): 過去に帯域外確認済みの招待者
 *   (origin × user_id)と指紋が一致すれば、12 語の帯域外読み上げの再実施を
 *   免除する。**受諾そのものの明示確認(yes 入力)はヒット時も要求する**。帳を
 *   使えるのは stdin / stdout が対話端末のときだけ(ADR-0016 決定 7 の一次境界)
 */
function confirmInviterFingerprint(input: {
  readonly origin: string;
  readonly link: InviteLinkData;
  readonly inviterFingerprintHex: string;
  readonly expectInviterFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.inviterFingerprintHex,
      "The link's inviter fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.link.inviterUserId,
      fingerprintHex: input.inviterFingerprintHex,
    });
    // 帳のヒットを使えるのは対話端末 + フラグなし + 非エージェントの経路だけ
    // (判定は usableBookHit)。そのときは読み上げ照合の指示 2 行を落とす
    const hit = yield* usableBookHit({
      book,
      flagProvided: input.expectInviterFingerprintHex !== null,
      isAgent: io.agentProfile().isAgent,
    });
    const lines = [
      "Inviter's key fingerprint (from ie= / is= in the link — mutual confirmation, CRYPTO_SPEC §6.5):",
      `  inviter: ${displayText(input.link.inviterUserId)}`,
      `  hex:  ${input.inviterFingerprintHex}`,
      "  word: " + formatWordList(words),
      ...(hit !== null
        ? []
        : [
            "Check that this word list matches the 12 words the inviter reads to you out of band (e.g. over a call).",
            "If they do not match, the link has been swapped (luring you into an attacker's project = reverse phishing) — abort the acceptance.",
          ]),
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectInviterFingerprintHex !== null) {
      if (input.expectInviterFingerprintHex !== input.inviterFingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--inviter-fingerprint does not match the inviter fingerprint derived from the link (ie= / is=). The link may have been tampered with — the acceptance was aborted (ask the inviter to reissue)",
          ),
        );
      }
      yield* io.log(
        "--inviter-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      yield* book.record;
      return;
    }
    yield* book.warnIfChanged;
    // AI エージェント環境では儀式を代行させない(server-grant と同じ姿勢。
    // 帳のヒットも代行の根拠にしない — フラグの明示指定だけが非対話経路)
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the inviter-fingerprint confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the inviter fingerprint noted out of band via --inviter-fingerprint",
        ),
      );
    }
    if (hit !== null) {
      return yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to accept this invite attributed to ${displayText(input.link.inviterUserId)} for project ${displayText(input.link.projectId)}`,
        cancelText: "The acceptance was cancelled.",
      });
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against the inviter's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Inviter fingerprint confirmation failed (the re-typed word does not match). The acceptance was not performed — re-run once you can check with the inviter",
    });
    yield* book.record;
  });
}

/**
 * master 鍵の用意(§15-3 の「鍵生成〔未生成時〕」— B1b 裁定 A′ の 3 ガード):
 * (1) エージェント環境では生成しない、(2) リカバリー登録済み = 別デバイスに
 * 既存鍵 → `key recover` へ誘導(旧鍵のリカバリー登録を上書きする事故を防ぐ)、
 * (3) 対話の明示確認 → 既存の keyGenerateOp(生成 → リカバリーコード儀式)を
 * そのまま実行する。生成後に中断しても、再実行は既存鍵を検出して受諾から続行
 * する(冪等な再開)。
 */
function ensureMasterKeysForAccept(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly keyGenerate: Effect.Effect<void, CliError, CliServices>;
}): Effect.Effect<
  { readonly keys: MasterKeys; readonly generated: boolean },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(
      masterKeyEntryName(input.session.origin, input.session.userId),
    );
    if (stored !== null) {
      return { keys: yield* loadMasterKeys(input.session), generated: false };
    }
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "No device key is present. Key generation is not performed in AI agent environments (issuing and storing the recovery code needs a human interactive terminal). Accept on a human terminal, or give this machine a key first — `maruhi device add` (approved from a device you have) or, if no device is left, `maruhi key recover` — and re-run",
        ),
      );
    }
    const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
    if (status.registered) {
      return yield* Effect.fail(
        cliError(
          "This machine has no device key, but your account already has a recovery ledger (a key was generated on another device). Creating a new key would start a second identity — add this machine as a device instead (`maruhi device add` here, `maruhi device approve` on a device you have), or `maruhi key recover` if no device of yours is left, then re-run (only if every device and every way to open the ledger are lost, rebuild with `maruhi key generate --new-identity`)",
        ),
      );
    }
    yield* io.log(
      "This machine has no device key. A new key (= a new cryptographic identity) will be generated before proceeding to accept",
    );
    yield* io.log(
      "If you already use maruhi on another device, stop here: add this machine as a device instead (`maruhi device add` here, then `maruhi device approve` on the other device) and re-run",
    );
    const answer = yield* io.promptLine({
      prompt: "Type yes to generate a new key: ",
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          "Key generation was cancelled (the acceptance was not performed). Re-run when ready",
        ),
      );
    }
    yield* input.keyGenerate;
    return { keys: yield* loadMasterKeys(input.session), generated: true };
  });
}

/**
 * 受諾者側の充足形 4(CRYPTO_SPEC §6.5 — IV2): 裏付け元が「招待者の sig 鍵
 * (`is`)はリンクが名指す login(`il`)の署名鍵である」と照合できたとき、
 * 12 語の読み上げは不要で、**受諾者が「その login からの招待を期待していた」
 * ことの表明**(非対話: `--from` の一致 / 対話: login を名指しする yes)で充足
 * する。照合の**不能**(裏付け元 `none`・`il` なし・未登録・取得不能)は
 * false = 充足形 1〜3(confirmInviterFingerprint)へ戻る。`--from` と `il` の
 * 不一致だけは**拒否**(経路で差し替えられた有効な別人のリンクの形)。
 */
function confirmInviterViaBacking(input: {
  readonly link: InviteLinkData;
  readonly identityBacking: IdentityBacking;
  readonly expectedFromLogin: string | null;
}): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { link } = input;
    if (input.identityBacking === "none") {
      if (input.expectedFromLogin !== null) {
        yield* logNote(
          "identityBacking is none, so --from cannot be checked against github.com — falling back to the inviter fingerprint confirmation",
        );
      }
      return false;
    }
    if (link.inviterLogin === null) {
      if (input.expectedFromLogin !== null) {
        yield* logNote(
          "the link does not name the inviter's GitHub login (il=), so --from cannot be checked — falling back to the inviter fingerprint confirmation",
        );
      }
      return false;
    }
    if (
      input.expectedFromLogin !== null &&
      input.expectedFromLogin.toLowerCase() !== link.inviterLogin.toLowerCase()
    ) {
      return yield* Effect.fail(
        cliError(
          `The link names github.com/${link.inviterLogin} as the inviter, but --from expects ${input.expectedFromLogin}. The link may have been swapped for another project's valid link — the acceptance was aborted (check with the person who sent it)`,
        ),
      );
    }
    const verdict = yield* checkSigningKeyBacking({
      login: link.inviterLogin,
      sigPubHex: link.inviterSigPubHex,
    });
    if (verdict.kind !== "match") {
      yield* logNote(
        `${describeBackingFallback(link.inviterLogin, verdict)} — falling back to the inviter fingerprint confirmation`,
      );
      return false;
    }
    yield* io.log(
      `Inviter key verified: the link's inviter signing key (is=) is registered as a signing key on github.com/${link.inviterLogin} (CRYPTO_SPEC §6.5)`,
    );
    if (input.expectedFromLogin !== null) {
      yield* io.log(
        "--from matches the link's inviter login (continuing without the 12-word call)",
      );
      return true;
    }
    return yield* confirmExpectedInviter(link, link.inviterLogin);
  });
}

/**
 * 充足形 4 の「期待していた」表明(対話形): login を名指しする yes。非対話では
 * フラグ(`--from`)だけが経路 — エージェント環境は拒否、非端末は儀式へ戻る。
 */
function confirmExpectedInviter(
  link: InviteLinkData,
  inviterLogin: string,
): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          `Refused to confirm the invite on your behalf: an AI agent environment was detected. Re-run with --from ${inviterLogin} if you expect this invite from that GitHub account, or accept on a human terminal`,
        ),
      );
    }
    const stdio = yield* Stdio.Stdio;
    if (!(yield* stdio.stdinIsTerminal) || !(yield* stdio.stdoutIsTerminal)) {
      yield* logNote(
        `stdin or stdout is not an interactive terminal — pass --from ${inviterLogin} to accept non-interactively; falling back to the inviter fingerprint confirmation`,
      );
      return false;
    }
    const answer = yield* io.promptLine({
      prompt: `Type yes to accept this invite from github.com/${inviterLogin} (project ${displayText(link.projectId)}, role ${link.role}, scope ${describeScope(link)}): `,
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          "The acceptance was cancelled. If you did not expect an invite from that GitHub account, tell the person who sent you the link",
        ),
      );
    }
    return true;
  });
}

export function inviteAcceptOp(input: {
  readonly client: MaruhiClient;
  readonly session: CliSession;
  readonly link: InviteLinkData;
  readonly expectInviterFingerprintHex: string | null;
  /** `--from <login>`(裏付け元による充足形 4 の非対話の表明)。 */
  readonly expectedFromLogin: string | null;
  readonly identityBacking: IdentityBacking;
  /** keyGenerateOp(生成 → リカバリー儀式)そのもの(cli.ts が結線する)。 */
  readonly keyGenerate: Effect.Effect<void, CliError, CliServices>;
}): Effect.Effect<InviteAcceptSummary, CliError, CliServices> {
  return Effect.gen(function* () {
    const { link } = input;
    // §15-3 の順序: 発行署名の検証(機械)→ 相互確認(充足形 4 → 1〜3)→
    // 鍵生成〔未生成時〕→ 共同署名 → 受諾 → アンカーのピン留め(受諾成立後のみ)
    const linkKey = yield* resolveLinkKey(link);
    yield* verifyLinkIssuanceWith(link, linkKey.linkPubHex);
    const inviterFingerprintHex = yield* inviterFingerprintOf(link);
    const backed = yield* confirmInviterViaBacking({
      link,
      identityBacking: input.identityBacking,
      expectedFromLogin: input.expectedFromLogin,
    });
    if (!backed) {
      yield* confirmInviterFingerprint({
        origin: input.session.origin,
        link,
        inviterFingerprintHex,
        expectInviterFingerprintHex: input.expectInviterFingerprintHex,
      });
    }

    const { keys: masterKeys, generated } = yield* ensureMasterKeysForAccept({
      session: input.session,
      client: input.client,
      keyGenerate: input.keyGenerate,
    });

    const context: InviteAcceptSignatureContext = {
      suite: SUITE_ID,
      projectId: link.projectId,
      linkPubHex: linkKey.linkPubHex,
      inviteeUserId: input.session.userId,
      inviteeEncPubHex: masterKeys.record.encPubHex,
      inviteeSigPubHex: masterKeys.record.sigPubHex,
    };
    const signature = yield* Effect.tryPromise({
      try: () => signInviteAccept({ context, signingKey: masterKeys.sigKeyPair.privateKey }),
      catch: () => cliError("Failed to create the acceptance signature (crypto error)"),
    });
    const linkSignature = yield* Effect.tryPromise({
      try: () => signInviteLink({ context, linkPrivateKey: linkKey.keyPair.privateKey }),
      catch: () => cliError("Failed to create the link signature (crypto error)"),
    });
    if (!signature.ok || !linkSignature.ok) {
      return yield* Effect.fail(cliError("Failed to create the acceptance signatures"));
    }

    const accepted = yield* input.client.invites
      .accept({
        payload: {
          linkPubHex: linkKey.linkPubHex,
          encPubHex: masterKeys.record.encPubHex,
          sigPubHex: masterKeys.record.sigPubHex,
          acceptSignatureHex: signature.value,
          linkSignatureHex: linkSignature.value,
        },
      })
      .pipe(Effect.mapError(acceptErrorToCliError));

    // リンク(発行署名済み)とサーバー応答の突合: p / r の不一致は署名検証を
    // 通らないはずの応答 = サーバーの自己矛盾か行のすり替え → 拒否
    if (accepted.projectId !== link.projectId) {
      return yield* Effect.fail(
        cliError(
          "The acceptance response's project ID does not match what the acceptance signature was bound to (the server's response contradicts itself). Do not trust this acceptance",
        ),
      );
    }
    if (accepted.role !== link.role) {
      return yield* Effect.fail(
        cliError(
          `The role declared in the signed link (${link.role}) does not match the role the server reports (${accepted.role}). The server's row contradicts the inviter's issue signature — do not trust this acceptance; ask the inviter to check \`maruhi invite list\``,
        ),
      );
    }
    // scope(2026-09-14 ES)も発行署名が覆う: 応答の scope が署名済みリンクと食い違えば
    // 同じくサーバーの自己矛盾 → 拒否(AUTH_SPEC §15-3)
    if (!sameScope(accepted, link)) {
      return yield* Effect.fail(
        cliError(
          `The scope declared in the signed link (${describeScope(link)}) does not match the scope the server reports (${describeScope(accepted)}). The server's row contradicts the inviter's issue signature — do not trust this acceptance; ask the inviter to check \`maruhi invite list\``,
        ),
      );
    }

    // アンカーのピン留めは受諾の成立(+ 突合)後(pinAnchorAfterAccept 参照)
    const anchored = yield* pinAnchorAfterAccept(link, inviterFingerprintHex);

    yield* reportAcceptOutcome({
      accepted,
      fingerprintHex: masterKeys.fingerprintHex,
      anchored,
      identityBacking: input.identityBacking,
    });
    // 登録の導線(補足 21 裁定 G ⑥ (b)): この受諾の中で鍵が生まれたなら、
    // 招待者が儀式なしで追加できるよう、ここで GitHub 登録を持ちかける
    if (generated && input.identityBacking !== "none") {
      yield* offerGithubRegistration({ session: input.session });
    }
    return { projectId: accepted.projectId, role: accepted.role };
  });
}

/**
 * 受諾成立後のアンカーのピン留め(§6.3 (a))。**機械照合に成功済み
 * (verifiedAtSeq ≠ null)の既存アンカーは上書きしない**: チェーンは
 * append-only であり検証済みアンカーの包含検査は以後も常に成立する(古くても
 * 無害・検出力は同等)ため、置換には利得がなく、上書き経路を一切残さない方が
 * 攻撃面が狭い(再招待の新アンカーより検証済みの実績を優先)。未照合アンカーは
 * 最新の受諾で置き換える(最後の正規受諾が勝つ)。
 *
 * 戻り値 = アンカーが有効に存在するか(保存成功 or 検証済み維持)。
 */
function pinAnchorAfterAccept(
  link: InviteLinkData,
  inviterFingerprintHex: string,
): Effect.Effect<boolean, CliError, CliIo | PinStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const pinStore = yield* PinStore;
    // ここへ来た時点で受諾はサーバー側で成立している。ピンは SHOULD 水準の
    // ローカル防衛なので、ピン留めの失敗で受諾を失敗扱いにしない — リンクは
    // 消費済みで、「再実行」は 410(accepted)にしかならない。破損ファイルは
    // 上書きしない(pins.ts の merge 規律)まま、警告して劣化を明示する
    const loaded = yield* pinStore
      .load(link.projectId)
      .pipe(
        Effect.catch((error) =>
          Effect.succeed({ pins: null, state: "error", detail: error.message } as const),
        ),
      );
    if (loaded.state === "error") {
      yield* warnUnpinned(loaded.detail);
      return false;
    }
    if (loaded.state === "corrupt") {
      yield* warnUnpinned(
        "the existing pin file is corrupt — inspect it, and delete it if the change was not intentional",
      );
      return false;
    }
    const existing = loaded.pins?.anchor ?? null;
    if (existing !== null && existing.verifiedAtSeq !== null) {
      yield* io.log(
        "This project already has a machine-verified invite link anchor — keeping the existing anchor (verified anchors are never overwritten)",
      );
      return true;
    }
    if (existing !== null) {
      // 未照合アンカーの置換は正規の再招待でも起きるが、痕跡ゼロだと偽リンクに
      // よる差し替え(DoS 経路)が監査不能になる — 一行で顕在化させる
      yield* io.log(
        "Replacing the unverified existing anchor with this acceptance's link anchor (the latest legitimate acceptance wins)",
      );
    }
    return yield* pinStore
      .saveAnchor(link.projectId, {
        headSeq: link.headSeq,
        headHashHex: link.headHashHex,
        inviterUserId: link.inviterUserId,
        inviterKeyFingerprintHex: inviterFingerprintHex,
        inviterSigPubHex: link.inviterSigPubHex,
        verifiedAtSeq: null,
      })
      .pipe(
        Effect.map(() => true),
        Effect.catch((error) => warnUnpinned(error.message).pipe(Effect.map(() => false))),
      );
  });
}

/** 受諾成立後の表示(自 FP ワード = 招待者への読み上げ材料 + 次の段の案内)。 */
function reportAcceptOutcome(input: {
  readonly accepted: InviteAcceptSummary;
  readonly fingerprintHex: string;
  readonly anchored: boolean;
  readonly identityBacking: IdentityBacking;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(
      `Accepted the invite (project=${input.accepted.projectId}, role=${input.accepted.role})`,
    );
    const ownWords = yield* fingerprintWords(
      input.fingerprintHex,
      "The key fingerprint is malformed",
    );
    yield* io.log("Your key fingerprint (the inviter checks this at member add):");
    yield* io.log(`  hex:  ${input.fingerprintHex}`);
    yield* io.log("  word: " + formatWordList(ownWords));
    // 完了表示(補足 21 裁定 G ⑥ (a)): 裏付け元があるときは「登録」が第一の
    // 導線で、12 語の読み上げはその代替
    yield* io.log(
      input.identityBacking === "none"
        ? "Your acceptance is bound to the invite link. Read these 12 words to the inviter out of band (e.g. over a call) (§6.5 mutual confirmation. To show them again later, run `maruhi key show`)"
        : "Your acceptance is bound to the invite link. Register this key on GitHub as a signing key with `maruhi key publish` so the inviter can add you without a call; otherwise read these 12 words to them out of band (e.g. over a call) (§6.5 mutual confirmation. To show them again later, run `maruhi key show`)",
    );
    yield* io.log(
      input.anchored
        ? "Your membership becomes final once the inviter completes member add. On the first sync after joining, the link anchor (genesis, head, inviter key) is machine-checked automatically"
        : "Your membership becomes final once the inviter completes member add (no anchor was pinned, so the first-sync machine check will not run — the out-of-band ceremony is the only defense)",
    );
  });
}

/** 410 の理由コードを運用手順に翻訳する。 */
function goneErrorToCliError(error: InviteGoneError): CliError {
  switch (error.reason) {
    case "accepted":
    case "completed":
      return cliError(
        "This invite has already been accepted. If that acceptance was not yours, the link may have been intercepted — contact the inviter and ask them to revoke this invite (`maruhi invite revoke`) and reissue (single use surfaces collisions — CRYPTO_SPEC §6.5)",
      );
    case "revoked":
      return cliError("This invite has been revoked. Ask the inviter to reissue");
    case "expired":
      return cliError("This invite has expired. Ask the inviter to reissue");
    default:
      return cliError("This invite is not usable. Ask the inviter to reissue");
  }
}

/** 受諾エラーの文言マップ(理由コードを運用手順に翻訳する)。 */
function acceptErrorToCliError(error: unknown): CliError {
  if (error instanceof InviteNotFoundError) {
    return cliError(
      "The server does not know this invite link's key. Check that the link (including everything after #) was copied completely, or ask the inviter whether it was issued against this server",
    );
  }
  if (error instanceof InviteGoneError) {
    return goneErrorToCliError(error);
  }
  if (error instanceof InviteSignatureInvalidError) {
    return error.which === "link"
      ? cliError(
          "The link signature was rejected by server verification. The link's key (k=) does not match the invite the server holds — the link is broken or was tampered with; ask the inviter to reissue",
        )
      : cliError(
          "The acceptance signature was rejected by server verification. The link's p (project ID) was tampered with, or the link is broken — ask the inviter to reissue the link",
        );
  }
  if (error instanceof ForbiddenError) {
    return cliError(
      "These credentials cannot accept the invite. Acceptance needs an all-project-scope (*) × admin token (AUTH_SPEC §15-2 — scope-limited tokens and web sessions are not allowed). Sign in again with `maruhi login`",
    );
  }
  return toCliError(error);
}

// ---------------------------------------------------------------------------
// invite list / revoke
// ---------------------------------------------------------------------------

export interface InviteListSummary {
  readonly rows: number;
  /** 署名検証の失敗・発行ピン不一致の件数(> 0 なら exit 1)。 */
  readonly integrityFailures: number;
}

/** 表示上の状態(pending + 期限超過は expired として表示 — 保存状態の導出)。 */
function displayStatus(row: InvitationRow, nowMs: number): string {
  return row.status === "pending" && row.expiresAtMs <= nowMs ? "expired" : row.status;
}

/**
 * 発行ピン突合(§6.5 の招待者側の追加材料 — SHOULD): サーバー申告の行が発行時の
 * link_pub・role・scope と食い違えば、行のすり替え・role / scope の虚偽申告の兆候。
 * ピンが無い(別端末発行)場合は発行署名の検証だけが行を固定する。
 */
export function pinMismatchOf(
  pins: InvitePins | null,
  row: InvitationRow,
): "missing" | "mismatch" | "match" {
  const pin = issuedPinOf(pins, row.id);
  if (pin === undefined) {
    return "missing";
  }
  return pin.linkPubHex !== row.issuance?.linkPubHex ||
    pin.role !== row.role ||
    !sameScope(pin, row)
    ? "mismatch"
    : "match";
}

/** 一覧 1 行の検証と表示(integrity failure の件数を返す)。 */
function listRowChecks(input: {
  readonly verified: VerifiedProject;
  readonly pins: InvitePins | null;
  readonly row: InvitationRow;
  readonly nowMs: number;
}): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { row } = input;
    let failures = 0;
    yield* io.log(
      `${displayText(row.id)}\t${displayStatus(row, input.nowMs)}\trole=${row.role}\tscope=${describeScope(row)}\tissued=${formatDateTimeUtc(row.createdAtMs)}\texpires=${formatDateTimeUtc(row.expiresAtMs)}`,
    );
    const issuance = yield* verifyIssuance({ verified: input.verified, row });
    if (!issuance.ok) {
      failures += 1;
      yield* logWarning(`invite ${displayText(row.id)} ${issuanceFailureText(issuance.reason)}`);
      return failures;
    }
    yield* io.log("  issuance: signature verified against the inviter's chain key");
    const pin = pinMismatchOf(input.pins, row);
    if (pin === "mismatch") {
      failures += 1;
      yield* logWarning(
        `the server's claim for invite ${displayText(row.id)} (link key / role) does not match the local record from issuance. The row may have been swapped or the role tampered with — do not run member add with this invite`,
      );
    }
    // 「照合して成功」と「照合材料なし」を同じ見た目にしない(S12 — §6.5 の
    // 追加材料が欠ける行は発行署名だけが固定する)
    if (pin === "missing") {
      yield* io.log(
        "  issuance pin: none on this machine (this invite may have been issued on another device) — the link key / role / scope cross-check was not performed",
      );
    }
    if (row.acceptance !== null) {
      const verified = yield* verifyAcceptanceBlock({
        projectId: input.verified.projectId,
        issuance: row.issuance,
        acceptance: row.acceptance,
      });
      if (!verified.ok) {
        failures += 1;
        yield* logWarning(
          `for invite ${displayText(row.id)}, ${acceptanceFailureText(verified.which)}. This acceptance block cannot be trusted — do not run member add; revoke the invite`,
        );
        return failures;
      }
      const words = yield* fingerprintWords(
        verified.fingerprintHex,
        "The acceptance key's fingerprint is malformed",
      );
      yield* io.log(
        `  accepted: ${displayText(row.acceptance.inviteeUserId)} (acceptance and link signatures verified)`,
      );
      yield* io.log(`  fp:   ${verified.fingerprintHex}`);
      yield* io.log("  word: " + formatWordList(words));
    }
    return failures;
  });
}

export function inviteListOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly pins: InvitePins | null;
  readonly nowMs: number;
}): Effect.Effect<InviteListSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const listed = yield* listInvitations(input.client, input.verified.projectId);
    const rows = [...listed].toSorted((a, b) => a.createdAtMs - b.createdAtMs);
    let integrityFailures = 0;
    if (rows.length === 0) {
      yield* io.log("No invites");
      return { rows: 0, integrityFailures };
    }
    for (const row of rows) {
      integrityFailures += yield* listRowChecks({
        verified: input.verified,
        pins: input.pins,
        row,
        nowMs: input.nowMs,
      });
    }
    return { rows: rows.length, integrityFailures };
  });
}

export function inviteRevokeOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.invites
      .revoke({ params: { projectId: input.verified.projectId, id: input.inviteId } })
      .pipe(
        Effect.mapError((error) => {
          if (error instanceof InviteNotFoundError) {
            return cliError("Invite not found (check the id with `maruhi invite list`)");
          }
          if (error instanceof InviteGoneError) {
            return error.reason === "completed"
              ? cliError(
                  "This invite has completed through add_member. To undo the membership, run `maruhi member remove` (it rotates every environment — CRYPTO_SPEC §7)",
                )
              : cliError("This invite is already revoked");
          }
          return toCliError(error);
        }),
      );
    yield* io.log("Revoked the invite");
  });
}
