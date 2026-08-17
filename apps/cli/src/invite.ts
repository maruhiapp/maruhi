// `maruhi invite create|accept|list|revoke`(AUTH_SPEC §15 / CRYPTO_SPEC §6.5 —
// Wave 2 B1b)。
//
// - create: 招待の発行 + §15-3 リンクの組み立て(アンカー = 発行時点の検証済み
//   ヘッド)+ 発行ピンの保存(member add 時のサーバー申告突合の材料)
// - accept: リンク解釈 → 招待者 FP の相互確認(§6.5 受諾者側 — 受諾時はリンクの
//   `if=` を表示。チェーンとの機械照合は add_member 後の初回同期 = context.ts)
//   → 鍵生成〔未生成時・ガード付き〕→ 受諾署名 → 受諾 → アンカーのピン留め
//   (§6.3 (a) — 受諾成立後のみ)→ 自分の FP ワード表示(招待者への読み上げ材料)
// - list: 受諾ブロックの §6.5 独立検証 + FP ワード表示 + 発行ピン突合
// - revoke: 失効
//
// トークン生値はワイヤ(発行応答・受諾要求)と表示にのみ存在し、永続化しない
// (発行ピンはハッシュのみ)。

import {
  ForbiddenError,
  InviteGoneError,
  InviteNotFoundError,
  InvitePendingLimitError,
  InviteRateLimitedError,
  InviteSignatureInvalidError,
} from "@maruhi/api-schema";
import {
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  signInviteAccept,
  SUITE_ID,
  verifyInviteAcceptSignature,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { buildInviteLink, type InviteLinkData, type InviteRole } from "./invite-link.ts";
import { CliIo } from "./io.ts";
import { Keychain, masterKeyEntryName } from "./keychain.ts";
import { type InvitePins, issuedPinOf, PinStore } from "./pins.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";
import type { VerifiedProject } from "./sync.ts";

/**
 * 提示トークン全体の SHA-256(PAT / 招待で共通のハッシュ入力定義 — §15-1)。
 *
 * 剥がす理由: ハッシュ入力にトークンのバイト列そのものが要る。戻り値は
 * ハッシュ(生値を含まない)なので、剥がした生値はこの関数の外へ出ない。
 */
export function tokenHashHexOf(token: Redacted.Redacted<string>): Effect.Effect<string, CliError> {
  return Effect.tryPromise({
    try: async () => {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(Redacted.value(token)) as BufferSource,
      );
      return encodeHex(new Uint8Array(digest));
    },
    catch: () => cliError("Failed to compute the token hash (crypto error)"),
  });
}

/** 招待の受諾ブロック(一覧応答の行 — §15-1)。 */
export interface InviteAcceptance {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly acceptedAtMs: number;
}

/** 一覧応答の 1 行(api-schema の InvitationSummary と同形)。 */
export interface InvitationRow {
  readonly id: string;
  readonly projectId: string;
  readonly role: InviteRole;
  readonly status: "pending" | "accepted" | "completed" | "revoked";
  readonly inviterUserId: string;
  readonly tokenHashHex: string;
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

/**
 * 受諾ブロックの §6.5 独立検証: signed_bytes を一覧の材料 + 検証済み文脈の
 * projectId から**自分で再構成**して検証する(サーバー申告の検証結果を信用
 * しない)。検証鍵は宣言鍵(自己束縛 — 検証鍵を外から与える口はない)。
 */
export function verifyAcceptanceBlock(input: {
  readonly projectId: string;
  readonly tokenHashHex: string;
  readonly acceptance: InviteAcceptance;
}): Effect.Effect<
  { readonly ok: true; readonly fingerprintHex: string } | { readonly ok: false },
  CliError
> {
  return Effect.gen(function* () {
    const verified = yield* Effect.tryPromise({
      try: () =>
        verifyInviteAcceptSignature({
          context: {
            suite: SUITE_ID,
            projectId: input.projectId,
            inviteTokenHashHex: input.tokenHashHex,
            inviteeUserId: input.acceptance.inviteeUserId,
            inviteeEncPubHex: input.acceptance.inviteeEncPubHex,
            inviteeSigPubHex: input.acceptance.inviteeSigPubHex,
          },
          signatureHex: input.acceptance.signatureHex,
        }),
      catch: () => cliError("Failed to verify the acceptance signature (crypto error)"),
    });
    if (!verified.ok) {
      return { ok: false } as const;
    }
    const enc = decodeHex(input.acceptance.inviteeEncPubHex);
    const sig = decodeHex(input.acceptance.inviteeSigPubHex);
    if (enc === null || sig === null) {
      return { ok: false } as const;
    }
    const fingerprint = yield* Effect.tryPromise({
      try: () => computeUserKeyFingerprint(enc, sig),
      catch: () => cliError("Failed to compute the acceptance key's fingerprint (crypto error)"),
    });
    if (!fingerprint.ok) {
      return { ok: false } as const;
    }
    return { ok: true, fingerprintHex: encodeHex(fingerprint.value) } as const;
  });
}

// ---------------------------------------------------------------------------
// invite create
// ---------------------------------------------------------------------------

export interface InviteCreateSummary {
  readonly id: string;
  /** 発行リンク(トークン生値を内包する — 表示以外の用途で剥がさない)。 */
  readonly link: Redacted.Redacted<string>;
  readonly role: InviteRole;
  readonly expiresAtMs: number;
}

/**
 * 招待の発行 + リンクの組み立て + 発行ピンの保存。発行の認可はサーバーが
 * 強制するが、role 規則(§6.2 と同水準: 発行は admin 以上・role=admin は
 * owner のみ)は通信前に手前で落とす(明確な文言のため)。
 */
export function inviteCreateOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly origin: string;
  readonly role: InviteRole;
  readonly sessionUserId: string;
}): Effect.Effect<InviteCreateSummary, CliError, CliIo | PinStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const pinStore = yield* PinStore;
    // 招待トークンの生値はリンクとして表示される(それが機能)が、AI エージェント
    // 環境では表示 = トランスクリプトへの残留であり、人対人チャネルで渡す前に
    // 第三者(エージェント基盤・ログ)へ漏れる経路になる。生値は再表示不可の
    // ため「発行して表示しない」形は取れない — 発行そのものを拒否する
    // (値表示 — agent.ts — ・リカバリーコード発行と同じ線引き)
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "An AI agent environment was detected, so the invite was not issued (the invite link's raw token would persist in execution logs and transcripts). Run maruhi invite create on a human interactive terminal",
        ),
      );
    }
    const inviter = input.verified.state.members.get(input.sessionUserId);
    if (inviter === undefined || ROLE_RANK[inviter.role] < ROLE_RANK.admin) {
      return yield* Effect.fail(
        cliError("Only admins and above can issue invites (AUTH_SPEC §15-2)"),
      );
    }
    if (input.role === "admin" && inviter.role !== "owner") {
      return yield* Effect.fail(
        cliError(
          "Only an owner can issue a role=admin invite (same level as the add_member permission table in CRYPTO_SPEC §6.2)",
        ),
      );
    }
    const issued = yield* input.client.invites
      .issue({
        params: { projectId: input.verified.projectId },
        payload: { role: input.role },
      })
      .pipe(
        Effect.mapError((error) => {
          if (error instanceof InvitePendingLimitError) {
            return cliError(
              `Pending invites have reached the limit (${error.limit}). Revoke unneeded invites with maruhi invite revoke, then issue again`,
            );
          }
          if (error instanceof InviteRateLimitedError) {
            return cliError(
              `Invite issuance hit the rate limit. Retry in about ${error.retryAfterSeconds} seconds`,
            );
          }
          return toCliError(error);
        }),
      );
    // ワイヤから来た生トークンはここで包み、以降 Redacted としてしか流さない
    const issuedToken = Redacted.make(issued.token, { label: "invite-token" });
    const link = buildInviteLink({
      origin: input.origin,
      token: issuedToken,
      projectId: input.verified.projectId,
      headHashHex: input.verified.state.headHashHex,
      headSeq: input.verified.state.headSeq,
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.keyFingerprintHex,
      role: issued.role,
    });
    // 発行ピン: member add 時にサーバー申告の一覧行(token_hash・role)と突合する
    // 材料(pins.ts)。トークン生値は保存しない。ピンは SHOULD 水準のローカル
    // 防衛なので、保存失敗(破損ファイル等)で成立済みの発行を失敗扱いにしない
    // (リンクは一度しか表示できない — ここで落とすと pending 枠だけ消費する)
    const tokenHashHex = yield* tokenHashHexOf(issuedToken);
    yield* pinStore
      .saveIssuedPin(input.verified.projectId, issued.id, {
        tokenHashHex,
        role: issued.role,
        expiresAtMs: issued.expiresAtMs,
      })
      .pipe(
        Effect.catch((error) =>
          io.logError(
            `Warning: could not save the issuance pin (${error.message}). The machine cross-check at member add degrades to the ceremony's visual comparison only`,
          ),
        ),
      );
    // 剥がす理由: リンクの表示がこのコマンドの機能そのもの。表示可否は上の
    // エージェントゲート(この関数の冒頭)で既に判定済みで、剥がすのはその後ろ
    yield* io.log(Redacted.value(link));
    yield* io.logError(
      `Issued an invite (id=${displayText(issued.id)}, role=${issued.role}, expires=${formatDateTimeUtc(issued.expiresAtMs)})`,
    );
    yield* io.logError(
      "This link is shown only once (the server stores only a hash and cannot re-display it). Hand it to the invitee over a person-to-person channel",
    );
    yield* io.logError(
      "After they accept: confirm the acceptance with maruhi invite list, check the FP words with the acceptor out of band (e.g. a call), then run maruhi member add (mutual confirmation — CRYPTO_SPEC §6.5)",
    );
    return { id: issued.id, link, role: issued.role, expiresAtMs: issued.expiresAtMs };
  });
}

/** unix ms を UTC 表示(YYYY-MM-DD HH:mm)にする。 */
function formatDateTimeUtc(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

// ---------------------------------------------------------------------------
// invite accept
// ---------------------------------------------------------------------------

export interface InviteAcceptSummary {
  readonly projectId: string;
  readonly role: InviteRole;
}

/** 受諾コマンドの入力(リンク or 生トークン + --project)。 */
export type AcceptTarget =
  | { readonly kind: "link"; readonly link: InviteLinkData }
  | {
      readonly kind: "token";
      readonly token: Redacted.Redacted<string>;
      readonly projectId: string;
    };

/**
 * 受諾者側の相互確認(§6.5): リンクの `if=` から招待者 FP のワード列を表示し、
 * 帯域外照合の明示確認を要求する。チェーンとの機械照合は受諾時には**できない**
 * (非メンバーへのチェーン GET は一律 404 — AUTH_SPEC §11-2)ため、add_member
 * 後の初回同期で行う(context.ts のアンカー検査)。
 *
 * - `--inviter-fingerprint <hex>`: 帯域外で控えた招待者 FP をリンクの `if=` と
 *   機械照合する(非対話の明示確認 + リンク改竄の第二経路検出)
 * - 対話: 12 語を表示し、最終語の再入力を要求する(server-grant と同じ儀式)
 * - エージェント環境ではフラグなしの儀式代行を拒否する
 */
function confirmInviterFingerprint(input: {
  readonly link: InviteLinkData;
  readonly expectInviterFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.link.inviterKeyFingerprintHex,
      "The link's inviter fingerprint (if=) is malformed",
    );
    const lines = [
      "Inviter's key fingerprint (if= in the link — mutual confirmation, CRYPTO_SPEC §6.5):",
      `  inviter: ${displayText(input.link.inviterUserId)}`,
      `  hex:  ${input.link.inviterKeyFingerprintHex}`,
      "  word: " + formatWordList(words),
      "Check that this word list matches the 12 words the inviter reads to you out of band (e.g. over a call).",
      "If they do not match, the link has been swapped (luring you into an attacker's project = reverse phishing) — abort the acceptance.",
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectInviterFingerprintHex !== null) {
      if (input.expectInviterFingerprintHex !== input.link.inviterKeyFingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--inviter-fingerprint does not match the link's inviter fingerprint (if=). The link may have been tampered with — the acceptance was aborted (ask the inviter to reissue)",
          ),
        );
      }
      yield* io.log(
        "--inviter-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      return;
    }
    // AI エージェント環境では儀式を代行させない(server-grant と同じ姿勢)
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "An AI agent environment was detected, so the inviter-fingerprint confirmation ceremony cannot run. Have a human run this, or pass the inviter fingerprint noted out of band via --inviter-fingerprint",
        ),
      );
    }
    return yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against the inviter's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Inviter fingerprint confirmation failed (the re-typed word does not match). The acceptance was not performed — re-run once you can check with the inviter",
    });
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
  readonly keyGenerate: Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient>;
}): Effect.Effect<MasterKeys, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const stored = yield* keychain.get(
      masterKeyEntryName(input.session.origin, input.session.userId),
    );
    if (stored !== null) {
      return yield* loadMasterKeys(input.session);
    }
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "No master key is present. Key generation is not performed in AI agent environments (issuing and storing the recovery code needs a human interactive terminal). Accept on a human terminal, or restore an existing key with `maruhi key recover` and re-run",
        ),
      );
    }
    const status = yield* input.client.auth.recoveryStatus({}).pipe(Effect.mapError(toCliError));
    if (status.registered) {
      return yield* Effect.fail(
        cliError(
          "This machine has no master key, but a recovery registration already exists (a key was generated on another device). Creating a new key would diverge from the existing one — restore it onto this machine with `maruhi key recover` and re-run (only if both the key and the recovery code are lost, explicitly rebuild with `maruhi key generate`)",
        ),
      );
    }
    yield* io.log(
      "This machine has no master key. A new key (= a new cryptographic identity) will be generated before proceeding to accept.",
    );
    yield* io.log(
      "If you already use maruhi on another device, stop here: run `maruhi key recovery` on the old device to issue a recovery code, then run `maruhi key recover` on this machine.",
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
    return yield* loadMasterKeys(input.session);
  });
}

export function inviteAcceptOp(input: {
  readonly client: MaruhiClient;
  readonly session: CliSession;
  readonly target: AcceptTarget;
  readonly expectInviterFingerprintHex: string | null;
  /** keyGenerateOp(生成 → リカバリー儀式)そのもの(cli.ts が結線する)。 */
  readonly keyGenerate: Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient>;
}): Effect.Effect<
  InviteAcceptSummary,
  CliError,
  CliIo | Keychain | PinStore | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;

    // §15-3 の順序: 相互確認 → 鍵生成〔未生成時〕→ 受諾署名 → 受諾 →
    // アンカーのピン留め(受諾成立後のみ — 同節の 2026-08-15 追補)
    const { projectId, token } =
      input.target.kind === "link"
        ? yield* prepareLinkAccept(input.target.link, input.expectInviterFingerprintHex)
        : yield* prepareTokenAccept(input.target, input.expectInviterFingerprintHex);

    const masterKeys = yield* ensureMasterKeysForAccept({
      session: input.session,
      client: input.client,
      keyGenerate: input.keyGenerate,
    });

    const tokenHashHex = yield* tokenHashHexOf(token);
    const signature = yield* Effect.tryPromise({
      try: () =>
        signInviteAccept({
          context: {
            suite: SUITE_ID,
            projectId,
            inviteTokenHashHex: tokenHashHex,
            inviteeUserId: input.session.userId,
            inviteeEncPubHex: masterKeys.record.encPubHex,
            inviteeSigPubHex: masterKeys.record.sigPubHex,
          },
          signingKey: masterKeys.sigKeyPair.privateKey,
        }),
      catch: () => cliError("Failed to create the acceptance signature (crypto error)"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("Failed to create the acceptance signature"));
    }

    const accepted = yield* input.client.invites
      .accept({
        payload: {
          // 剥がす理由: 受諾要求のワイヤ境界(サーバーは生トークンを検証する)
          token: Redacted.value(token),
          encPubHex: masterKeys.record.encPubHex,
          sigPubHex: masterKeys.record.sigPubHex,
          signatureHex: signature.value,
        },
      })
      .pipe(Effect.mapError(acceptErrorToCliError));

    // リンク申告とサーバー応答の突合: p の不一致は署名検証(project_id 束縛)を
    // 通らないはずの応答 = サーバーの自己矛盾。r は表示専用申告なので警告に留める
    if (accepted.projectId !== projectId) {
      return yield* Effect.fail(
        cliError(
          "The acceptance response's project ID does not match what the acceptance signature was bound to (the server's response contradicts itself). Do not trust this acceptance",
        ),
      );
    }
    if (
      input.target.kind === "link" &&
      input.target.link.role !== null &&
      input.target.link.role !== accepted.role
    ) {
      yield* io.logError(
        `Warning: the role declared in the link (${input.target.link.role}) does not match the actual role (${accepted.role}). The link may have been tampered with, or the invite was re-created — check with the inviter`,
      );
    }

    // アンカーのピン留めは受諾の成立(+ p の突合)後(pinAnchorAfterAccept 参照)。
    // anchored はピン留めの実否(リンク受諾か、ではなく)— 警告で劣化を明示した
    // 直後に「機械照合が行われます」と案内する矛盾出力を作らない
    const anchored =
      input.target.kind === "link" ? yield* pinAnchorAfterAccept(input.target.link) : false;

    yield* reportAcceptOutcome({
      accepted,
      fingerprintHex: masterKeys.fingerprintHex,
      anchored,
    });
    return { projectId: accepted.projectId, role: accepted.role };
  });
}

/**
 * リンク受諾の前段(§6.5): 招待者 FP の相互確認。アンカーのピン留めは
 * **受諾の成立後**に行う(pinAnchorAfterAccept — pullfrog レビュー反映):
 * 受諾成立前に書くと、在籍中のプロジェクトの projectId を持つ細工リンクを
 * 開いただけ(受諾は署名検証 422 / 410 で失敗する)で正規アンカーが偽の
 * ヘッドへ差し替わり、以後の全同期が硬い証拠として恒久失敗する自己 DoS 経路に
 * なる。初回同期(add_member 後)より前に書ければアンカーの目的は満たされる。
 */
function prepareLinkAccept(
  link: InviteLinkData,
  expectInviterFingerprintHex: string | null,
): Effect.Effect<
  { readonly projectId: string; readonly token: Redacted.Redacted<string> },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    yield* confirmInviterFingerprint({ link, expectInviterFingerprintHex });
    return { projectId: link.projectId, token: link.token };
  });
}

/**
 * 受諾成立後のアンカーのピン留め(§6.3 (a))。**機械照合に成功済み
 * (verifiedAtSeq ≠ null)の既存アンカーは上書きしない**: チェーンは
 * append-only であり検証済みアンカーの包含検査は以後も常に成立する(古くても
 * 無害・検出力は同等)ため、置換には利得がなく、上書き経路を一切残さない方が
 * 攻撃面が狭い(再招待の新アンカーより検証済みの実績を優先 — pullfrog
 * レビュー反映)。未照合アンカーは最新の受諾で置き換える(最後の正規受諾が勝つ)。
 *
 * 戻り値 = アンカーが有効に存在するか(保存成功 or 検証済み維持)。呼び出し側の
 * 完了報告が「初回同期で機械照合される」と案内してよいかの根拠になる — 警告で
 * 劣化を明示した直後に照合を約束する矛盾出力を作らない(pullfrog レビュー反映)。
 */
function pinAnchorAfterAccept(
  link: InviteLinkData,
): Effect.Effect<boolean, CliError, CliIo | PinStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const pinStore = yield* PinStore;
    // ここへ来た時点で受諾はサーバー側で成立している。ピンは SHOULD 水準の
    // ローカル防衛なので、ピン留めの失敗で受諾を失敗扱いにしない — トークンは
    // 消費済みで、「再実行」は 410(accepted)にしかならない。破損ファイルは
    // 上書きしない(pins.ts の merge 規律)まま、警告して劣化を明示する
    const warnUnpinned = (detail: string) =>
      io.logError(
        `Warning: could not pin the invite link anchor (${detail}). The machine check on first sync (CRYPTO_SPEC §6.3 (a)) will not run — be sure to perform the ceremony with the inviter (out-of-band FP word comparison)`,
      );
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
        inviterKeyFingerprintHex: link.inviterKeyFingerprintHex,
        verifiedAtSeq: null,
      })
      .pipe(
        Effect.map(() => true),
        Effect.catch((error) => warnUnpinned(error.message).pipe(Effect.map(() => false))),
      );
  });
}

/**
 * 生トークン受諾の前段: アンカーも招待者 FP も持たない(§6.3 (a) / §6.5 の
 * 受諾者側チェックが両方失われる)ため、対話環境でのみ明示の了解つきで許す。
 */
function prepareTokenAccept(
  target: { readonly token: Redacted.Redacted<string>; readonly projectId: string },
  expectInviterFingerprintHex: string | null,
): Effect.Effect<
  { readonly projectId: string; readonly token: Redacted.Redacted<string> },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (expectInviterFingerprintHex !== null) {
      return yield* Effect.fail(
        usageError(
          "--inviter-fingerprint is only for link acceptance (a raw token has no if= to check against). Accept with the invite link",
        ),
      );
    }
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "An AI agent environment was detected, so acceptance with a raw token was refused (there is no anchor or inviter fingerprint to check against). Accept with the invite link",
        ),
      );
    }
    yield* io.logError(
      "Warning: accepting with a raw token loses both the link anchor (rollback detection — CRYPTO_SPEC §6.3) and the inviter fingerprint check (§6.5). Accept with the invite link whenever possible",
    );
    const answer = yield* io.promptLine({
      prompt: "Type yes to accept without an anchor: ",
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(cliError("The acceptance was cancelled"));
    }
    return { projectId: target.projectId, token: target.token };
  });
}

/** 受諾成立後の表示(自 FP ワード = 招待者への読み上げ材料 + 次の段の案内)。 */
function reportAcceptOutcome(input: {
  readonly accepted: InviteAcceptSummary;
  readonly fingerprintHex: string;
  readonly anchored: boolean;
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
    yield* io.log(
      "Read these 12 words to the inviter out of band (e.g. over a call) (§6.5 mutual confirmation — one call completes the check in both directions. To show them again later, run maruhi key show)",
    );
    yield* io.log(
      input.anchored
        ? "Your membership becomes final once the inviter completes member add. On the first sync after joining, the link anchor (genesis, head, inviter FP) is machine-checked automatically"
        : "Your membership becomes final once the inviter completes member add (no anchor was pinned, so the first-sync machine check will not run — the out-of-band ceremony is the only defense)",
    );
  });
}

/** 受諾エラーの文言マップ(理由コードを運用手順に翻訳する)。 */
function acceptErrorToCliError(error: unknown): CliError {
  if (error instanceof InviteNotFoundError) {
    return cliError("Unknown invite token. Check that the link (or token) was copied completely");
  }
  if (error instanceof InviteGoneError) {
    switch (error.reason) {
      case "accepted":
      case "completed":
        return cliError(
          "This invite has already been accepted. If that acceptance was not yours, the link may have been intercepted — contact the inviter and ask them to revoke this invite (maruhi invite revoke) and reissue (single use surfaces collisions — CRYPTO_SPEC §6.5)",
        );
      case "revoked":
        return cliError("This invite has been revoked. Ask the inviter to reissue");
      case "expired":
        return cliError("This invite has expired. Ask the inviter to reissue");
      default:
        return cliError("This invite is not usable. Ask the inviter to reissue");
    }
  }
  if (error instanceof InviteSignatureInvalidError) {
    return cliError(
      "The acceptance signature was rejected by server verification. The link's p (project ID) was tampered with, or the link is broken — ask the inviter to reissue the link",
    );
  }
  if (error instanceof ForbiddenError) {
    return cliError(
      "These credentials cannot accept the invite. Acceptance needs a session, or an all-project-scope (*) × admin token (AUTH_SPEC §15-2 — scope-limited tokens are not allowed). Log in again with `maruhi login`",
    );
  }
  return toCliError(error);
}

// ---------------------------------------------------------------------------
// invite list / revoke
// ---------------------------------------------------------------------------

export interface InviteListSummary {
  readonly rows: number;
  /** 受諾署名の検証失敗・発行ピン不一致の件数(> 0 なら exit 1)。 */
  readonly integrityFailures: number;
}

/** 表示上の状態(pending + 期限超過は expired として表示 — 保存状態の導出)。 */
function displayStatus(row: InvitationRow, nowMs: number): string {
  return row.status === "pending" && row.expiresAtMs <= nowMs ? "expired" : row.status;
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
      yield* io.log(
        `${displayText(row.id)}\t${displayStatus(row, input.nowMs)}\trole=${row.role}\tissued=${formatDateTimeUtc(row.createdAtMs)}\texpires=${formatDateTimeUtc(row.expiresAtMs)}`,
      );
      // 発行ピン突合(§6.5 の招待者側対応物): サーバー申告の行が発行時の
      // token_hash・role と食い違えば、行のすり替え・role の虚偽申告の兆候
      const pin = issuedPinOf(input.pins, row.id);
      if (pin !== undefined && (pin.tokenHashHex !== row.tokenHashHex || pin.role !== row.role)) {
        integrityFailures += 1;
        yield* io.logError(
          `Warning: the server's claim for invite ${displayText(row.id)} (token_hash / role) does not match the local record from issuance. The row may have been swapped or the role tampered with — do not run member add with this invite`,
        );
      }
      if (row.acceptance !== null) {
        const verified = yield* verifyAcceptanceBlock({
          projectId: input.verified.projectId,
          tokenHashHex: row.tokenHashHex,
          acceptance: row.acceptance,
        });
        if (!verified.ok) {
          integrityFailures += 1;
          yield* io.logError(
            `Warning: the acceptance signature for invite ${displayText(row.id)} failed verification (CRYPTO_SPEC §6.5). This acceptance block cannot be trusted — do not run member add; revoke the invite`,
          );
          continue;
        }
        const words = yield* fingerprintWords(
          verified.fingerprintHex,
          "The acceptance key's fingerprint is malformed",
        );
        yield* io.log(
          `  accepted: ${displayText(row.acceptance.inviteeUserId)} (signature verified)`,
        );
        yield* io.log(`  fp:   ${verified.fingerprintHex}`);
        yield* io.log("  word: " + formatWordList(words));
      }
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
            return cliError("Invite not found (check the id with maruhi invite list)");
          }
          if (error instanceof InviteGoneError) {
            return error.reason === "completed"
              ? cliError(
                  "This invite has completed through add_member. To undo the membership, run maruhi member remove (it rotates every environment — CRYPTO_SPEC §7)",
                )
              : cliError("This invite is already revoked");
          }
          return toCliError(error);
        }),
      );
    yield* io.log("Revoked the invite");
  });
}
