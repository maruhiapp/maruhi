// `maruhi member add|remove|change-role`(CRYPTO_SPEC §6.2 / §6.5 / §7、
// AUTH_SPEC §12-6 / §15)。
//
// - add: 一覧の受諾ブロックから §6.5 独立検証 + 発行ピン突合 + FP 確認の儀式 →
//   add_member 追記(CAS リトライ)→ 全環境 × 全エポックのバックフィル
//   (409 = 登録済みの冪等再開。**再追加(過去在籍が別鍵)の 409 は旧鍵ラップの
//   疑い**があるため、鍵履歴ゲート付きで削除 → 再登録の自動修復を行う — §12-6
//   の修復経路。放置すると再追加メンバーが履歴エポックを復号できない)
// - remove / change-role(member 未満への降格): エントリ追記 → **全環境の強制
//   ローテーション**(§7)。中断復旧は server revoke と同じチェーン導出方式
//   (rotation-sweep.ts — 基準 = 最後のローテーション義務エントリの seq)
//
// 自分自身の remove / member 未満への自己降格は拒否する: 実行後に本人が
// rotate_epoch の権限を失い、§7 の義務を自分で履行できない(合意規則は
// 禁止していないが、義務が構造的に宙に浮く形を CLI が作らない)。

import { ChainHeadConflictError, DekWrapNotFoundError } from "@maruhi/api-schema";
import type { ChainEntry, ChainMember, Role, SigningKeyPair } from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { backfillEnvironmentFor, registerWraps } from "./backfill.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import type { IdentityBacking } from "./config.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import {
  acceptanceFailureText,
  type InvitationRow,
  type InviteAcceptance,
  type InviteIssuance,
  issuanceFailureText,
  listInvitations,
  pinMismatchOf,
  verifyAcceptanceBlock,
  verifyIssuance,
} from "./invite.ts";
import { CliIo } from "./io.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  type FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { logNote } from "./notice.ts";
import { type InvitePins, issuedPinOf } from "./pins.ts";
import { retryOnConflict } from "./retry.ts";
import {
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
  verifiedDeletedEnvironmentSet,
} from "./rotation-sweep.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/** remove / 降格後の全環境ローテーションの理由(§6.2 payload の固定文字列)。 */
export const MEMBER_REMOVED_ROTATION_REASON = "member-removed";
export const ROLE_DEMOTED_ROTATION_REASON = "role-demoted";

// ---------------------------------------------------------------------------
// 共通: ローテーション義務の基準 seq(中断復旧の基準 — チェーン導出のみ)
// ---------------------------------------------------------------------------

/**
 * **対象 user_id の**最後の「ローテーション義務エントリ」の seq(存在しなければ
 * null): `remove_member`(常に義務 — §7)、または「直前 role が member 以上 →
 * newRole が member 未満」の `change_role`(降格の義務 — §7)。導出の本体は
 * rotation-sweep.ts の rotationMandates(未収束の常時警告と同じ 1 導出 —
 * 判定のズレを構造的に防ぐ)。
 *
 * 対象スコープにするのは、各コマンドが収束させる義務を**自分の操作の分**に
 * 限定するため: 大域の最終義務を基準にすると、born-reader への
 * no-op 再実行が**他人の**未収束義務を拾って全環境ローテーションを開始する。
 * 対象の義務エントリ以降のローテーションは対象の偽造可能座標を閉じる(§7)ため、
 * 対象スコープでも自分の義務を過小に満たすことはない(他人の未収束義務は
 * 常時警告 — rotation-sweep.ts — とその操作の再実行の責務)。
 */
function lastRotationMandateSeqFor(verified: VerifiedProject, targetUserId: string): number | null {
  const mandates = rotationMandates(verified).filter(
    (mandate) => mandate.kind !== "server-revoked" && mandate.target === targetUserId,
  );
  return mandates[mandates.length - 1]?.seq ?? null;
}

/** §7 の全環境走査(remove / 降格の共有後段。基準 seq は呼び出し側が導出する)。 */
function sweepAfterMandate<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly baselineSeq: number;
  readonly rotate: SweepRotate<R>;
}): Effect.Effect<SweepOutcome & { readonly skippedDeleted: readonly string[] }, CliError, R> {
  return Effect.gen(function* () {
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const skippedDeleted = [...input.verified.state.environments.keys()]
      .filter((environmentId) => deletedVerified.has(environmentId))
      .toSorted();
    const sweep = yield* sweepRotations({
      rotate: input.rotate,
      verified: input.verified,
      baselineSeq: input.baselineSeq,
      deletedVerified,
    });
    return { ...sweep, skippedDeleted };
  });
}

/**
 * メンバーシップ op の CAS 追記(retryOnConflict の共有足場 — add / remove /
 * change_role で同型)。ヘッド競合ごとに延長検査付き再同期 → `recheck` で
 * 事前検査をやり直し、並行実行が同じ変更を先に積んでいたら(already)追記せず
 * 継続する。
 */
function appendWithCas(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** exhausted 文言に使う op 名(例: "remove_member")。 */
  readonly opLabel: string;
  readonly signEntry: (verified: VerifiedProject) => Effect.Effect<ChainEntry, CliError>;
  readonly recheck: (
    verified: VerifiedProject,
  ) => Effect.Effect<{ readonly already: boolean }, CliError>;
}): Effect.Effect<{ readonly verified: VerifiedProject; readonly appended: boolean }, CliError> {
  return retryOnConflict<
    { readonly verified: VerifiedProject; readonly already: boolean },
    { readonly verified: VerifiedProject; readonly appended: boolean },
    "head-conflict"
  >(
    { verified: input.verified, already: false },
    {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) =>
        state.already
          ? Effect.succeed({ verified: state.verified, appended: false })
          : Effect.gen(function* () {
              const entry = yield* input.signEntry(state.verified);
              yield* appendEntry(input.client, state.verified, entry);
              return { verified: state.verified, appended: true };
            }),
      classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
      recover: (state) =>
        Effect.gen(function* () {
          const resynced = yield* resyncExtended(input.resync, state.verified);
          const rechecked = yield* input.recheck(resynced);
          return { verified: resynced, already: rechecked.already };
        }),
      exhaustedMessage: `${input.opLabel}'s chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
    },
  );
}

/** actor(実行者)と target の解決(remove / change_role 共通の前段)。 */
function resolveActorAndTarget(
  verified: VerifiedProject,
  signerUserId: string,
  targetUserId: string,
): Effect.Effect<
  { readonly actor: ChainMember; readonly target: ChainMember | undefined },
  CliError
> {
  const actor = verified.state.members.get(signerUserId);
  if (actor === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  return Effect.succeed({ actor, target: verified.state.members.get(targetUserId) });
}

/** remove / change_role の対象規則(§6.2)の CLI 早期検査(文言のための手前判定)。 */
function targetedOpRejection(input: {
  readonly actor: ChainMember;
  readonly target: ChainMember;
  readonly operation: string;
}): string | null {
  if (ROLE_RANK[input.actor.role] < ROLE_RANK.admin) {
    return `Only admins and above can run ${input.operation} (CRYPTO_SPEC §6.2)`;
  }
  if (ROLE_RANK[input.target.role] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return `Only an owner can run ${input.operation} against an admin / owner (CRYPTO_SPEC §6.2)`;
  }
  return null;
}

function ownersCount(verified: VerifiedProject): number {
  let count = 0;
  for (const member of verified.state.members.values()) {
    if (member.role === "owner") {
      count += 1;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// member add
// ---------------------------------------------------------------------------

export interface MemberAddSummary {
  /** チェーンへ追記したか(false = 既に同一鍵で在籍 — バックフィルのみの再開)。 */
  readonly appended: boolean;
  readonly targetUserId: string;
  readonly role: Role;
  /** バックフィルで新規登録したラップ数。 */
  readonly registered: number;
  /** 既に登録済みだったラップ数(再実行の収束)。 */
  readonly alreadyRegistered: number;
  /** 旧鍵ラップの疑いで削除 → 再登録した数(再追加の自動修復 — §12-6)。 */
  readonly repaired: number;
  /** バックフィルに失敗した環境(§7 — 黙ってスキップしない)。 */
  readonly failed: readonly { readonly environmentId: string; readonly message: string }[];
}

/** 受諾済みかつ発行文のある行(IV 改訂前の行は発行文が無く add できない)。 */
type AddableRow = InvitationRow & {
  readonly acceptance: InviteAcceptance;
  readonly issuance: InviteIssuance;
};

const withAcceptance = (
  row: InvitationRow,
): row is InvitationRow & { readonly acceptance: InviteAcceptance } => row.acceptance !== null;

/**
 * 受諾済み招待の選択: id 指定があればその行、なければ受諾済み(accepted)が
 * ちょうど 1 件のときだけ自動選択する(複数・ゼロは明示を要求)。
 */
function selectInvitation(
  rows: readonly InvitationRow[],
  inviteId: string | null,
): Effect.Effect<AddableRow, CliError> {
  if (inviteId !== null) {
    const row = rows.find((candidate) => candidate.id === inviteId);
    if (row === undefined) {
      return Effect.fail(
        cliError("The specified invite was not found (check the id with `maruhi invite list`)"),
      );
    }
    if (row.status === "revoked") {
      return Effect.fail(
        cliError(
          "The specified invite has been revoked (its acceptance block, if any, will not be used)",
        ),
      );
    }
    if (!withAcceptance(row)) {
      return Effect.fail(
        cliError(
          "The specified invite has not been accepted yet (check with `maruhi invite list` after acceptance)",
        ),
      );
    }
    return requireIssuance(row);
  }
  const accepted = rows.filter(withAcceptance).filter((row) => row.status === "accepted");
  const first = accepted[0];
  if (first === undefined) {
    // completed 行は自動選択しない(過去メンバー全員の行が completed のまま
    // 蓄積するため曖昧)。add_member 済み招待のバックフィル再開は id 明示の
    // 経路が受ける — その導線をここで示す
    return Effect.fail(
      cliError(
        "There is no accepted invite. To resume the backfill of an invite that completed through add_member, look up the id with `maruhi invite list` and pass it explicitly: `maruhi member add <invite-id>`",
      ),
    );
  }
  if (accepted.length > 1) {
    return Effect.fail(
      cliError(
        `Multiple invites have been accepted (${accepted.map((row) => displayText(row.id)).join(", ")}). Specify which invite id to add`,
      ),
    );
  }
  return requireIssuance(first);
}

/** 発行文の無い行(IV 改訂前)は add_member に使えない(互換経路なし)。 */
function requireIssuance(
  row: InvitationRow & { readonly acceptance: InviteAcceptance },
): Effect.Effect<AddableRow, CliError> {
  return row.issuance === null
    ? Effect.fail(cliError(`This invite ${issuanceFailureText("unbound")}`))
    : Effect.succeed({ ...row, issuance: row.issuance });
}

/**
 * 招待者側の相互確認(§6.5 — 必須 UX): 受諾鍵の FP ワード列と付与 role を
 * 表示し、帯域外照合の明示確認を要求する。儀式は再実行(バックフィルのみの
 * 中断復旧)でも省略しない(server-grant と同じ規律 — これからラップを配る鍵の
 * 照合を省略しない)。
 *
 * 検証済み指紋帳(KF — known-fingerprints.ts): 過去に帯域外確認済みの相手
 * (origin × user_id)の指紋と一致すれば、12 語の帯域外読み上げの再実施を
 * 免除する。**付与そのものの明示確認(yes 入力)はヒット時も要求し**、
 * エージェント環境では帳を auto-pass に使わない(フラグ必須のまま — 帳は
 * 過去の検証の記録であって、この付与への人間の同意を代替しない)。さらに
 * **帳を使えるのは stdin / stdout が対話端末のときだけ**(ADR-0016 決定 7 の
 * 一次境界と同じ allow-list): 12 語儀式は実行ごとの最終語再入力が要るため
 * 盲目的なパイプでは通らないが、yes 確認はそうではないので、パイプ・CI・
 * 未検出エージェントでは帳を無効化して完全な儀式へ戻す(fail-closed)。
 * フラグの明示指定は帳より優先し、不一致は警告して通常の儀式へ戻す(自動失敗に
 * しない — 正当な鍵更新があり得る)。儀式 / フラグ照合の成功は帳へ記録する。
 */
function confirmInviteeFingerprint(input: {
  readonly origin: string;
  readonly targetUserId: string;
  readonly role: Role;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "The acceptance key's fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.targetUserId,
      fingerprintHex: input.fingerprintHex,
    });
    // 帳のヒットを使えるのは対話端末 + フラグなし + 非エージェントの経路だけ
    // (判定は usableBookHit)。そのときは読み上げ照合の指示 2 行を落とす
    // (通話を指示した直後に「要らない」と言わない)
    const hit = yield* usableBookHit({
      book,
      flagProvided: input.expectFingerprintHex !== null,
      isAgent: io.agentProfile().isAgent,
    });
    const lines = [
      "Acceptor's key fingerprint (mutual confirmation — CRYPTO_SPEC §6.5):",
      `  invitee: ${displayText(input.targetUserId)}`,
      `  role:    ${input.role} (will be granted to this member)`,
      `  hex:  ${input.fingerprintHex}`,
      "  word: " + formatWordList(words),
      ...(hit !== null
        ? []
        : [
            "Check that this word list matches the 12 words the acceptor reads to you out of band (e.g. over a call).",
            "If they do not match, the acceptance has been hijacked (an attacker's key was injected) — abort add_member and revoke the invite.",
          ]),
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectFingerprintHex !== null) {
      if (input.expectFingerprintHex !== input.fingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--expect-fingerprint does not match the acceptance key's fingerprint. The acceptance may have been hijacked — add_member was aborted (revoke the invite and reissue)",
          ),
        );
      }
      yield* io.log(
        "--expect-fingerprint matches (continuing; the out-of-band record counts as checked)",
      );
      yield* book.record;
      return;
    }
    yield* book.warnIfChanged;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the acceptance-key confirmation ceremony: an AI agent environment was detected. Run this yourself in a terminal, or pass the acceptance key fingerprint noted out of band via --expect-fingerprint",
        ),
      );
    }
    if (hit !== null) {
      return yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to add ${displayText(input.targetUserId)} as ${input.role} with this previously verified key`,
        cancelText: "add_member was cancelled.",
      });
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against the acceptor's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Acceptance key fingerprint confirmation failed (the re-typed word does not match). add_member was not performed — re-run once you can check with the acceptor",
    });
    yield* book.record;
  });
}

/**
 * 宛先 login の解決(充足形 4 の (iii)): `--github` → 発行ピンの宛先。無しは
 * null = 儀式へ。対話入力は設けない(儀式の再入力プロンプトと混ざり、また
 * 打ち間違いが「別人の GitHub」への問い合わせになる — 名指しは発行時か
 * フラグの明示的作為に限る)。
 */
function resolveAddresseeLogin(input: {
  readonly flagLogin: string | null;
  readonly pinLogin: string | null;
}): Effect.Effect<string | null, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.flagLogin !== null) {
      return input.flagLogin;
    }
    if (input.pinLogin !== null) {
      yield* io.log(
        `The invite was issued for github.com/${input.pinLogin} (recorded at issuance on this machine)`,
      );
      return input.pinLogin;
    }
    return null;
  });
}

/**
 * 未登録時の二択(補足 21 裁定 D ④): 相手の GitHub に鍵が無いとき、儀式へ入る前に
 * 「頼んで再実行」か「今すぐ儀式」かを聞く。対話端末 + 非エージェント + フラグ
 * なしのときだけ(非対話ではフラグ経路のみ — 従来どおり)。yes = 儀式へ進む。
 */
function askCeremonyOrWait(input: {
  readonly login: string;
  readonly flagProvided: boolean;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const interactive =
      !io.agentProfile().isAgent &&
      (yield* stdio.stdinIsTerminal) &&
      (yield* stdio.stdoutIsTerminal);
    if (!interactive || input.flagProvided) {
      return;
    }
    yield* io.log(
      `github.com/${input.login} has not registered this key as a signing key. Ask them to run \`maruhi key publish\` and re-run \`maruhi member add\` to add them without a call, or confirm the 12 words with them now`,
    );
    const answer = yield* io.promptLine({
      prompt:
        "Type yes to confirm the 12 words now; anything else to stop and wait for their registration: ",
    });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          `add_member was not performed. Ask github.com/${input.login} to register their key with \`maruhi key publish\`, then re-run \`maruhi member add\``,
        ),
      );
    }
  });
}

/**
 * 招待者側の充足形 4(CRYPTO_SPEC §6.5 — IV2): 発行文・両署名の検証(呼び出し側
 * で済み)に加えて、裏付け元が「受諾の sig 鍵は名指しした相手の鍵である」と照合
 * できたとき、**確認入力なしに** add_member へ進んでよい(名指しは発行時の明示的
 * 作為)。`--expect-fingerprint` が同時に指定されていれば照合に加えて要求し、
 * 不一致は拒否する。照合の不能(裏付け元 `none`・宛先なし・未登録・取得不能)は
 * false = 充足形 1〜3(confirmInviteeFingerprint)へ戻る。
 */
function confirmInviteeViaBacking(input: {
  readonly identityBacking: IdentityBacking;
  readonly flagLogin: string | null;
  readonly pinLogin: string | null;
  readonly sigPubHex: string;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<boolean, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.identityBacking === "none") {
      if (input.flagLogin !== null) {
        yield* logNote(
          "identityBacking is none, so --github cannot be checked against github.com — falling back to the fingerprint confirmation",
        );
      }
      return false;
    }
    const login = yield* resolveAddresseeLogin({
      flagLogin: input.flagLogin,
      pinLogin: input.pinLogin,
    });
    if (login === null) {
      yield* logNote(
        "no GitHub login to check the acceptance key against (pass --github <login>, or name the invitee with `maruhi invite create --github`) — falling back to the fingerprint confirmation",
      );
      return false;
    }
    const verdict = yield* checkSigningKeyBacking({ login, sigPubHex: input.sigPubHex });
    if (verdict.kind === "not-registered") {
      yield* askCeremonyOrWait({ login, flagProvided: input.expectFingerprintHex !== null });
      yield* logNote(
        `${describeBackingFallback(login, verdict)} — falling back to the fingerprint confirmation`,
      );
      return false;
    }
    if (verdict.kind !== "match") {
      yield* logNote(
        `${describeBackingFallback(login, verdict)} — falling back to the fingerprint confirmation`,
      );
      return false;
    }
    if (
      input.expectFingerprintHex !== null &&
      input.expectFingerprintHex !== input.fingerprintHex
    ) {
      return yield* Effect.fail(
        cliError(
          "--expect-fingerprint does not match the acceptance key's fingerprint. The acceptance may have been hijacked — add_member was aborted (revoke the invite and reissue)",
        ),
      );
    }
    yield* io.log(
      `Acceptance key verified: it is registered as a signing key on github.com/${login}, and the acceptance is bound to the link you issued (CRYPTO_SPEC §6.5) — no 12-word call is needed`,
    );
    yield* io.log(`  fp:   ${input.fingerprintHex}`);
    return true;
  });
}

/** add_member の実行者 role 規則(§6.2)の早期検査(不成立なら理由の文字列)。 */
function addActorRejection(actor: ChainMember | undefined, role: Role): string | null {
  if (actor === undefined || ROLE_RANK[actor.role] < ROLE_RANK.admin) {
    return "Only admins and above can run add_member (CRYPTO_SPEC §6.2)";
  }
  if (ROLE_RANK[role] >= ROLE_RANK.admin && actor.role !== "owner") {
    return "Only an owner can run a role=admin add_member (CRYPTO_SPEC §6.2)";
  }
  return null;
}

/** メンバー鍵一意性(§6.2 duplicate-member-key)の早期検査(不成立なら理由)。 */
function duplicateMemberKeyRejection(
  verified: VerifiedProject,
  acceptance: InviteAcceptance,
): string | null {
  for (const member of verified.state.members.values()) {
    if (
      member.encPubHex === acceptance.inviteeEncPubHex ||
      member.sigPubHex === acceptance.inviteeSigPubHex
    ) {
      return `The acceptance key equals current member ${displayText(member.userId)}'s key (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2). add_member cannot proceed with this acceptance`;
    }
  }
  return null;
}

/** add_member の追記前検査(CAS リトライの再同期後にも同じ検査を通す)。 */
function ensureAddable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly acceptance: InviteAcceptance;
  readonly role: Role;
}): Effect.Effect<{ readonly alreadyAdded: boolean }, CliError> {
  return Effect.gen(function* () {
    const actor = input.verified.state.members.get(input.signerUserId);
    const actorRejection = addActorRejection(actor, input.role);
    if (actorRejection !== null) {
      return yield* Effect.fail(cliError(actorRejection));
    }
    const existing = input.verified.state.members.get(input.acceptance.inviteeUserId);
    if (existing !== undefined) {
      if (
        existing.encPubHex === input.acceptance.inviteeEncPubHex &&
        existing.sigPubHex === input.acceptance.inviteeSigPubHex
      ) {
        // 追記済み(前回実行の中断・並行実行)— バックフィルのみの再開へ
        return { alreadyAdded: true };
      }
      return yield* Effect.fail(
        cliError(
          "The target user ID is already a member with a different key (the acceptance block contradicts the chain). Another acceptance may already have been added, or the acceptances were mixed up — check the state with `maruhi invite list` and `maruhi project verify`",
        ),
      );
    }
    const keyRejection = duplicateMemberKeyRejection(input.verified, input.acceptance);
    if (keyRejection !== null) {
      return yield* Effect.fail(cliError(keyRejection));
    }
    return { alreadyAdded: false };
  });
}

/** add_member エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。 */
function signAddMemberEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly acceptance: InviteAcceptance;
  readonly role: Role;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "add_member",
      payload: {
        targetUserId: input.acceptance.inviteeUserId,
        encPubHex: input.acceptance.inviteeEncPubHex,
        sigPubHex: input.acceptance.inviteeSigPubHex,
        role: input.role,
      },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the add_member entry",
  });
}

/** バックフィル 1 環境分の結果。 */
interface MemberBackfillResult {
  readonly registered: number;
  readonly alreadyRegistered: number;
  readonly repaired: number;
}

/**
 * 1 環境の全エポックの新メンバー宛バックフィル(CRYPTO_SPEC §7 — 新規メンバーは
 * 履歴も読める。共有核 = backfill.ts)。
 *
 * **再追加の自動修復(B1b 裁定 + §12-6 追補)**: エポック単位の 409 は
 * 「旧在籍時の旧鍵ラップがスロットを占有している」可能性がある。放置すると
 * 再追加メンバーは当該エポックを復号できない(409 を登録済み扱いにすると
 * 不可視化する)ため、旧鍵ラップと判定したら §12-6 の修復経路(削除 → 再登録)で
 * 新鍵ラップへ置換する。判定は 409 応答の保存済み受信者 enc 公開鍵
 * (`storedRecipientEncPubHex` — AUTH_SPEC §12-6)と受諾鍵の**厳密比較**を優先し
 * (復号可能性 = enc 鍵一致そのもの)、応答に無い場合(追補以前のセルフホスト
 * サーバー)に限り従来の鍵履歴ヒューリスティック(`staleWrapSuspected`)へ
 * フォールバックする。ヒューリスティック経路で占有ラップが実は現行鍵だった
 * としても、削除 → 再登録は同内容への収束であり安全。
 */
function backfillMemberEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly staleWrapSuspected: boolean;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<MemberBackfillResult, CliError> {
  const register = registerWraps(input.client, input.verified.projectId, input.environmentId);
  return backfillEnvironmentFor({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    wrapRecipient: { kind: "member", member: input.target },
    recipientLabel: "new-member-addressed",
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    onSlotConflict: (wrap, storedRecipientEncPubHex) =>
      Effect.gen(function* () {
        // 占有スロットが旧鍵ラップか: 応答の保存済み enc 公開鍵との厳密比較を
        // 優先(一致 = 現行鍵で登録済み = 冪等)。無い場合のみ推定へ劣化
        const staleWrap =
          storedRecipientEncPubHex === null
            ? input.staleWrapSuspected
            : storedRecipientEncPubHex !== input.target.encPubHex;
        if (!staleWrap) {
          return "already-registered" as const;
        }
        // 修復経路(§12-6): 占有スロットを削除して新鍵ラップを再登録する
        yield* input.client.deks
          .remove({
            params: { projectId: input.verified.projectId, environmentId: input.environmentId },
            payload: { wraps: [{ epoch: wrap.epoch, recipientUserId: input.target.userId }] },
          })
          .pipe(
            Effect.asVoid,
            Effect.catch((error) =>
              // 並行修復でスロットが消えた場合は再登録だけ行えばよい
              error instanceof DekWrapNotFoundError ? Effect.void : Effect.fail(toCliError(error)),
            ),
          );
        // 削除 → 再登録は原子的でない: ここで再登録が失敗するとスロットは
        // 空のまま残る。汎用の失敗文言に紛れさせず状態を明示する(再実行は
        // 空スロットへの直登録になるため、そのまま復旧経路になる)
        const retried = yield* register([wrap]).pipe(
          Effect.mapError((error) =>
            cliError(
              `After the repair path deleted the old wrap, re-registering the new-key wrap failed — the epoch ${wrap.epoch} slot remains empty (the target cannot decrypt this epoch; a re-run recovers it as a direct registration into the empty slot): ${error.message}`,
            ),
          ),
        );
        // 削除と再登録の間に並行実行が登録した場合、受理検査(§12-6 の受信者
        // 一致)は現チェーンの鍵で通っているため、新鍵ラップとして収束済み
        return retried.kind === "ok" ? ("repaired" as const) : ("already-registered" as const);
      }),
  });
}

/**
 * member add の前段: 招待の選択 → 発行ピン突合 → §6.5 独立検証 → 追記前検査 →
 * FP 確認の儀式。儀式は追記の有無に関わらず行う(バックフィルだけの再実行でも、
 * これからラップを配る鍵の照合を省略しない — server grant と同じ規律)。
 */
function prepareMemberAdd(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string | null;
  readonly expectFingerprintHex: string | null;
  /** `--github <login>`(裏付け元の照合先。発行ピンの宛先より優先)。 */
  readonly githubLogin: string | null;
  readonly identityBacking: IdentityBacking;
  readonly pins: InvitePins | null;
  readonly signerUserId: string;
  readonly origin: string;
}): Effect.Effect<
  {
    readonly row: AddableRow;
    readonly alreadyAdded: boolean;
  },
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const listed = yield* listInvitations(input.client, input.verified.projectId);
    const row = yield* selectInvitation(listed, input.inviteId);

    // 発行文の検証(CRYPTO_SPEC §6.5 — IV): 行の発行署名をチェーン導出の招待者鍵で
    // 検証する。自分が発行した行なら自分の鍵で「自分の発行か」が固定される
    // (発行ピンに依存しない)。失敗 = 行のすり替え / 改竄 → 拒否
    const issuance = yield* verifyIssuance({ verified: input.verified, row });
    if (!issuance.ok) {
      return yield* Effect.fail(
        cliError(`This invite ${issuanceFailureText(issuance.reason)}. add_member was aborted`),
      );
    }

    // 発行ピン突合(SHOULD — 発行時の link_pub / role とサーバー申告の一致)。
    // ピンがない場合(別デバイスでの発行・保持窓超過)は発行署名の検証だけが
    // 行を固定する(IV 改訂で真実源は発行署名へ移った)
    const pin = pinMismatchOf(input.pins, row);
    if (pin === "mismatch") {
      return yield* Effect.fail(
        cliError(
          "The server's claim for the invite row (link key / role) does not match the local record from issuance. The row may have been swapped or the role tampered with — add_member was aborted",
        ),
      );
    }
    if (pin === "missing") {
      yield* logNote(
        "this machine has no issuance pin for this invite (it may have been issued on another device). The issue signature still fixes the row; only the addressee login recorded at issuance is unavailable here",
      );
    }

    // §6.5 の独立検証(サーバー申告の検証結果を信用しない): リンク署名 → 受諾署名
    const acceptanceVerified = yield* verifyAcceptanceBlock({
      projectId: input.verified.projectId,
      issuance: row.issuance,
      acceptance: row.acceptance,
    });
    if (!acceptanceVerified.ok) {
      return yield* Effect.fail(
        cliError(
          `For this invite, ${acceptanceFailureText(acceptanceVerified.which)}. This acceptance block cannot be trusted — add_member was aborted (revoke the invite)`,
        ),
      );
    }

    const first = yield* ensureAddable({
      verified: input.verified,
      signerUserId: input.signerUserId,
      acceptance: row.acceptance,
      role: row.role,
    });

    // 充足形 4(裏付け元)→ 不成立なら充足形 1〜3(儀式 / フラグ / 帳)
    const backed = yield* confirmInviteeViaBacking({
      identityBacking: input.identityBacking,
      flagLogin: input.githubLogin,
      pinLogin: issuedPinOf(input.pins, row.id)?.expectedGithubLogin ?? null,
      sigPubHex: row.acceptance.inviteeSigPubHex,
      fingerprintHex: acceptanceVerified.fingerprintHex,
      expectFingerprintHex: input.expectFingerprintHex,
    });
    if (!backed) {
      yield* confirmInviteeFingerprint({
        origin: input.origin,
        targetUserId: row.acceptance.inviteeUserId,
        role: row.role,
        fingerprintHex: acceptanceVerified.fingerprintHex,
        expectFingerprintHex: input.expectFingerprintHex,
      });
    }
    return { row, alreadyAdded: first.alreadyAdded };
  });
}

/** バックフィルの全環境走査(1 環境の失敗で残りを止めない — §7)。 */
function backfillAllEnvironments(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly staleWrapSuspected: boolean;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError
> {
  return Effect.gen(function* () {
    // チェーン導出の全環境(検証済み削除を除く)× 全エポック
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const environments = [...input.verified.state.environments.keys()]
      .filter((environmentId) => !deletedVerified.has(environmentId))
      .toSorted();
    let registered = 0;
    let alreadyRegistered = 0;
    let repaired = 0;
    const failed: { readonly environmentId: string; readonly message: string }[] = [];
    for (const environmentId of environments) {
      const result = yield* backfillMemberEnvironment({ ...input, environmentId }).pipe(
        Effect.map((outcome) => ({ kind: "ok", outcome }) as const),
        Effect.catch((error) =>
          Effect.succeed({ kind: "failed", message: error.message } as const),
        ),
      );
      if (result.kind === "ok") {
        registered += result.outcome.registered;
        alreadyRegistered += result.outcome.alreadyRegistered;
        repaired += result.outcome.repaired;
      } else {
        failed.push({ environmentId, message: result.message });
      }
    }
    return { registered, alreadyRegistered, repaired, failed };
  });
}

export function memberAddOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly inviteId: string | null;
  readonly expectFingerprintHex: string | null;
  readonly githubLogin: string | null;
  readonly identityBacking: IdentityBacking;
  readonly pins: InvitePins | null;
  readonly signerUserId: string;
  readonly origin: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<
  MemberAddSummary,
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { row, alreadyAdded } = yield* prepareMemberAdd(input);

    let verified = input.verified;
    let appended = false;
    if (alreadyAdded) {
      yield* io.log(
        "The target is already a member with the same key — skipping add_member and running only the backfill (crash recovery)",
      );
    } else {
      const outcome = yield* appendWithCas({
        client: input.client,
        verified,
        resync: input.resync,
        opLabel: "add_member",
        signEntry: (view) =>
          signAddMemberEntry({
            verified: view,
            signerUserId: input.signerUserId,
            acceptance: row.acceptance,
            role: row.role,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureAddable({
            verified: view,
            signerUserId: input.signerUserId,
            acceptance: row.acceptance,
            role: row.role,
          }).pipe(Effect.map((rechecked) => ({ already: rechecked.alreadyAdded }))),
      });
      appended = outcome.appended;
      verified = outcome.verified;
    }

    // 受理後の再同期で掲載を確認する(サーバー申告を真実源にしない)
    verified = yield* resyncExtended(input.resync, verified);
    const target = verified.state.members.get(row.acceptance.inviteeUserId);
    if (
      target === undefined ||
      target.encPubHex !== row.acceptance.inviteeEncPubHex ||
      target.sigPubHex !== row.acceptance.inviteeSigPubHex
    ) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_member was accepted does not show the member (with the acceptance key) on the chain (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    if (appended) {
      yield* io.log(
        `Appended add_member to the chain (target=${displayText(target.userId)}, role=${row.role}, seq=${verified.state.headSeq})`,
      );
    }

    // 再追加(過去在籍が別鍵)の検出: 鍵履歴に受諾鍵と異なる束縛があるか。
    // 409 の判定は応答の保存済み enc 公開鍵との厳密比較が優先で(AUTH_SPEC
    // §12-6 追補)、このヒューリスティックは応答にフィールドが無い旧サーバー
    // への 409 だけに使うフォールバックである。なお追補済みサーバーは
    // add_member 受理時に旧鍵宛ラップを自動掃除するため(同追補)、通常は
    // 409 自体が「現行鍵で登録済み」しか意味しない
    const staleWrapSuspected = (verified.keyHistory.get(target.userId) ?? []).some(
      (binding) =>
        binding.encPubHex !== row.acceptance.inviteeEncPubHex ||
        binding.sigPubHex !== row.acceptance.inviteeSigPubHex,
    );
    if (staleWrapSuspected) {
      yield* io.log(
        "The target user ID was previously a member with a different key. If leftover wraps addressed to the old key are found, the repair path (delete → re-register) replaces them with the new key (CRYPTO_SPEC §7 / AUTH_SPEC §12-6)",
      );
    }

    const backfilled = yield* backfillAllEnvironments({
      client: input.client,
      verified,
      recipient: input.recipient,
      target,
      staleWrapSuspected,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
    return { appended, targetUserId: target.userId, role: row.role, ...backfilled };
  });
}

// ---------------------------------------------------------------------------
// member remove
// ---------------------------------------------------------------------------

export interface MemberRemoveSummary extends SweepOutcome {
  /** チェーンへ追記したか(false = 既に削除済み — ローテーションの続きから再開)。 */
  readonly appended: boolean;
  readonly targetUserId: string;
  readonly skippedDeleted: readonly string[];
}

/** remove の追記前検査(CAS リトライの再同期後にも同じ検査を通す)。 */
function ensureRemovable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
}): Effect.Effect<{ readonly alreadyRemoved: boolean }, CliError> {
  return Effect.gen(function* () {
    if (input.targetUserId === input.signerUserId) {
      return yield* Effect.fail(
        cliError(
          "You cannot remove yourself. You would be unable to run the post-removal rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to remove you",
        ),
      );
    }
    const { actor, target } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    if (target === undefined) {
      // 削除済みからの再開(中断復旧): チェーン上に当該 user_id の remove が
      // あることを要求する(タイプミスの user_id で sweep が走る形を作らない)
      const removedBefore = input.verified.entries.some(
        (entry) =>
          entry.op === "remove_member" && entry.payload.targetUserId === input.targetUserId,
      );
      if (!removedBefore) {
        return yield* Effect.fail(
          cliError(
            "The target is not a member and the chain has no removal record for it (check the user ID)",
          ),
        );
      }
      if (ROLE_RANK[actor.role] < ROLE_RANK.member) {
        return yield* Effect.fail(
          cliError("Resuming the rotation requires the member role or above (CRYPTO_SPEC §6.2)"),
        );
      }
      return { alreadyRemoved: true };
    }
    const rejection = targetedOpRejection({ actor, target, operation: "remove_member" });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    if (target.role === "owner" && ownersCount(input.verified) === 1) {
      return yield* Effect.fail(
        cliError("The last owner cannot be removed (CRYPTO_SPEC §6.2 last-owner-protected)"),
      );
    }
    return { alreadyRemoved: false };
  });
}

/** remove_member エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。 */
function signRemoveEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: { op: "remove_member", payload: { targetUserId: input.targetUserId } },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the remove_member entry",
  });
}

export function memberRemoveOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotate: SweepRotate<R>;
}): Effect.Effect<MemberRemoveSummary, CliError, R> {
  return Effect.gen(function* () {
    const first = yield* ensureRemovable({
      verified: input.verified,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
    });

    let verified = input.verified;
    let appended = false;
    if (!first.alreadyRemoved) {
      const outcome = yield* appendWithCas({
        client: input.client,
        verified,
        resync: input.resync,
        opLabel: "remove_member",
        signEntry: (view) =>
          signRemoveEntry({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureRemovable({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
          }).pipe(Effect.map((rechecked) => ({ already: rechecked.alreadyRemoved }))),
      });
      verified = outcome.verified;
      appended = outcome.appended;
    }

    // 受理後の再同期で削除の掲載を確認(サーバー申告を真実源にしない)
    verified = yield* resyncExtended(input.resync, verified);
    if (verified.state.members.has(input.targetUserId)) {
      return yield* Effect.fail(
        cliError(
          "The resync after remove_member was accepted still shows the target as a member (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }

    // 対象の remove エントリ(今回の追記 or 履歴上のもの)が基準になる。ここで
    // null は「削除は確認済みなのに義務エントリがない」= 導出の内部矛盾
    const baselineSeq = lastRotationMandateSeqFor(verified, input.targetUserId);
    if (baselineSeq === null) {
      return yield* Effect.fail(
        cliError(
          "Cannot find the rotation-mandate entry on the chain (internal contradiction in the derivation)",
        ),
      );
    }
    const sweep = yield* sweepAfterMandate({
      client: input.client,
      verified,
      baselineSeq,
      rotate: input.rotate,
    });
    return { appended, targetUserId: input.targetUserId, ...sweep };
  });
}

// ---------------------------------------------------------------------------
// member change-role
// ---------------------------------------------------------------------------

export interface MemberChangeRoleSummary {
  /** チェーンへ追記したか(false = 既に対象 role — 降格なら sweep の再開のみ)。 */
  readonly appended: boolean;
  readonly targetUserId: string;
  readonly newRole: Role;
  /** 降格(member 未満)に伴う全環境ローテーションの結果(降格以外は null)。 */
  readonly sweep: (SweepOutcome & { readonly skippedDeleted: readonly string[] }) | null;
}

/** change_role の role 規則(§6.2)の早期検査(不成立なら理由の文字列)。 */
function changeRoleRuleRejection(input: {
  readonly verified: VerifiedProject;
  readonly actor: ChainMember;
  readonly target: ChainMember;
  readonly newRole: Role;
}): string | null {
  const base = targetedOpRejection({
    actor: input.actor,
    target: input.target,
    operation: "change_role",
  });
  if (base !== null) {
    return base;
  }
  if (ROLE_RANK[input.newRole] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return "Only an owner can change a role to admin / owner (CRYPTO_SPEC §6.2)";
  }
  if (
    input.target.role === "owner" &&
    input.newRole !== "owner" &&
    ownersCount(input.verified) === 1
  ) {
    return "The last owner cannot be demoted (CRYPTO_SPEC §6.2 last-owner-protected)";
  }
  return null;
}

/** change_role の追記前検査(CAS リトライの再同期後にも同じ検査を通す)。 */
function ensureRoleChangeable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly newRole: Role;
}): Effect.Effect<{ readonly alreadyChanged: boolean }, CliError> {
  return Effect.gen(function* () {
    const { actor, target } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    if (target === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    if (
      input.targetUserId === input.signerUserId &&
      ROLE_RANK[target.role] >= ROLE_RANK.member &&
      ROLE_RANK[input.newRole] < ROLE_RANK.member
    ) {
      return yield* Effect.fail(
        cliError(
          "You cannot demote yourself below member. You would be unable to run the post-demotion rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to demote you",
        ),
      );
    }
    if (target.role === input.newRole) {
      // 追記済み(前回実行の中断・並行実行)または no-op。降格の中断復旧
      // (エントリは載ったが sweep が未了)をここから再開できる形にする
      return { alreadyChanged: true };
    }
    const rejection = changeRoleRuleRejection({
      verified: input.verified,
      actor,
      target,
      newRole: input.newRole,
    });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    return { alreadyChanged: false };
  });
}

/** change_role エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。 */
function signChangeRoleEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "change_role",
      payload: { targetUserId: input.targetUserId, newRole: input.newRole },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the change_role entry",
  });
}

export function memberChangeRoleOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotate: SweepRotate<R>;
}): Effect.Effect<MemberChangeRoleSummary, CliError, R> {
  return Effect.gen(function* () {
    const first = yield* ensureRoleChangeable({
      verified: input.verified,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
      newRole: input.newRole,
    });

    let verified = input.verified;
    let appended = false;
    if (!first.alreadyChanged) {
      const outcome = yield* appendWithCas({
        client: input.client,
        verified,
        resync: input.resync,
        opLabel: "change_role",
        signEntry: (view) =>
          signChangeRoleEntry({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            newRole: input.newRole,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureRoleChangeable({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            newRole: input.newRole,
          }).pipe(Effect.map((rechecked) => ({ already: rechecked.alreadyChanged }))),
      });
      verified = outcome.verified;
      appended = outcome.appended;
    }

    // 受理後の再同期で role の掲載を確認(サーバー申告を真実源にしない)
    verified = yield* resyncExtended(input.resync, verified);
    const target = verified.state.members.get(input.targetUserId);
    if (target === undefined || target.role !== input.newRole) {
      return yield* Effect.fail(
        cliError(
          "The resync after change_role was accepted does not show the target's new role (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }

    if (ROLE_RANK[input.newRole] >= ROLE_RANK.member) {
      // 昇格・member 以上どうしの変更にローテーション義務はない(§7 の対象は
      // member 未満への降格のみ)
      return { appended, targetUserId: input.targetUserId, newRole: input.newRole, sweep: null };
    }
    // member 未満への降格は全環境ローテーション義務(§7 — エポックアンカーの
    // 健全性)。alreadyChanged からの再開でも、**対象の**義務エントリがチェーンに
    // あれば sweep が force / verify を分類して収束させる。対象の義務エントリが
    // ない場合(最初から reader として追加されたメンバーへの no-op 再実行)は
    // 義務自体が発生していないので何もしない — 他人の未収束義務をここで拾わない
    const baselineSeq = lastRotationMandateSeqFor(verified, input.targetUserId);
    if (baselineSeq === null) {
      return { appended, targetUserId: input.targetUserId, newRole: input.newRole, sweep: null };
    }
    const sweep = yield* sweepAfterMandate({
      client: input.client,
      verified,
      baselineSeq,
      rotate: input.rotate,
    });
    return { appended, targetUserId: input.targetUserId, newRole: input.newRole, sweep };
  });
}
