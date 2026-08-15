// `maruhi member add|remove|change-role`(CRYPTO_SPEC §6.2 / §6.5 / §7、
// AUTH_SPEC §12-6 / §15 — Wave 2 B1b)。
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
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { backfillEnvironmentFor, registerWraps } from "./backfill.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import {
  type InvitationRow,
  type InviteAcceptance,
  listInvitations,
  verifyAcceptanceBlock,
} from "./invite.ts";
import { CliIo } from "./io.ts";
import { type InvitePins, issuedPinOf } from "./pins.ts";
import { retryOnConflict } from "./retry.ts";
import {
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
 * newRole が member 未満」の `change_role`(降格の義務 — §7)。直前 role は
 * 検証済み履歴(memberStateAt の inclusive 規約 — seq-1 で適用前)から取る。
 *
 * 対象スコープにするのは、各コマンドが収束させる義務を**自分の操作の分**に
 * 限定するため(Cursor bot 指摘): 大域の最終義務を基準にすると、born-reader への
 * no-op 再実行が**他人の**未収束義務を拾って全環境ローテーションを開始する。
 * 対象の義務エントリ以降のローテーションは対象の偽造可能座標を閉じる(§7)ため、
 * 対象スコープでも自分の義務を過小に満たすことはない(他人の未収束義務は
 * その操作の再実行、または B2 の要ローテーション検出の責務)。
 */
function lastRotationMandateSeqFor(verified: VerifiedProject, targetUserId: string): number | null {
  for (let index = verified.entries.length - 1; index >= 0; index -= 1) {
    const entry = verified.entries[index];
    if (entry === undefined || !mandatesRotationFor(verified, entry, targetUserId)) {
      continue;
    }
    return entry.seq;
  }
  return null;
}

/** entry が対象 user_id のローテーション義務エントリか(§7)。 */
function mandatesRotationFor(
  verified: VerifiedProject,
  entry: ChainEntry,
  targetUserId: string,
): boolean {
  if (entry.op === "remove_member") {
    return entry.payload.targetUserId === targetUserId;
  }
  if (
    entry.op === "change_role" &&
    entry.payload.targetUserId === targetUserId &&
    ROLE_RANK[entry.payload.newRole] < ROLE_RANK.member
  ) {
    const before = verified.history.memberStateAt(targetUserId, entry.seq - 1);
    return before !== undefined && ROLE_RANK[before.role] >= ROLE_RANK.member;
  }
  return false;
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
      exhaustedMessage: `${input.opLabel} のチェーンヘッド競合が解消しません(${MAX_ATTEMPTS} 回試行)。時間をおいて再実行してください`,
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
    return Effect.fail(cliError("このプロジェクトのチェーン導出メンバーではありません"));
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
    return `${input.operation}は admin 以上のみが実行できます(CRYPTO_SPEC §6.2)`;
  }
  if (ROLE_RANK[input.target.role] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return `admin / owner を対象とする${input.operation}は owner のみが実行できます(CRYPTO_SPEC §6.2)`;
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
): Effect.Effect<InvitationRow & { readonly acceptance: InviteAcceptance }, CliError> {
  if (inviteId !== null) {
    const row = rows.find((candidate) => candidate.id === inviteId);
    if (row === undefined) {
      return Effect.fail(
        cliError("指定の招待が見つかりません(maruhi invite list で id を確認してください)"),
      );
    }
    if (row.status === "revoked") {
      return Effect.fail(cliError("指定の招待は失効済みです(受諾ブロックがあっても使用しません)"));
    }
    if (!withAcceptance(row)) {
      return Effect.fail(
        cliError(
          "指定の招待はまだ受諾されていません(受諾後に maruhi invite list で確認してください)",
        ),
      );
    }
    return Effect.succeed(row);
  }
  const accepted = rows.filter(withAcceptance).filter((row) => row.status === "accepted");
  const first = accepted[0];
  if (first === undefined) {
    // completed 行は自動選択しない(過去メンバー全員の行が completed のまま
    // 蓄積するため曖昧)。add_member 済み招待のバックフィル再開は id 明示の
    // 経路が受ける — その導線をここで示す(Cursor bot 指摘)
    return Effect.fail(
      cliError(
        "受諾済み(accepted)の招待がありません。add_member まで完了した招待のバックフィルを再開する場合は、maruhi invite list で id を確認し、maruhi member add <招待id> と id を明示してください",
      ),
    );
  }
  if (accepted.length > 1) {
    return Effect.fail(
      cliError(
        `受諾済みの招待が複数あります(${accepted.map((row) => displayText(row.id)).join(", ")})。対象の招待 id を指定してください`,
      ),
    );
  }
  return Effect.succeed(first);
}

/**
 * 招待者側の相互確認(§6.5 — 必須 UX): 受諾鍵の FP ワード列と付与 role を
 * 表示し、帯域外照合の明示確認を要求する。儀式は再実行(バックフィルのみの
 * 中断復旧)でも省略しない(server-grant と同じ規律 — これからラップを配る鍵の
 * 照合を省略しない)。
 */
function confirmInviteeFingerprint(input: {
  readonly targetUserId: string;
  readonly role: Role;
  readonly fingerprintHex: string;
  readonly expectFingerprintHex: string | null;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "受諾鍵のフィンガープリント形式が不正です",
    );
    const lines = [
      "受諾者の鍵フィンガープリント(CRYPTO_SPEC §6.5 の相互確認):",
      `  invitee: ${displayText(input.targetUserId)}`,
      `  role:    ${input.role}(このメンバーに付与されます)`,
      `  hex:  ${input.fingerprintHex}`,
      "  word: " + formatWordList(words),
      "この語列が、受諾者本人が帯域外(通話等)で読み上げる 12 語と一致することを照合してください。",
      "一致しない場合、受諾は横取りされています(攻撃者の鍵の混入)— add_member を中止し、招待を失効させてください。",
    ];
    for (const line of lines) {
      yield* io.log(line);
    }
    if (input.expectFingerprintHex !== null) {
      if (input.expectFingerprintHex !== input.fingerprintHex) {
        return yield* Effect.fail(
          cliError(
            "--expect-fingerprint が受諾鍵の FP と一致しません。受諾の横取りの可能性があります — add_member を中止しました(招待を失効させ、再発行してください)",
          ),
        );
      }
      yield* io.log(
        "--expect-fingerprint と一致しました(帯域外の控えとの照合済みとして続行します)",
      );
      return;
    }
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "AI エージェント環境を検出したため、受諾鍵 FP 確認の儀式を実行できません。人間が実行するか、帯域外で控えた受諾鍵 FP を --expect-fingerprint で明示してください",
        ),
      );
    }
    return yield* confirmByLastWord({
      words,
      promptText:
        "帯域外(通話等)で受諾者本人の読み上げと照合できたら、表示された 12 語の最後の語を入力してください",
      mismatchText: "入力が一致しません。表示された語列の最後の語を入力してください",
      exhaustedText:
        "受諾鍵 FP の確認に失敗しました(語の再入力が一致しません)。add_member は実行していません — 受諾者本人と照合できてから再実行してください",
    });
  });
}

/** add_member の実行者 role 規則(§6.2)の早期検査(不成立なら理由の文字列)。 */
function addActorRejection(actor: ChainMember | undefined, role: Role): string | null {
  if (actor === undefined || ROLE_RANK[actor.role] < ROLE_RANK.admin) {
    return "add_member は admin 以上のみが実行できます(CRYPTO_SPEC §6.2)";
  }
  if (ROLE_RANK[role] >= ROLE_RANK.admin && actor.role !== "owner") {
    return "role = admin の add_member は owner のみが実行できます(CRYPTO_SPEC §6.2)";
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
      return `受諾鍵が現メンバー ${displayText(member.userId)} の鍵と一致しています(合意規則 duplicate-member-key — CRYPTO_SPEC §6.2)。この受諾では add_member できません`;
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
          "対象 user_id は既に**別の鍵**で在籍しています(受諾ブロックとチェーンの不一致)。別の受諾の add_member 済みか、受諾の取り違えの可能性があります — maruhi invite list と maruhi project verify で状態を確認してください",
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
    failureText: "add_member エントリの署名に失敗しました",
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
 * **再追加の自動修復(B1b 裁定)**: 対象 user_id の鍵履歴に受諾鍵と異なる鍵が
 * ある(= 過去に別鍵で在籍していた)場合、エポック単位の 409 は「旧在籍時の
 * 旧鍵ラップがスロットを占有している」疑いがある。放置すると再追加メンバーは
 * 当該エポックを復号できない(409 を登録済み扱いにすると不可視化する)ため、
 * §12-6 の修復経路(削除 → 再登録)で新鍵ラップへ置換する。占有ラップが並行
 * 実行の新鍵ラップだったとしても、削除 → 再登録は同内容への収束であり安全。
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
    recipientLabel: "新メンバー宛",
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    onSlotConflict: (wrap) =>
      Effect.gen(function* () {
        if (!input.staleWrapSuspected) {
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
              `修復経路で旧ラップの削除後、新鍵ラップの再登録に失敗しました — epoch ${wrap.epoch} のスロットは空のままです(対象はこのエポックを復号できません。再実行は空スロットへの直登録として復旧します): ${error.message}`,
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
  readonly pins: InvitePins | null;
  readonly signerUserId: string;
}): Effect.Effect<
  {
    readonly row: InvitationRow & { readonly acceptance: InviteAcceptance };
    readonly alreadyAdded: boolean;
  },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const listed = yield* listInvitations(input.client, input.verified.projectId);
    const row = yield* selectInvitation(listed, input.inviteId);

    // 発行ピン突合(発行時の token_hash / role とサーバー申告の一致 — 行の
    // すり替え・role の虚偽申告の機械検出)。ピンがない場合(別デバイスでの
    // 発行・保持窓超過)は儀式の role 表示照合のみに劣化する
    const pin = issuedPinOf(input.pins, row.id);
    if (pin !== undefined && (pin.tokenHashHex !== row.tokenHashHex || pin.role !== row.role)) {
      return yield* Effect.fail(
        cliError(
          "サーバー申告の招待行(token_hash / role)が発行時のローカル記録と一致しません。行のすり替え・role の改竄の可能性があります — add_member を中止しました",
        ),
      );
    }
    if (pin === undefined) {
      yield* io.logError(
        "注意: この招待の発行時ピンがこの端末にありません(別デバイスでの発行など)。表示される role が発行時の意図と一致することを確認してください",
      );
    }

    // §6.5 の独立検証(サーバー申告の検証結果を信用しない)
    const acceptanceVerified = yield* verifyAcceptanceBlock({
      projectId: input.verified.projectId,
      tokenHashHex: row.tokenHashHex,
      acceptance: row.acceptance,
    });
    if (!acceptanceVerified.ok) {
      return yield* Effect.fail(
        cliError(
          "受諾署名の検証に失敗しました(CRYPTO_SPEC §6.5)。この受諾ブロックは信用できません — add_member を中止しました(招待を失効させてください)",
        ),
      );
    }

    const first = yield* ensureAddable({
      verified: input.verified,
      signerUserId: input.signerUserId,
      acceptance: row.acceptance,
      role: row.role,
    });

    yield* confirmInviteeFingerprint({
      targetUserId: row.acceptance.inviteeUserId,
      role: row.role,
      fingerprintHex: acceptanceVerified.fingerprintHex,
      expectFingerprintHex: input.expectFingerprintHex,
    });
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
  readonly pins: InvitePins | null;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<MemberAddSummary, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { row, alreadyAdded } = yield* prepareMemberAdd(input);

    let verified = input.verified;
    let appended = false;
    if (alreadyAdded) {
      yield* io.log(
        "対象は既に同一鍵で在籍しています — add_member をスキップし、バックフィルのみ実行します(中断復旧)",
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
          "add_member の受理後の再同期でメンバーの掲載(受諾鍵との一致)を確認できません(サーバー応答の矛盾)。配布されたチェーンを調査してください",
        ),
      );
    }
    if (appended) {
      yield* io.log(
        `add_member をチェーンへ追記しました(target=${displayText(target.userId)}、role=${row.role}、seq=${verified.state.headSeq})`,
      );
    }

    // 再追加(過去在籍が別鍵)の検出: 鍵履歴に受諾鍵と異なる束縛があるか。
    // ある場合のみ、バックフィルの 409 を旧鍵ラップの疑いとして自動修復する
    const staleWrapSuspected = (verified.keyHistory.get(target.userId) ?? []).some(
      (binding) =>
        binding.encPubHex !== row.acceptance.inviteeEncPubHex ||
        binding.sigPubHex !== row.acceptance.inviteeSigPubHex,
    );
    if (staleWrapSuspected) {
      yield* io.log(
        "対象 user_id は過去に別の鍵で在籍していました。旧鍵宛の残存ラップは修復経路(削除 → 再登録)で新鍵へ置換します(CRYPTO_SPEC §7 / AUTH_SPEC §12-6)",
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
          "自分自身は削除できません。削除後の全環境ローテーション(CRYPTO_SPEC §7)を本人が実行できなくなります — 別の admin / owner に削除を依頼してください",
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
            "対象はメンバーではなく、チェーン上に削除記録もありません(user_id を確認してください)",
          ),
        );
      }
      if (ROLE_RANK[actor.role] < ROLE_RANK.member) {
        return yield* Effect.fail(
          cliError("ローテーションの再開には member 以上の role が必要です(CRYPTO_SPEC §6.2)"),
        );
      }
      return { alreadyRemoved: true };
    }
    const rejection = targetedOpRejection({ actor, target, operation: "remove_member " });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    if (target.role === "owner" && ownersCount(input.verified) === 1) {
      return yield* Effect.fail(
        cliError("最後の owner は削除できません(CRYPTO_SPEC §6.2 last-owner-protected)"),
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
    failureText: "remove_member エントリの署名に失敗しました",
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
          "remove_member の受理後の再同期で対象が削除されていません(サーバー応答の矛盾)。配布されたチェーンを調査してください",
        ),
      );
    }

    // 対象の remove エントリ(今回の追記 or 履歴上のもの)が基準になる。ここで
    // null は「削除は確認済みなのに義務エントリがない」= 導出の内部矛盾
    const baselineSeq = lastRotationMandateSeqFor(verified, input.targetUserId);
    if (baselineSeq === null) {
      return yield* Effect.fail(
        cliError("ローテーション義務エントリをチェーン上に確認できません(導出の内部矛盾)"),
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
    operation: "change_role ",
  });
  if (base !== null) {
    return base;
  }
  if (ROLE_RANK[input.newRole] >= ROLE_RANK.admin && input.actor.role !== "owner") {
    return "admin / owner への変更は owner のみが実行できます(CRYPTO_SPEC §6.2)";
  }
  if (
    input.target.role === "owner" &&
    input.newRole !== "owner" &&
    ownersCount(input.verified) === 1
  ) {
    return "最後の owner は降格できません(CRYPTO_SPEC §6.2 last-owner-protected)";
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
      return yield* Effect.fail(
        cliError("対象がメンバーに見つかりません(user_id を確認してください)"),
      );
    }
    if (
      input.targetUserId === input.signerUserId &&
      ROLE_RANK[target.role] >= ROLE_RANK.member &&
      ROLE_RANK[input.newRole] < ROLE_RANK.member
    ) {
      return yield* Effect.fail(
        cliError(
          "自分自身を member 未満へ降格できません。降格後の全環境ローテーション(CRYPTO_SPEC §7)を本人が実行できなくなります — 別の admin / owner に降格を依頼してください",
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
    failureText: "change_role エントリの署名に失敗しました",
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
          "change_role の受理後の再同期で対象の role を確認できません(サーバー応答の矛盾)。配布されたチェーンを調査してください",
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
