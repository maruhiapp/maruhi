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
import {
  ALL_SCOPE,
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  effectivePermissionOf,
  type EffectivePermission,
  type MemberScope,
  memberScopeOf,
  type ProposableOperation,
  type Role,
  type ScopePayloadFields,
  scopeIncludesEnvironment,
  scopePayloadFieldsOf,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { describeKeyReuse, isApprovalTarget, keyReuseOf } from "./approval-rules.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  type ProposeContext,
  proposeOperation,
  proposeRecheck,
  type ProposedSummary,
} from "./approval.ts";
import { backfillEachEnvironment, backfillEnvironmentFor, registerWraps } from "./backfill.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import type { IdentityBacking } from "./config.ts";
import { deviceReceivesEnvironment, ROLE_RANK } from "./dek-wrap.ts";
import type { DekRecipient } from "./deks.ts";
import { describeDevice, devicesOf, memberHasKeys, ownDeviceBySigningKey } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { checkSigningKeyBacking, describeBackingFallback } from "./github-signing-keys.ts";
import {
  acceptanceFailureText,
  type InvitationRow,
  type InviteAcceptance,
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
import { logNote, logWarning } from "./notice.ts";
import { type InvitePins, issuedPinOf } from "./pins.ts";
import { retryOnConflict } from "./retry.ts";
import {
  baselinesOf,
  partitionSweepBaselines,
  type RotationMandate,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
  verifiedDeletedEnvironmentSet,
} from "./rotation-sweep.ts";
import {
  compareCodePoints,
  describeScope,
  environmentsOfScopeAt,
  requireScopeEnvironmentsExist,
  sameScope,
  scopeChangeAt,
  scopeContains,
} from "./scope.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

const MAX_ATTEMPTS = 5;

/**
 * 四眼(K6)の下での各 op の結果: 方針が内側 op を対象にしていれば `propose` を追記して
 * 終わる(`proposed` — 何も適用されない)。それ以外は従来の適用結果(`applied`)。
 */
export type MemberOpOutcome<S> =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: S };

/** remove / 降格 / 縮小後のローテーションの理由(§6.2 payload の固定文字列)。 */
const MEMBER_REMOVED_ROTATION_REASON = "member-removed";
const ROLE_DEMOTED_ROTATION_REASON = "role-demoted";
const SCOPE_NARROWED_ROTATION_REASON = "scope-narrowed";

// ---------------------------------------------------------------------------
// 共通: ローテーション義務の環境集合と基準 seq(中断復旧の基準 — チェーン導出のみ)
// ---------------------------------------------------------------------------

/**
 * **対象 user_id の**ローテーション義務エントリ(`remove_member` / 降格 / 縮小 —
 * §7)。導出の本体は rotation-sweep.ts の rotationMandates(未収束の常時警告と
 * 同じ 1 導出 — 判定のズレを構造的に防ぐ)。義務の環境集合はエントリごとに
 * 具体化済み(remove = 現 scope、降格 = 新 scope、縮小 = 旧 \ 新 — 設計録 K4-J)。
 *
 * 対象スコープにするのは、各コマンドが収束させる義務を**自分の操作の分**に
 * 限定するため: 大域の義務を基準にすると、born-reader への no-op 再実行が
 * **他人の**未収束義務を拾ってローテーションを開始する。対象の義務エントリ以降の
 * ローテーションは対象の偽造可能座標を閉じる(§7)ため、対象スコープでも自分の
 * 義務を過小に満たすことはない(他人の未収束義務は常時警告 — rotation-sweep.ts —
 * とその操作の再実行の責務)。
 */
function memberMandatesFor(
  verified: VerifiedProject,
  targetUserId: string,
): readonly RotationMandate[] {
  // 端末失効の義務(`device-revoked`)は `device revoke` 自身の sweep(device-ops.ts)が
  // 履行する — member 系コマンドの再実行が他の操作の義務を拾わない(同じ線)
  return rotationMandates(verified).filter(
    (mandate) =>
      mandate.kind !== "server-revoked" &&
      mandate.kind !== "device-revoked" &&
      mandate.target === targetUserId,
  );
}

/** §7 の義務環境の走査(remove / 降格 / 縮小の共有後段。基準は環境 → 最大の義務 seq)。 */
function sweepAfterMandate<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly mandates: readonly RotationMandate[];
  /** 実行者(actor)。scope 外の義務環境は rotate できない(§7)ので対象から外して注記する。 */
  readonly actorUserId: string;
  /** 実行者が署名する端末の鍵(履行できる範囲 = 端末の実効 scope — DK K4-17)。 */
  readonly signingKeyPair: SigningKeyPair;
  /** 義務の種別ごとのローテーション注入(rotate エントリの reason を義務に合わせる)。 */
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome, CliError, R> {
  return Effect.gen(function* () {
    const actorScope = yield* actorEffectiveScope(
      input.verified,
      input.actorUserId,
      input.signingKeyPair,
    );
    // 自分の(端末の実効)scope 外の義務環境(他人が過去に作った縮小 / remove の義務が
    // 対象の履歴に残っている場合、cap 付き端末で実行した場合)は rotate の対象に含めない
    // (CRYPTO_SPEC §7 — 実行者も scope 外なら rotate できない。独立レビュー S2)。
    // 常時警告が引き続き表示する
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const { baselines, outOfScope, skippedDeleted } = partitionSweepBaselines({
      verified: input.verified,
      all: baselinesOf(input.mandates),
      actorScope,
      deletedVerified,
    });
    // 環境ごとの reason = その環境の基準になった義務(最大 seq)の種別(独立レビュー N3)
    const reasons = reasonsByEnvironment(input.mandates);
    const sweep = yield* sweepRotations({
      rotate: (environmentId, mode) =>
        input.rotateWith(reasons.get(environmentId) ?? MEMBER_REMOVED_ROTATION_REASON)(
          environmentId,
          mode,
        ),
      verified: input.verified,
      baselines,
      deletedVerified,
    });
    return { ...sweep, skippedDeleted, outOfScope };
  });
}

/**
 * 実行者が rotate を履行できる環境の範囲 = 署名する端末の実効 scope(人 ∩ 端末 — DK
 * K4-17)。実効 role が member 未満(reader、または member cap の端末)なら空(rotate は
 * member 以上 — §6.2)。非メンバー・未登録端末も空(fail-closed — 常時警告に残る)。
 */
function actorEffectiveScope(
  verified: VerifiedProject,
  actorUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<MemberScope, CliError> {
  return Effect.gen(function* () {
    const actor = verified.state.members.get(actorUserId);
    if (actor === undefined) {
      return { kind: "listed", environmentIds: [] };
    }
    const device = yield* ownDeviceBySigningKey(verified, actor, signingKeyPair).pipe(
      Effect.catch(() => Effect.succeed<ChainDevice | null>(null)),
    );
    if (device === null) {
      return { kind: "listed", environmentIds: [] };
    }
    const permission = effectivePermissionOf(actor, device);
    return ROLE_RANK[permission.role] >= ROLE_RANK.member
      ? permission.scope
      : { kind: "listed", environmentIds: [] };
  });
}

/**
 * 対象の義務(remove / 降格 / 縮小 — 提案経由の適用を含む)の sweep。直接追記の後段と、
 * 四眼で適用を完成させた承認者の履行(approval-approve.ts — 承認項目 22)が共有する。
 */
export function sweepMemberMandates<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly actorUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<MemberSweepOutcome | null, CliError, R> {
  const mandates = memberMandatesFor(input.verified, input.targetUserId);
  return mandates.length === 0 ? Effect.succeed(null) : sweepAfterMandate({ ...input, mandates });
}

/** member 系の sweep の結果(削除済み環境と、実行者の scope 外で回せなかった環境を含む)。 */
export type MemberSweepOutcome = SweepOutcome & {
  readonly skippedDeleted: readonly string[];
  /** 実行者の scope 外で rotate できない義務環境(§7 — 他メンバーの履行に委ねる)。 */
  readonly outOfScope: readonly string[];
};

const MANDATE_REASONS = {
  "member-removed": MEMBER_REMOVED_ROTATION_REASON,
  "role-demoted": ROLE_DEMOTED_ROTATION_REASON,
  "scope-narrowed": SCOPE_NARROWED_ROTATION_REASON,
  "server-revoked": "server-revoked",
  "device-revoked": "device-revoked",
} satisfies Record<RotationMandate["kind"], string>;

/** 環境 → 基準(最大 seq)の義務の reason(同 seq なら降格を優先)。 */
function reasonsByEnvironment(mandates: readonly RotationMandate[]): ReadonlyMap<string, string> {
  const chosen = new Map<string, RotationMandate>();
  for (const mandate of mandates) {
    for (const environmentId of mandate.environmentIds) {
      const current = chosen.get(environmentId);
      if (
        current === undefined ||
        current.seq < mandate.seq ||
        (current.seq === mandate.seq && mandate.kind === "role-demoted")
      ) {
        chosen.set(environmentId, mandate);
      }
    }
  }
  return new Map(
    [...chosen].map(([environmentId, mandate]) => [environmentId, MANDATE_REASONS[mandate.kind]]),
  );
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

/**
 * pre-flight が見る実行者の権限材料。合意は実効権限(人 ∩ 端末の cap — §6.2
 * `effectivePermissionOf`)で判定するので、手前判定もこれに合わせる(署名端末の
 * cap が人より狭ければ、実効側で検査しないと append 時の拒否まで進む)。
 */
type ActorAuthority = { readonly role: Role; readonly scope: MemberScope };

/**
 * 署名端末を引き、その実効権限を返す。端末がチェーンに無い鍵(未登録・失効済み)
 * には型付きの失敗が人の権限の文言の前に出る(device-ops.ts と同じ順序)。
 */
function actorAuthority(
  verified: VerifiedProject,
  actor: ChainMember,
  signingKeyPair: SigningKeyPair,
): Effect.Effect<EffectivePermission, CliError> {
  return Effect.map(ownDeviceBySigningKey(verified, actor, signingKeyPair), (device) =>
    effectivePermissionOf(actor, device),
  );
}

/** remove / change_role の対象規則(§6.2)の CLI 早期検査(文言のための手前判定)。 */
function targetedOpRejection(input: {
  readonly actor: ActorAuthority;
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

/** 受諾済みの行(発行文は全行が持つ)。 */
type AddableRow = InvitationRow & { readonly acceptance: InviteAcceptance };

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
    return Effect.succeed(row);
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
  return Effect.succeed(first);
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

/**
 * 鍵 FP 再登録の警告(設計録 K5-K / K6-I): 受諾鍵が検証済みチェーンの履歴の別の在籍区間に
 * 現れるとき警告する(拒否ではない — 同一鍵での復帰は §6.2 が許容する)。同一 user_id の
 * 過去の在籍と、別 user_id の在籍の両方を言い分ける。判定材料は `keyHistory`(提案経由の
 * 追加も含む — K6-C)。直接追記・提案化の両経路で署名の前に出す。
 */
function warnKeyReuse(
  verified: VerifiedProject,
  acceptance: InviteAcceptance,
): Effect.Effect<void, never, CliIo> {
  return Effect.forEach(
    keyReuseOf(verified, {
      targetUserId: acceptance.inviteeUserId,
      encPubHex: acceptance.inviteeEncPubHex,
      sigPubHex: acceptance.inviteeSigPubHex,
    }),
    (reuse) => logWarning(describeKeyReuse("the acceptance key", reuse)),
    { discard: true },
  );
}

/** add_member の実行者 role 規則(§6.2)の早期検査(不成立なら理由の文字列)。 */
function addActorRejection(actor: ActorAuthority | undefined, role: Role): string | null {
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
  // 比較対象は現メンバー集合の全端末鍵(§6.2 — 2026-09-19 DK)
  for (const member of verified.state.members.values()) {
    for (const device of member.devices.values()) {
      if (
        device.encPubHex === acceptance.inviteeEncPubHex ||
        device.sigPubHex === acceptance.inviteeSigPubHex
      ) {
        return `The acceptance key equals current member ${displayText(member.userId)}'s key (consensus rule duplicate-member-key — CRYPTO_SPEC §6.2). add_member cannot proceed with this acceptance`;
      }
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
  readonly scope: ScopePayloadFields;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<{ readonly alreadyAdded: boolean }, CliError> {
  return Effect.gen(function* () {
    const actor = input.verified.state.members.get(input.signerUserId);
    if (actor === undefined) {
      return yield* Effect.fail(
        cliError("Only admins and above can run add_member (CRYPTO_SPEC §6.2)"),
      );
    }
    const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
    const actorRejection = addActorRejection(permission, input.role);
    if (actorRejection !== null) {
      return yield* Effect.fail(cliError(actorRejection));
    }
    const existing = input.verified.state.members.get(input.acceptance.inviteeUserId);
    if (existing !== undefined) {
      if (
        memberHasKeys(
          existing,
          input.acceptance.inviteeEncPubHex,
          input.acceptance.inviteeSigPubHex,
        )
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
    // 原則 1(§6.2 scope-not-contained — 検査順も §6.2: duplicate 系の後): add の権限変化の
    // 環境集合 = 新 scope(招待行)。発行時の検査(K4-G)は発行者のもので、add の実行者は
    // 別人・別時点でありうる(独立レビュー S1)。儀式の前に落とす。追記済みの再開(上)は
    // remove / change-role と同じく包含を問わない(残るのはバックフィルだけ)
    const invited = memberScopeOf(input.scope);
    if (!scopeContains(permission.scope, invited)) {
      return yield* Effect.fail(
        cliError(
          `Your environment scope (${describeScope(permission.scope)}) does not contain the invite's scope (${describeScope(invited)}), so add_member would be rejected (CRYPTO_SPEC §6.2 scope-not-contained). Ask an owner or an admin whose scope covers it to run member add`,
        ),
      );
    }
    return { alreadyAdded: false };
  });
}

/**
 * add_member エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。
 * scope は招待行の付与予定 scope(AUTH_SPEC §15-2 — 招待者が受諾後に別の scope を
 * 付けることはできない: 同意の範囲は発行時の発行署名が固定する)
 */
function signAddMemberEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly acceptance: InviteAcceptance;
  readonly role: Role;
  readonly scope: ScopePayloadFields;
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
        scopeKind: input.scope.scopeKind,
        scopeEnvironmentIds: input.scope.scopeEnvironmentIds,
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
 * (`storedRecipientEncPubHex` — AUTH_SPEC §12-6)と受諾鍵の**厳密比較**で行う
 * (復号可能性 = enc 鍵一致そのもの)。
 */
function backfillMemberEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<MemberBackfillResult, CliError> {
  return Effect.gen(function* () {
    // 対象の**全端末**のうち実効 scope に E を含むもの(R(E) の端末展開 — CRYPTO_SPEC
    // §6.2、DK K4)。端末ごとにスロットが別なので、端末ごとに登録する
    const devices = devicesOf(input.target).filter((device) =>
      deviceReceivesEnvironment(input.target, device, input.environmentId),
    );
    let registered = 0;
    let alreadyRegistered = 0;
    let repaired = 0;
    for (const device of devices) {
      const result = yield* backfillMemberDevice({ ...input, targetDevice: device });
      registered += result.registered;
      alreadyRegistered += result.alreadyRegistered;
      repaired += result.repaired;
    }
    return { registered, alreadyRegistered, repaired };
  });
}

/** 1 環境 × 対象の 1 端末のバックフィル(スロット = (epoch, user_id, enc 鍵))。 */
function backfillMemberDevice(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly recipient: DekRecipient;
  readonly target: ChainMember;
  readonly targetDevice: ChainDevice;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<MemberBackfillResult, CliError> {
  const register = registerWraps(input.client, input.verified.projectId, input.environmentId);
  const { targetDevice } = input;
  return backfillEnvironmentFor({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    wrapRecipient: { kind: "member", member: input.target, device: targetDevice },
    recipientLabel: "new-member-addressed",
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    onSlotConflict: (wrap, storedRecipientEncPubHex) =>
      Effect.gen(function* () {
        // 占有スロットが旧鍵ラップか: 応答の保存済み enc 公開鍵との厳密比較
        // (一致 = 現行鍵で登録済み = 冪等)
        if (storedRecipientEncPubHex === targetDevice.encPubHex) {
          return "already-registered" as const;
        }
        // 修復経路(§12-6): 占有スロットを削除して新鍵ラップを再登録する。参照は
        // 端末の enc 鍵まで名指しする
        yield* input.client.deks
          .remove({
            params: { projectId: input.verified.projectId, environmentId: input.environmentId },
            payload: {
              wraps: [
                {
                  epoch: wrap.epoch,
                  recipientUserId: input.target.userId,
                  recipientEncPubHex: storedRecipientEncPubHex,
                },
              ],
            },
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
  readonly signingKeyPair: SigningKeyPair;
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
      scope: { scopeKind: row.scopeKind, scopeEnvironmentIds: row.scopeEnvironmentIds },
      signingKeyPair: input.signingKeyPair,
    });
    if (!first.alreadyAdded) {
      yield* warnKeyReuse(input.verified, row.acceptance);
    }

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
  /** バックフィルする環境(省略 = 対象の scope の全環境)。指定も scope で再度絞る。 */
  readonly environments?: readonly string[];
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError
> {
  return Effect.gen(function* () {
    // 対象の scope の環境(チェーン導出・検証済み削除を除く)× 全エポック
    // (CRYPTO_SPEC §7「対象の scope の全環境の全エポック DEK」— 2026-09-15 ES K4。
    // `environments` の明示指定は change-role の拡大分のバックフィルに使う)
    const deletedVerified = yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const environments = (input.environments ?? [...input.verified.state.environments.keys()])
      .filter(
        (environmentId) =>
          !deletedVerified.has(environmentId) &&
          scopeIncludesEnvironment(input.target.scope, environmentId),
      )
      .toSorted(compareCodePoints);
    return yield* backfillEachEnvironment(environments, (environmentId) =>
      backfillMemberEnvironment({ ...input, environmentId }),
    );
  });
}

/** add_member の内側 op(直接追記と提案で同じ payload — 招待行の scope)。 */
function addMemberOperation(
  row: AddableRow,
): Extract<ProposableOperation, { readonly op: "add_member" }> {
  return {
    op: "add_member",
    payload: {
      targetUserId: row.acceptance.inviteeUserId,
      encPubHex: row.acceptance.inviteeEncPubHex,
      sigPubHex: row.acceptance.inviteeSigPubHex,
      role: row.role,
      scopeKind: row.scopeKind,
      scopeEnvironmentIds: row.scopeEnvironmentIds,
    },
  };
}

/**
 * 新メンバー宛のバックフィル(add_member の追記後段 — CRYPTO_SPEC §7 / AUTH_SPEC §12-6)。
 * 直接追記の add と、四眼で適用を完成させた承認者の履行(§12-6 の 5 番目の経路 —
 * approval-approve.ts)が共有する。対象は再同期後の現メンバー(`target`)。
 */
export function backfillNewMember(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly recipient: DekRecipient;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed">,
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 再追加(過去在籍が別鍵)の案内: 鍵履歴に現在の鍵と異なる束縛があるか。409 の判定は
    // 応答の保存済み enc 公開鍵との厳密比較(AUTH_SPEC §12-6 追補)で、これは案内だけ。
    // サーバーは add_member 受理時に旧鍵宛ラップを自動掃除するため(同追補)、通常は
    // 409 自体が「現行鍵で登録済み」しか意味しない
    // 「別鍵」= 履歴の束縛のうち、対象の現端末集合のどれとも一致しないもの(端末が
    // 複数でも、現端末の鍵は旧鍵ではない — DK K4)
    const readdedWithNewKey = (input.verified.keyHistory.get(input.target.userId) ?? []).some(
      (binding) => !memberHasKeys(input.target, binding.encPubHex, binding.sigPubHex),
    );
    if (readdedWithNewKey) {
      yield* io.log(
        "The target user ID was previously a member with a different key. If leftover wraps addressed to the old key are found, the repair path (delete → re-register) replaces them with the new key (CRYPTO_SPEC §7 / AUTH_SPEC §12-6)",
      );
    }
    return yield* backfillAllEnvironments({
      client: input.client,
      verified: input.verified,
      recipient: input.recipient,
      target: input.target,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
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
  readonly proposal: ProposalInput;
}): Effect.Effect<
  MemberOpOutcome<MemberAddSummary>,
  CliError,
  CliIo | FingerprintBook | Stdio.Stdio | HttpClient.HttpClient
> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { row, alreadyAdded } = yield* prepareMemberAdd(input);
    const inner = addMemberOperation(row);
    const scope = { scopeKind: row.scopeKind, scopeEnvironmentIds: row.scopeEnvironmentIds };
    const recheck = (view: VerifiedProject) =>
      ensureAddable({
        verified: view,
        signerUserId: input.signerUserId,
        acceptance: row.acceptance,
        role: row.role,
        scope,
        signingKeyPair: input.signingKeyPair,
      });

    // 四眼(K6-A / K6-D): 方針が add_member を対象にしていれば提案して終わる。儀式
    // (prepareMemberAdd)は提案者が済ませ、バックフィルは適用を完成させた承認者が行う
    if (!alreadyAdded && isApprovalTarget(inner, input.verified.state.approvalPolicy)) {
      const proposal = yield* proposeOperation(
        input,
        inner,
        proposeRecheck(
          recheck,
          (rechecked) => rechecked.alreadyAdded,
          "The target was added by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi member add` to resume the backfill",
        ),
      );
      return { kind: "proposed", proposal };
    }

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
            scope,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureStillTarget(view, inner, false).pipe(
            Effect.flatMap(() => recheck(view)),
            Effect.map((rechecked) => ({ already: rechecked.alreadyAdded })),
          ),
      });
      appended = outcome.appended;
      verified = outcome.verified;
    }

    // 受理後の再同期で掲載を確認する(サーバー申告を真実源にしない)
    verified = yield* resyncExtended(input.resync, verified);
    const target = verified.state.members.get(row.acceptance.inviteeUserId);
    if (
      target === undefined ||
      !memberHasKeys(target, row.acceptance.inviteeEncPubHex, row.acceptance.inviteeSigPubHex)
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

    const backfilled = yield* backfillNewMember({
      client: input.client,
      verified,
      target,
      recipient: input.recipient,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
    return {
      kind: "applied",
      summary: { appended, targetUserId: target.userId, role: row.role, ...backfilled },
    };
  });
}

// ---------------------------------------------------------------------------
// member remove
// ---------------------------------------------------------------------------

export interface MemberRemoveSummary extends MemberSweepOutcome {
  /** チェーンへ追記したか(false = 既に削除済み — ローテーションの続きから再開)。 */
  readonly appended: boolean;
  readonly targetUserId: string;
}

/**
 * remove の追記前検査(CAS リトライの再同期後にも同じ検査を通す)。`proposing` = 提案化の
 * 経路(自己 remove の拒否は履行者が承認者に移るので外す — 設計録 K6-N)。
 */
function ensureRemovable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly proposing: boolean;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<{ readonly alreadyRemoved: boolean }, CliError> {
  return Effect.gen(function* () {
    if (input.targetUserId === input.signerUserId && !input.proposing) {
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
    const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
    if (target === undefined) {
      const resumable = removalResumeRejection(input.verified, permission, input.targetUserId);
      return resumable === null
        ? { alreadyRemoved: true }
        : yield* Effect.fail(cliError(resumable));
    }
    const rejection = removeRuleRejection(input.verified, permission, target);
    return rejection === null ? { alreadyRemoved: false } : yield* Effect.fail(cliError(rejection));
  });
}

/**
 * 削除済みからの再開(中断復旧)の条件: チェーン上に当該 user_id の remove があること
 * (タイプミスの user_id で sweep が走る形を作らない。提案経由で適用された remove — 四眼 K6 —
 * も同じ列に載る: 設計録 K6-C)と、再開する実行者が member 以上であること。
 */
function removalResumeRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  targetUserId: string,
): string | null {
  const removedBefore = verified.applied.some(
    ({ operation }) =>
      operation.op === "remove_member" && operation.payload.targetUserId === targetUserId,
  );
  if (!removedBefore) {
    return "The target is not a member and the chain has no removal record for it (check the user ID)";
  }
  return ROLE_RANK[actor.role] < ROLE_RANK.member
    ? "Resuming the rotation requires the member role or above (CRYPTO_SPEC §6.2)"
    : null;
}

/** remove_member の §6.2 規則(role → scope-not-contained → last-owner)の手前判定。 */
function removeRuleRejection(
  verified: VerifiedProject,
  actor: ActorAuthority,
  target: ChainMember,
): string | null {
  const rejection = targetedOpRejection({ actor, target, operation: "remove_member" });
  if (rejection !== null) {
    return rejection;
  }
  // 原則 1(§6.2 scope-not-contained): remove の権限変化の環境集合 = 対象の現 scope
  // (「消せる = rotate を履行できる」— 裁定 D)。change-role と同じ手前判定
  if (!scopeContains(actor.scope, target.scope)) {
    return `Your environment scope (${describeScope(actor.scope)}) does not contain the target's scope (${describeScope(target.scope)}), so you could not run the post-removal rotation — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
  }
  return target.role === "owner" && ownersCount(verified) === 1
    ? "The last owner cannot be removed (CRYPTO_SPEC §6.2 last-owner-protected)"
    : null;
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
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.Effect<MemberOpOutcome<MemberRemoveSummary>, CliError, R> {
  return Effect.gen(function* () {
    const inner: ProposableOperation = {
      op: "remove_member",
      payload: { targetUserId: input.targetUserId },
    };
    const proposing = isApprovalTarget(inner, input.verified.state.approvalPolicy);
    const recheck = (view: VerifiedProject) =>
      ensureRemovable({
        verified: view,
        signerUserId: input.signerUserId,
        targetUserId: input.targetUserId,
        proposing,
        signingKeyPair: input.signingKeyPair,
      });
    const first = yield* recheck(input.verified);

    // 四眼(K6-A): 方針が remove_member を対象にしていれば提案して終わる(rotate 義務は
    // 適用後に承認者の sweep が履行する — 裁定 P7 / P8)。再開(削除済み)は提案しない
    if (!first.alreadyRemoved && proposing) {
      const proposal = yield* proposeOperation(
        input,
        inner,
        proposeRecheck(
          recheck,
          (rechecked) => rechecked.alreadyRemoved,
          "The target was removed by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi member remove` to resume the rotation",
        ),
      );
      return { kind: "proposed", proposal };
    }

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
          ensureStillTarget(view, inner, false).pipe(
            Effect.flatMap(() => recheck(view)),
            Effect.map((rechecked) => ({ already: rechecked.alreadyRemoved })),
          ),
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

    // 対象の義務エントリ(今回の remove の追記 or 履歴上のもの — 過去の縮小 / 降格
    // を含む)が基準になる。remove が無いのは「削除は確認済みなのに義務エントリが
    // ない」= 導出の内部矛盾。義務の環境集合は対象の現 scope(§7 — listed{} なら空)
    const mandates = memberMandatesFor(verified, input.targetUserId);
    if (!mandates.some((mandate) => mandate.kind === "member-removed")) {
      return yield* Effect.fail(
        cliError(
          "Cannot find the rotation-mandate entry on the chain (internal contradiction in the derivation)",
        ),
      );
    }
    const sweep = yield* sweepAfterMandate({
      client: input.client,
      verified,
      mandates,
      actorUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
      rotateWith: input.rotateWith,
    });
    return { kind: "applied", summary: { appended, targetUserId: input.targetUserId, ...sweep } };
  });
}

// ---------------------------------------------------------------------------
// member change-role
// ---------------------------------------------------------------------------

export interface MemberChangeRoleSummary {
  /** チェーンへ追記したか(false = 既に対象 (role, scope) — 義務の再開のみ)。 */
  readonly appended: boolean;
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  /** 拡大分の環境(新 \ 旧 — actor のバックフィル義務。§12-6)のうち actor の scope 内。 */
  readonly widenedEnvironmentIds: readonly string[];
  /** 履歴上の拡大分のうち actor の scope 外(自分の義務ではない — その環境を持つメンバーに委ねる)。 */
  readonly widenedOutOfScopeEnvironmentIds: readonly string[];
  /** 縮小分の環境(旧 \ 新 — rotate 義務。§7)。 */
  readonly narrowedEnvironmentIds: readonly string[];
  /** 拡大分のバックフィルの結果(拡大なし = null)。 */
  readonly backfill: Pick<
    MemberAddSummary,
    "registered" | "alreadyRegistered" | "repaired" | "failed"
  > | null;
  /** 対象に降格の義務(role-demoted)があるか(報告文言の材料 — 新 role からは再導出しない)。 */
  readonly demoted: boolean;
  /** 降格 / 縮小に伴う義務環境のローテーションの結果(義務なし = null)。 */
  readonly sweep: MemberSweepOutcome | null;
}

/** change_role の入力(役割と scope はどちらも省略 = 据え置き — 設計録 K4-A)。 */
export interface ChangeRoleRequest {
  readonly newRole: Role | null;
  readonly newScope: MemberScope | null;
}

/** 対象の現 (role, scope) と要求から、追記する新 (role, scope) を決める(全置換 — §6.2)。 */
function resolveRoleChange(
  target: ChainMember,
  request: ChangeRoleRequest,
): Effect.Effect<{ readonly role: Role; readonly scope: MemberScope }, CliError> {
  const role = request.newRole ?? target.role;
  if (role === "owner") {
    // owner の scope は常に all(§6.2 scope-role-mismatch)— `--env` の併用は矛盾
    if (request.newScope !== null && request.newScope.kind !== "all") {
      return Effect.fail(
        usageError(
          "An owner's scope is always all environments (CRYPTO_SPEC §6.2 scope-role-mismatch) — drop --env / --no-envs, or use --all-envs",
        ),
      );
    }
    return Effect.succeed({ role, scope: ALL_SCOPE });
  }
  return Effect.succeed({ role, scope: request.newScope ?? target.scope });
}

/** change_role の role 規則(§6.2)の早期検査(不成立なら理由の文字列)。 */
function changeRoleRuleRejection(input: {
  readonly verified: VerifiedProject;
  readonly actor: ActorAuthority;
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

/**
 * 原則 1(§6.2 scope-not-contained)の手前判定: role が変わるなら 旧 ∪ 新、scope
 * だけなら対称差を actor の scope が包含する。旧か新が all なら差集合が U \ X に
 * なるため all の actor しか行えない(集合代数 — 設計録 K4-I の導出)。
 */
function scopeContainmentRejection(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newRole: Role;
  readonly newScope: MemberScope;
}): string | null {
  const contained =
    input.newRole !== input.target.role
      ? scopeContains(input.actor.scope, input.target.scope) &&
        scopeContains(input.actor.scope, input.newScope)
      : actorMayReplaceScope(input);
  if (contained) {
    return null;
  }
  return `Your environment scope (${describeScope(input.actor.scope)}) does not contain the environments whose permissions this change affects (target: ${describeScope(input.target.scope)} → ${describeScope(input.newScope)}) — CRYPTO_SPEC §6.2 scope-not-contained. Ask an owner or an admin whose scope covers them`;
}

/** scope だけの置換で actor が対称差(旧 △ 新)を包含するか。 */
function actorMayReplaceScope(input: {
  readonly actor: ActorAuthority;
  readonly target: ChainMember;
  readonly newScope: MemberScope;
}): boolean {
  if (input.actor.scope.kind === "all") {
    return true;
  }
  const before = input.target.scope;
  const after = input.newScope;
  if (before.kind === "all" || after.kind === "all") {
    // all △ all = ∅(変化なし)、all △ listed = U \ X(listed の actor は包含できない)
    return before.kind === after.kind;
  }
  const beforeIds = new Set(before.environmentIds);
  const afterIds = new Set(after.environmentIds);
  const changed = [
    ...before.environmentIds.filter((id) => !afterIds.has(id)),
    ...after.environmentIds.filter((id) => !beforeIds.has(id)),
  ];
  return scopeContains(input.actor.scope, { kind: "listed", environmentIds: changed });
}

/**
 * 自分自身への降格 / 縮小の拒否: §7 の義務(rotate)を本人が履行できなくなる
 * (降格後は member 未満、縮小後は当該環境が scope 外)。
 */
function rejectSelfObligation(
  verified: VerifiedProject,
  target: ChainMember,
  next: { readonly role: Role; readonly scope: MemberScope },
): Effect.Effect<void, CliError> {
  switch (selfObligationReason(verified, target, next)) {
    case "demotion":
      return Effect.fail(
        cliError(
          "You cannot demote yourself below member. You would be unable to run the post-demotion rotation of every environment (CRYPTO_SPEC §7) — ask another admin / owner to demote you",
        ),
      );
    case "scope-narrowing":
      return Effect.fail(
        cliError(
          "You cannot narrow your own scope. You would be unable to run the rotation of the environments you leave (CRYPTO_SPEC §7) — ask another admin / owner to narrow it",
        ),
      );
    case null:
      return Effect.void;
  }
}

/**
 * 対象自身が §7 の義務を履行できなくなる (role, scope) の変更か: member 未満への降格、
 * または scope の縮小(履行者 = 対象自身になる直接追記、および承認者 = 対象の approve —
 * 設計録 K6-N / Cursor Bugbot 指摘対応)。
 */
export function selfObligationReason(
  verified: VerifiedProject,
  target: ChainMember,
  next: { readonly role: Role; readonly scope: MemberScope },
): "demotion" | "scope-narrowing" | null {
  if (ROLE_RANK[target.role] >= ROLE_RANK.member && ROLE_RANK[next.role] < ROLE_RANK.member) {
    return "demotion";
  }
  return scopeChangeAt(verified, target.scope, next.scope, verified.state.headSeq).narrowed.length >
    0
    ? "scope-narrowing"
    : null;
}

/**
 * change_role の追記前検査(CAS リトライの再同期後にも同じ検査を通す)。`proposing` = 提案化の
 * 経路(自己降格 / 自己縮小の拒否は履行者が承認者に移るので外す — 設計録 K6-N)。
 */
function ensureRoleChangeable(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly proposing: boolean;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<
  { readonly alreadyChanged: boolean; readonly role: Role; readonly scope: MemberScope },
  CliError
> {
  return Effect.gen(function* () {
    const { actor, target } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    const permission = yield* actorAuthority(input.verified, actor, input.signingKeyPair);
    if (target === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const next = yield* resolveRoleChange(target, input.request);
    if (input.targetUserId === input.signerUserId && !input.proposing) {
      yield* rejectSelfObligation(input.verified, target, next);
    }
    if (target.role === next.role && sameScope(target.scope, next.scope)) {
      // 追記済み(前回実行の中断・並行実行)または no-op。降格 / 縮小の中断復旧
      // (エントリは載ったが義務が未了)をここから再開できる形にする。再開(rotate /
      // バックフィル)は member 以上(remove の再開と同じガード — 独立レビュー N11)
      if (ROLE_RANK[permission.role] < ROLE_RANK.member) {
        return yield* Effect.fail(
          cliError(
            "Resuming the rotation / backfill requires the member role or above (CRYPTO_SPEC §6.2)",
          ),
        );
      }
      return { alreadyChanged: true, ...next };
    }
    // 検査順は §6.2 の合意規則と同じ: role 規則 → last-owner → unknown-environment →
    // scope-not-contained(独立レビュー N2)
    const rejection = changeRoleRuleRejection({
      verified: input.verified,
      actor: permission,
      target,
      newRole: next.role,
    });
    if (rejection !== null) {
      return yield* Effect.fail(cliError(rejection));
    }
    yield* requireScopeEnvironmentsExist(input.verified, next.scope);
    const containment = scopeContainmentRejection({
      actor: permission,
      target,
      newRole: next.role,
      newScope: next.scope,
    });
    if (containment !== null) {
      return yield* Effect.fail(cliError(containment));
    }
    return { alreadyChanged: false, ...next };
  });
}

/**
 * change_role エントリを現ヘッドの直後に署名する(共有核 = chain-append.ts)。payload は
 * 新 (role, scope) の全置換(CRYPTO_SPEC §6.2)— 2026-09-15 ES K4: `--role` / `--env` /
 * `--all-envs` の省略はそれぞれ据え置き(設計録 K4-A)、owner は all 固定。
 */
function signChangeRoleEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly newScope: MemberScope;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  const scope = scopePayloadFieldsOf(input.newScope);
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "change_role",
      payload: {
        targetUserId: input.targetUserId,
        newRole: input.newRole,
        scopeKind: scope.scopeKind,
        scopeEnvironmentIds: scope.scopeEnvironmentIds,
      },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the change_role entry",
  });
}

/**
 * 署名するビューの対象の現状から新 (role, scope) を解決して署名する(据え置き側は
 * **そのビュー**の現状)。CAS リトライで並行の change_role が据え置き側を変えていても
 * 上書きしない(設計録 K4-A の「省略 = 変えない」— Cursor Bugbot 指摘対応)。
 */
function signChangeRoleAtView(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return Effect.gen(function* () {
    const current = input.verified.state.members.get(input.targetUserId);
    if (current === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const next = yield* resolveRoleChange(current, input.request);
    return yield* signChangeRoleEntry({
      verified: input.verified,
      signerUserId: input.signerUserId,
      targetUserId: input.targetUserId,
      newRole: next.role,
      newScope: next.scope,
      signingKeyPair: input.signingKeyPair,
    });
  });
}

/**
 * 拡大分 = 対象の **全** `change_role` 履歴の拡大分(各エントリの直前状態との差)の
 * 和集合のうち、現 scope に残る環境(pullfrog 指摘対応: 最後のエントリだけを見ると、
 * 拡大バックフィルの中断中に第三者が別の change_role を積んだ場合に拡大分が空になり
 * 再開されない。sweep 側が対象の全義務を畳むのと同じく、履歴全体から導く。409 で
 * 冪等なので過剰分は「登録済み」に収束する)。縮小分は報告用で、最後のエントリの差。
 */
export function scopeChangesOf(
  verified: VerifiedProject,
  target: ChainMember,
): { readonly widened: readonly string[]; readonly narrowed: readonly string[] } {
  const current = new Set(environmentsOfScopeAt(verified, target.scope, verified.state.headSeq));
  const widened = new Set<string>();
  let narrowed: readonly string[] = [];
  // 提案経由で適用された change_role も同じ列に載る(設計録 K6-C)
  for (const { seq, operation } of verified.applied) {
    if (operation.op !== "change_role" || operation.payload.targetUserId !== target.userId) {
      continue;
    }
    const before = verified.history.memberStateAt(target.userId, seq - 1);
    if (before === undefined) {
      continue;
    }
    const change = scopeChangeAt(verified, before.scope, memberScopeOf(operation.payload), seq);
    for (const environmentId of change.widened) {
      if (current.has(environmentId)) {
        widened.add(environmentId);
      }
    }
    narrowed = change.narrowed;
  }
  return { widened: [...widened].toSorted(compareCodePoints), narrowed };
}

/**
 * 履歴上の拡大分のうち actor の scope 外の環境は自分の義務ではない(§6.2 の系 —
 * 義務の環境集合 ⊆ 権限変化の環境集合 ⊆ actor scope。独立レビュー S6)。sweep と同じく
 * 注記に回し、その環境を scope に持つメンバーの再実行に委ねる。
 */
function splitWidenedByActorScope(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly actorUserId: string;
  readonly widened: readonly string[];
}): Effect.Effect<
  { readonly widened: readonly string[]; readonly widenedOutOfScope: readonly string[] },
  CliError
> {
  return Effect.gen(function* () {
    // 検証済み削除の環境は scope に残っていても拡大分から外す(scope 外の注記を「誰も
    // 埋められない環境」で出し続けない — pullfrog 指摘。backfillAllEnvironments と同じ集合)。
    // 拡大分が無ければ問い合わせない(追記後の余計な要求で exit を汚さない)
    const deletedVerified =
      input.widened.length === 0
        ? new Set<string>()
        : yield* verifiedDeletedEnvironmentSet(input.client, input.verified);
    const live = input.widened.filter((environmentId) => !deletedVerified.has(environmentId));
    const actor = input.verified.state.members.get(input.actorUserId);
    const actorScope: MemberScope = actor?.scope ?? { kind: "listed", environmentIds: [] };
    return {
      widened: live.filter((environmentId) => scopeIncludesEnvironment(actorScope, environmentId)),
      widenedOutOfScope: live.filter(
        (environmentId) => !scopeIncludesEnvironment(actorScope, environmentId),
      ),
    };
  });
}

/**
 * `maruhi member change-role`: 新 (role, scope) の全置換を追記し、拡大分を actor が
 * バックフィル(§12-6 の追記経路)→ 降格 / 縮小分の義務環境を rotate(§7)する
 * (順序は設計録 K4-B: 3 つの環境集合は互いに素で、どちらも冪等に再開できる)。
 */
/** change_role の内側 op(提案化 — 省略側は提案時のビューの対象の現状で解決済み)。 */
function changeRoleOperation(input: {
  readonly targetUserId: string;
  readonly newRole: Role;
  readonly newScope: MemberScope;
}): Extract<ProposableOperation, { readonly op: "change_role" }> {
  const scope = scopePayloadFieldsOf(input.newScope);
  return {
    op: "change_role",
    payload: {
      targetUserId: input.targetUserId,
      newRole: input.newRole,
      scopeKind: scope.scopeKind,
      scopeEnvironmentIds: scope.scopeEnvironmentIds,
    },
  };
}

/** change_role の提案(K6-A): 省略側の再解決が提案時と一致することも再同期後に確かめる。 */
function proposeRoleChange(
  input: ProposeContext,
  inner: ProposableOperation,
  resolved: { readonly role: Role; readonly scope: MemberScope },
  recheck: (
    view: VerifiedProject,
  ) => Effect.Effect<
    { readonly alreadyChanged: boolean; readonly role: Role; readonly scope: MemberScope },
    CliError
  >,
): Effect.Effect<ProposedSummary, CliError> {
  const notApplied = proposeRecheck(
    recheck,
    (rechecked) => rechecked.alreadyChanged,
    "The target already has the requested role / scope (a concurrent run applied it) — nothing to propose. Re-run `maruhi member change-role` to resume any pending backfill / rotation",
  );
  return proposeOperation(input, inner, (view) =>
    notApplied(view).pipe(
      Effect.flatMap((rechecked) =>
        rechecked.role === resolved.role && sameScope(rechecked.scope, resolved.scope)
          ? Effect.void
          : Effect.fail(
              cliError(
                "The target's role / scope changed concurrently, so the omitted side of this request no longer resolves to the same (role, scope) — re-run to propose against the current state",
              ),
            ),
      ),
    ),
  );
}

/**
 * change_role の直接追記(CAS)と、受理後の再同期での掲載確認(サーバー申告を真実源に
 * しない)。要求の不動点(省略側は現状据え置き)と一致すること — 並行の change_role が
 * 据え置き側を変えていても、要求した側が載っていれば成立。
 */
function appendRoleChange(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly inner: ProposableOperation;
  readonly alreadyChanged: boolean;
  readonly recheck: (
    view: VerifiedProject,
  ) => Effect.Effect<{ readonly alreadyChanged: boolean }, CliError>;
}): Effect.Effect<
  { readonly verified: VerifiedProject; readonly appended: boolean; readonly target: ChainMember },
  CliError
> {
  return Effect.gen(function* () {
    let verified = input.verified;
    let appended = false;
    if (!input.alreadyChanged) {
      const outcome = yield* appendWithCas({
        client: input.client,
        verified,
        resync: input.resync,
        opLabel: "change_role",
        // 省略した側(role / scope)は**署名するビュー**の対象の現状から解決する
        // (signChangeRoleAtView — Cursor Bugbot 指摘対応)
        signEntry: (view) =>
          signChangeRoleAtView({
            verified: view,
            signerUserId: input.signerUserId,
            targetUserId: input.targetUserId,
            request: input.request,
            signingKeyPair: input.signingKeyPair,
          }),
        recheck: (view) =>
          ensureStillTarget(view, input.inner, false).pipe(
            Effect.flatMap(() => input.recheck(view)),
            Effect.map((rechecked) => ({ already: rechecked.alreadyChanged })),
          ),
      });
      verified = outcome.verified;
      appended = outcome.appended;
    }
    verified = yield* resyncExtended(input.resync, verified);
    const target = verified.state.members.get(input.targetUserId);
    const expected =
      target === undefined ? undefined : yield* resolveRoleChange(target, input.request);
    if (
      target === undefined ||
      expected === undefined ||
      target.role !== expected.role ||
      !sameScope(target.scope, expected.scope)
    ) {
      return yield* Effect.fail(
        cliError(
          "The resync after change_role was accepted does not show the target's new role / scope (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    return { verified, appended, target };
  });
}

/** change_role の適用後の履行の結果(拡大バックフィル + 降格 / 縮小 sweep)。 */
export type RoleChangeFulfilment = Pick<
  MemberChangeRoleSummary,
  | "widenedEnvironmentIds"
  | "widenedOutOfScopeEnvironmentIds"
  | "narrowedEnvironmentIds"
  | "backfill"
  | "demoted"
  | "sweep"
>;

/**
 * change_role の適用後段(設計録 K4-B の順序: 拡大分のバックフィル → 降格 / 縮小分の
 * rotate)。直接追記の change-role と、四眼で適用を完成させた承認者の履行
 * (approval-approve.ts — 承認項目 22)が共有する。対象は再同期後の現メンバー。
 */
export function fulfilRoleChange<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly rotateWith: (reason: string) => SweepRotate<R>;
}): Effect.Effect<RoleChangeFulfilment, CliError, R> {
  return Effect.gen(function* () {
    const change = scopeChangesOf(input.verified, input.target);
    const { widened, widenedOutOfScope } = yield* splitWidenedByActorScope({
      client: input.client,
      verified: input.verified,
      actorUserId: input.signerUserId,
      widened: change.widened,
    });

    // (1) 拡大分のバックフィル — actor は包含規則により DEK を持つ(§12-6)。409 で冪等
    const backfill =
      widened.length === 0
        ? null
        : yield* backfillAllEnvironments({
            client: input.client,
            verified: input.verified,
            recipient: input.recipient,
            target: input.target,
            environments: widened,
            signerUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
          });

    // (2) 降格 / 縮小の義務環境の rotate(§7)。対象の義務エントリが無ければ義務自体が
    // 発生していない(昇格・拡大・最初から reader の no-op)— 他人の未収束義務は拾わない
    const mandates = memberMandatesFor(input.verified, input.target.userId);
    const demoted = mandates.some((mandate) => mandate.kind === "role-demoted");
    const sweep =
      mandates.length === 0
        ? null
        : yield* sweepAfterMandate({
            client: input.client,
            verified: input.verified,
            mandates,
            actorUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
            rotateWith: input.rotateWith,
          });
    return {
      widenedEnvironmentIds: widened,
      widenedOutOfScopeEnvironmentIds: widenedOutOfScope,
      narrowedEnvironmentIds: change.narrowed,
      backfill,
      demoted,
      sweep,
    };
  });
}

export function memberChangeRoleOp<R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly targetUserId: string;
  readonly request: ChangeRoleRequest;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** 義務の理由(降格 = role-demoted / 縮小のみ = scope-narrowed)ごとのローテーション注入。 */
  readonly rotateWith: (reason: string) => SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.Effect<MemberOpOutcome<MemberChangeRoleSummary>, CliError, R> {
  return Effect.gen(function* () {
    // 提案化の判定は要求を現ビューで解決した新 (role, scope) で行う(owner の確立は常時対象)。
    // 検査の順(§6.2 の合意規則の順 — 自己義務 → role 規則 …)は ensureRoleChangeable が持つ
    const { target: current } = yield* resolveActorAndTarget(
      input.verified,
      input.signerUserId,
      input.targetUserId,
    );
    if (current === undefined) {
      return yield* Effect.fail(cliError("The target is not a member (check the user ID)"));
    }
    const resolved = yield* resolveRoleChange(current, input.request);
    const inner = changeRoleOperation({
      targetUserId: input.targetUserId,
      newRole: resolved.role,
      newScope: resolved.scope,
    });
    const proposing = isApprovalTarget(inner, input.verified.state.approvalPolicy);
    const recheck = (view: VerifiedProject) =>
      ensureRoleChangeable({
        verified: view,
        signerUserId: input.signerUserId,
        targetUserId: input.targetUserId,
        request: input.request,
        proposing,
        signingKeyPair: input.signingKeyPair,
      });
    const first = yield* recheck(input.verified);

    // 四眼(K6-A): 方針が対象にしていれば提案して終わる(拡大バックフィル・縮小 sweep は
    // 適用後に承認者が履行する — 承認項目 22)。省略側は提案時のビューの現状で固定される
    if (!first.alreadyChanged && proposing) {
      const proposal = yield* proposeRoleChange(input, inner, resolved, recheck);
      return { kind: "proposed", proposal };
    }

    const { verified, appended, target } = yield* appendRoleChange({
      ...input,
      inner,
      alreadyChanged: first.alreadyChanged,
      recheck,
    });
    const fulfilment = yield* fulfilRoleChange({
      client: input.client,
      verified,
      target,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
      recipient: input.recipient,
      rotateWith: input.rotateWith,
    });
    return {
      kind: "applied",
      summary: {
        appended,
        targetUserId: input.targetUserId,
        newRole: target.role,
        newScope: target.scope,
        ...fulfilment,
      },
    };
  });
}

// ---------------------------------------------------------------------------
// member list
// ---------------------------------------------------------------------------

/** 1 メンバー行(検証済みチェーン導出 — 値ゼロ。設計録 裁定 M / K4-E、端末列は DK K4-20)。 */
export interface MemberListRow {
  readonly userId: string;
  readonly role: Role;
  readonly scope: MemberScope;
  /** The member's device keys (fingerprint ascending — 2026-09-19 DK: 端末は複数ありうる)。 */
  readonly devices: readonly ChainDevice[];
}

/** 検証済みチェーンのメンバー一覧(user_id 昇順)。 */
export function memberListRows(verified: VerifiedProject): readonly MemberListRow[] {
  return [...verified.state.members.values()]
    .map((member) => ({
      userId: member.userId,
      role: member.role,
      scope: member.scope,
      devices: devicesOf(member),
    }))
    .toSorted((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
}

/** `--json` の 1 文書(機械可読 — エージェント / スクリプト向け。値ゼロ)。 */
export function memberListJson(rows: readonly MemberListRow[]): string {
  return JSON.stringify(
    {
      members: rows.map((row) => ({
        userId: row.userId,
        role: row.role,
        scope: jsonScope(row.scope),
        // 端末一覧(K4-20): FP と cap を構造化して出す。連結した `keyFingerprintHex` は
        // K4 で撤去(消費側に分解させない — 設計録 §7 K2-10 追加巡 j-4 の完成形)
        devices: row.devices.map((device) => ({
          keyFingerprintHex: device.keyFingerprintHex,
          roleCap: device.roleCap,
          scope: jsonScope(device.scope),
        })),
        deviceKeyFingerprintsHex: row.devices.map((device) => device.keyFingerprintHex),
      })),
    },
    null,
    2,
  );
}

function jsonScope(scope: MemberScope) {
  return scope.kind === "all"
    ? { kind: "all" as const }
    : { kind: "listed" as const, environmentIds: [...scope.environmentIds] };
}

/** 人が読む 1 行(user id・role・scope・端末数・端末 FP(cap)。id は中和する)。 */
export function formatMemberListRow(row: MemberListRow): string {
  return `${displayText(row.userId)}\t${row.role}\tscope=${describeScope(row.scope)}\tdevices=${row.devices.length}\tfp=${row.devices.map(describeDevice).join(",")}`;
}
