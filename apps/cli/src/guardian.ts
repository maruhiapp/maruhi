// 保護者グループ(CRYPTO_SPEC §8.3 / AUTH_SPEC §13-7 — KL3)。
//
// `maruhi guardian add`: 共有プロジェクトのチェーン導出メンバーから保護者を選び、
// その enc 公開鍵(チェーン上の鍵)へ分片を封印して台帳に登録する。鍵の確認は
// §6.5 の充足形(12 語の読み上げ儀式 / 検証済み指紋帳のヒット + yes)に従う —
// グローバルな公開鍵ディレクトリは作らない。`all` は乱数 XOR 分割で全員が要る。
// `any` は誰か 1 人で足りる。
//
// `list` / `remove` / `wards` は台帳の閲覧・削除・「自分が保護者である ward」の一覧。
// `list --project` を与えると、台帳の保護者鍵 FP をチェーン導出の現鍵と突合し、
// 鍵が変わった保護者(その分片は開けない)を警告する(`all` では 1 人の不一致で
// グループ全体が復元不能になる)。
//
// 平文の KEK・分片・B はローカル変数にのみ存在する。

import {
  decodeHex,
  encodeHex,
  generateMasterWrapKek,
  type GuardianMode,
  importEncryptionPublicKey,
  sealGuardianShare,
  splitGuardianKek,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { type CliServices, type CommonFlags, openMetadataProject, openSession } from "./context.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { serializeStoredMasterKey } from "./keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import { newLedgerId } from "./master-ops.ts";
import { logNote, logWarning } from "./notice.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";

/** 受理ポリシー(AUTH_SPEC §13-8)と同じ上限(サーバーの 422 を先に案内する)。 */
const MAX_GUARDIANS = 5;

/**
 * 保護者鍵の明示確認(CRYPTO_SPEC §6.5 の充足形を保護者の指名に適用): 帳のヒットは
 * 読み上げの再実施を免除するが、指名単位の yes 確認は残す。エージェント環境では
 * 儀式を行わない(保護者の指名にはフラグ経路を設けない — 鍵素材の封印先を
 * 非対話で決めさせない)。
 */
function confirmGuardianFingerprint(input: {
  readonly origin: string;
  readonly userId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (io.agentProfile().isAgent) {
      return yield* Effect.fail(
        cliError(
          "Refused to run the guardian key confirmation ceremony: an AI agent environment was detected. Run `maruhi guardian add` yourself in a terminal",
        ),
      );
    }
    const words = yield* fingerprintWords(
      input.fingerprintHex,
      "The guardian's key fingerprint is malformed",
    );
    const book = yield* consultFingerprintBook({
      origin: input.origin,
      userId: input.userId,
      fingerprintHex: input.fingerprintHex,
    });
    const hit = yield* usableBookHit({ book, flagProvided: false, isAgent: false });
    yield* io.log(`Guardian ${displayText(input.userId)} — key fingerprint:`);
    yield* io.log(`  hex:  ${input.fingerprintHex}`);
    yield* io.log(`  word: ${formatWordList(words)}`);
    if (hit === null) {
      yield* io.log(
        "Check that this word list matches the 12 words this person reads to you out of band (e.g. over a call). Their key will be able to help restore yours",
      );
    }
    yield* book.warnIfChanged;
    if (hit !== null) {
      yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to make ${displayText(input.userId)} a guardian with this previously verified key`,
        cancelText: "guardian add was cancelled.",
      });
      return;
    }
    yield* confirmByLastWord({
      words,
      promptText:
        "Once you have checked against this person's out-of-band read-out (e.g. a call), type the last of the 12 words shown above",
      mismatchText: "That does not match. Type the last word of the list shown above",
      exhaustedText:
        "Guardian key fingerprint confirmation failed (the re-typed word does not match). No guardian group was created — re-run once you can check with this person",
    });
    yield* book.record;
  });
}

/** 指名の前提検査(サーバーの 422 と同じ規則をここで先に言う)。 */
function guardianInputRejection(input: {
  readonly selfUserId: string;
  readonly mode: GuardianMode;
  readonly userIds: readonly string[];
}): string | null {
  if (input.userIds.length > MAX_GUARDIANS) {
    return `At most ${MAX_GUARDIANS} guardians per group`;
  }
  if (input.mode === "all" && input.userIds.length < 2) {
    return "Mode all needs at least 2 guardians (use mode any for a single guardian)";
  }
  if (new Set(input.userIds).size !== input.userIds.length) {
    return "The same user was given more than once";
  }
  if (input.userIds.includes(input.selfUserId)) {
    return "You cannot be your own guardian";
  }
  return null;
}

/** チェーン導出の現メンバー(保護者候補)。 */
interface GuardianMember {
  readonly userId: string;
  readonly encPubHex: string;
  readonly keyFingerprintHex: string;
}

/** 分片の登録形(ワイヤ — AUTH_SPEC §13-9 GuardianShare)。 */
interface SealedShare {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** 保護者候補をチェーンの現メンバーから引く(§8.3 — 公開鍵ディレクトリを作らない)。 */
function resolveGuardians(input: {
  readonly projectId: string;
  readonly members: ReadonlyMap<string, { encPubHex: string; keyFingerprintHex: string }>;
  readonly userIds: readonly string[];
}): Effect.Effect<readonly GuardianMember[], CliError> {
  return Effect.forEach(input.userIds, (userId) => {
    const member = input.members.get(userId);
    return member === undefined
      ? Effect.fail(
          cliError(
            `${displayText(userId)} is not a current member of project ${displayText(input.projectId)}. Guardians must be members of a project you share (their key comes from that project's verified chain)`,
          ),
        )
      : Effect.succeed({
          userId,
          encPubHex: member.encPubHex,
          keyFingerprintHex: member.keyFingerprintHex,
        });
  });
}

/** 1 人分の分片を保護者のチェーン鍵へ封印する。 */
function sealShareFor(input: {
  readonly wardUserId: string;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  readonly guardian: GuardianMember;
  readonly share: Uint8Array;
}): Effect.Effect<SealedShare, CliError> {
  return Effect.gen(function* () {
    const encPub = decodeHex(input.guardian.encPubHex);
    const publicKey =
      encPub === null ? null : yield* Effect.promise(() => importEncryptionPublicKey(encPub));
    if (publicKey === null || !publicKey.ok) {
      return yield* Effect.fail(
        cliError(`The chain key of ${displayText(input.guardian.userId)} cannot be imported`),
      );
    }
    const sealed = yield* Effect.tryPromise({
      try: () =>
        sealGuardianShare({
          guardianPublicKey: publicKey.value,
          share: input.share,
          context: {
            userId: input.wardUserId,
            groupId: input.groupId,
            mode: input.mode,
            shareIndex: input.shareIndex,
            guardianUserId: input.guardian.userId,
          },
        }),
      catch: () => cliError("Failed to seal a guardian share (crypto error)"),
    });
    if (!sealed.ok) {
      return yield* Effect.fail(cliError("Failed to seal a guardian share"));
    }
    return {
      shareIndex: input.shareIndex,
      guardianUserId: input.guardian.userId,
      guardianEncPubHex: input.guardian.encPubHex,
      guardianKeyFingerprintHex: input.guardian.keyFingerprintHex,
      encHex: encodeHex(sealed.value.enc),
      ciphertextHex: encodeHex(sealed.value.ciphertext),
    };
  });
}

/** B を乱数 KEK でラップし、KEK を分片へ割って各保護者へ封印する(§8.3)。 */
function prepareGroup(input: {
  readonly wardUserId: string;
  readonly masterKeys: MasterKeys;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly guardians: readonly GuardianMember[];
}): Effect.Effect<
  {
    readonly wrap: { readonly nonceHex: string; readonly ciphertextHex: string };
    readonly shares: readonly SealedShare[];
  },
  CliError
> {
  return Effect.gen(function* () {
    const kek = generateMasterWrapKek();
    const blob = new TextEncoder().encode(serializeStoredMasterKey(input.masterKeys.record));
    const wrapped = yield* Effect.tryPromise({
      try: () =>
        wrapMasterBlob({
          kek,
          masterSecretBlob: blob,
          context: {
            userId: input.wardUserId,
            kind: "guardian",
            wrapRef: input.groupId,
            mode: input.mode,
          },
        }),
      catch: () => cliError("Failed to wrap the master key for the guardian group (crypto error)"),
    });
    const split = splitGuardianKek({ kek, mode: input.mode, count: input.guardians.length });
    if (!wrapped.ok || !split.ok || split.value.length !== input.guardians.length) {
      return yield* Effect.fail(cliError("Failed to prepare the guardian group"));
    }
    const shares = yield* Effect.forEach(input.guardians, (guardian, index) =>
      sealShareFor({
        wardUserId: input.wardUserId,
        groupId: input.groupId,
        mode: input.mode,
        shareIndex: index + 1,
        guardian,
        share: split.value[index] ?? new Uint8Array(),
      }),
    );
    return {
      wrap: {
        nonceHex: encodeHex(wrapped.value.nonce),
        ciphertextHex: encodeHex(wrapped.value.ciphertext),
      },
      shares,
    };
  });
}

/**
 * `maruhi guardian add --project <p> --mode any|all <user>...`: register a
 * guardian group whose members can approve restoring your master key.
 */
export function guardianAddOp(input: {
  readonly flags: CommonFlags;
  readonly mode: GuardianMode;
  readonly userIds: readonly string[];
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openMetadataProject(input.flags);
    const rejection = guardianInputRejection({
      selfUserId: context.session.userId,
      mode: input.mode,
      userIds: input.userIds,
    });
    if (rejection !== null) {
      return yield* Effect.fail(usageError(rejection));
    }
    const masterKeys = yield* loadMasterKeys(context.session);
    const guardians = yield* resolveGuardians({
      projectId: context.projectId,
      members: context.verified.state.members,
      userIds: input.userIds,
    });
    for (const guardian of guardians) {
      yield* confirmGuardianFingerprint({
        origin: context.origin,
        userId: guardian.userId,
        fingerprintHex: guardian.keyFingerprintHex,
      });
    }
    const groupId = newLedgerId();
    const prepared = yield* prepareGroup({
      wardUserId: context.session.userId,
      masterKeys,
      groupId,
      mode: input.mode,
      guardians,
    });
    yield* context.client.keyWraps
      .guardianCreate({
        payload: {
          groupId,
          mode: input.mode,
          wrap: { suite: "maruhi/v1", ...prepared.wrap },
          shares: prepared.shares,
        },
      })
      .pipe(
        Effect.catchTag("KeyWrapPolicy", (error) =>
          Effect.fail(cliError(`The server rejected the guardian group (${error.reason})`)),
        ),
        Effect.mapError(toCliError),
      );
    yield* io.log(
      `Registered guardian group ${groupId} (mode ${input.mode}: ${input.mode === "any" ? "any one guardian can approve" : "all guardians must approve"})`,
    );
    for (const share of prepared.shares) {
      yield* io.log(
        `  ${share.shareIndex}. ${displayText(share.guardianUserId)} (key fingerprint ${share.guardianKeyFingerprintHex})`,
      );
    }
    yield* logNote(
      "a guardian who rebuilds their key (`maruhi key generate`) can no longer open their share. Check with `maruhi guardian list --project <id>` and re-add the group if needed. To restore on a new device, run `maruhi key recover --handoff` there and send the code to a guardian",
    );
  });
}

/** 台帳の保護者 1 行(status の配布形)。 */
interface GuardianRow {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianKeyFingerprintHex: string;
}

/** チェーンの現鍵との突合結果(null = 突合していない / 一致)。 */
type Staleness = "left" | "rekeyed" | null;

function stalenessOf(
  guardian: GuardianRow,
  chainMembers: ReadonlyMap<string, { keyFingerprintHex: string }> | null,
): Staleness {
  if (chainMembers === null) {
    return null;
  }
  const current = chainMembers.get(guardian.guardianUserId);
  if (current === undefined) {
    return "left";
  }
  return current.keyFingerprintHex === guardian.guardianKeyFingerprintHex ? null : "rekeyed";
}

function reportGroup(
  group: {
    readonly groupId: string;
    readonly mode: GuardianMode;
    readonly guardians: readonly GuardianRow[];
  },
  chainMembers: ReadonlyMap<string, { keyFingerprintHex: string }> | null,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(`${group.groupId}  mode ${group.mode}  ${group.guardians.length} guardians`);
    for (const guardian of group.guardians) {
      const staleness = stalenessOf(guardian, chainMembers);
      yield* io.log(
        `  ${guardian.shareIndex}. ${displayText(guardian.guardianUserId)} (key fingerprint ${guardian.guardianKeyFingerprintHex})${staleness === null ? "" : "  STALE"}`,
      );
      if (staleness !== null) {
        yield* logWarning(
          `${displayText(guardian.guardianUserId)} ${staleness === "left" ? "is no longer a member of that project" : "has a different key on the chain now"}, so their share cannot be opened${group.mode === "all" ? " — this all-mode group can no longer restore your key" : ""}. Remove the group and add it again`,
        );
      }
    }
  });
}

/** `maruhi guardian list [--project <p>]`: list your guardian groups. */
export function guardianListOp(input: {
  readonly flags: CommonFlags;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const session = yield* openSession(input.flags.server);
    const status = yield* session.client.keyWraps.status({}).pipe(Effect.mapError(toCliError));
    if (status.guardianGroups.length === 0) {
      yield* io.log("No guardian groups. Add one with `maruhi guardian add`");
      return;
    }
    // --project があれば、台帳の保護者鍵 FP をチェーン導出の現鍵と突合する
    const chainMembers =
      input.flags.project === undefined
        ? null
        : (yield* openMetadataProject(input.flags)).verified.state.members;
    for (const group of status.guardianGroups) {
      yield* reportGroup(group, chainMembers);
    }
  });
}

/** `maruhi guardian remove <group-id>`: delete a guardian group. */
export function guardianRemoveOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly groupId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.keyWraps.guardianDelete({ params: { groupId: input.groupId } }).pipe(
      Effect.catchTag("KeyWrapNotFound", () =>
        Effect.fail(
          cliError("No guardian group with that ID (list them with `maruhi guardian list`)"),
        ),
      ),
      Effect.mapError(toCliError),
    );
    yield* io.log(`Removed guardian group ${displayText(input.groupId)}`);
  });
}

/** `maruhi guardian wards`: list the people who made you a guardian. */
export function guardianWardsOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { wards } = yield* input.client.keyWraps.wards({}).pipe(Effect.mapError(toCliError));
    if (wards.length === 0) {
      yield* io.log("Nobody has made you a guardian");
      return;
    }
    for (const ward of wards) {
      const label =
        ward.wardLogin === null
          ? displayText(ward.wardUserId)
          : `${displayText(ward.wardLogin)} (${displayText(ward.wardUserId)})`;
      yield* io.log(
        `${label}  group ${displayText(ward.groupId)}  mode ${ward.mode}  share ${ward.shareIndex}`,
      );
    }
    yield* io.log(
      "When one of them asks you to help restore their key, run `maruhi key approve` with the code they send you",
    );
  });
}
