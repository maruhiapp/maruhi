// 保護者グループ(CRYPTO_SPEC §8.3 / §8.4 / AUTH_SPEC §13-7 — KL3、2026-09-19 DK)。
//
// `maruhi guardian add`: 共有プロジェクトのチェーン導出メンバーから保護者を選び、
// その**現在有効な各端末鍵**の enc 公開鍵(チェーン上の鍵 — §8.3 の端末展開)へ分片を
// 封印して台帳に登録する。ラップ対象 B は**予備鍵**のレコード(§8.1 — 呼び出し側が
// 台帳を開封して得る。ledger-open.ts / 設計録 §9 K4-2)。鍵の確認は §6.5 の充足形
// (12 語の読み上げ儀式 / 検証済み指紋帳のヒット + yes)に従う — グローバルな公開鍵
// ディレクトリは作らない。`all` は乱数 XOR 分割で全員が要る。`any` は誰か 1 人で足りる。
//
// `maruhi guardian approve <code>`(旧 `key approve` — 旧端末経路の削除に伴い改名。K4-15):
// コードから E.pub と request_id を復元し、要求を照会する。自分宛の分片を**この端末の
// 端末鍵**で開き(`deviceShares` から手元の FP の行を選ぶ — K3-10)、その場で E.pub へ
// 再封印する。サーバーは E.pub を中継しない(コードは人が運ぶ)。
//
// `list` / `remove` / `wards` は台帳の閲覧・削除・「自分が保護者である ward」の一覧。
// `list --project` を与えると、台帳の分片行(端末ごと)をチェーン導出の現端末集合と
// 突合し、開けない行(失効した端末)と、全端末が失効して開けなくなった分片を警告する
// (`all` では 1 人の不一致でグループ全体が復元不能になる)。
//
// 平文の KEK・分片・B はローカル変数にのみ存在する。

import {
  type ChainDevice,
  type ChainMember,
  computeHandoffRequestId,
  decodeHandoffCode,
  decodeHex,
  encodeHex,
  type EncryptionKey,
  generateMasterWrapKek,
  type GuardianMode,
  importEncryptionPublicKey,
  sealGuardianShare,
  splitGuardianKek,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { type CliServices, type CommonFlags, openMetadataProject, openSession } from "./context.ts";
import { devicesOf } from "./device-key.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { confirmByLastWord, fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import type { Keychain } from "./keychain.ts";
import { serializeStoredMasterKey } from "./keychain.ts";
import {
  confirmKnownFingerprint,
  consultFingerprintBook,
  FingerprintBook,
  usableBookHit,
} from "./known-fingerprints.ts";
import {
  decodeWrapped,
  newLedgerId,
  openOwnGuardianShare,
  sealForRequester,
} from "./master-ops.ts";
import { logNote, logWarning } from "./notice.ts";
import type { ReserveKeys } from "./reserve.ts";
import { type CliSession, loadMasterKeys, type MasterKeys } from "./session.ts";

/** 受理ポリシー(AUTH_SPEC §13-8)と同じ上限(サーバーの 422 を先に案内する)。 */
const MAX_GUARDIANS = 5;

/**
 * 指名の儀式はハンドオフの要求 / 承認と同じゲート(ADR-0016 決定 7): 人間の
 * 対話端末でのみ行い、エージェント環境は拒否する。保護者の指名にはフラグ経路を
 * 設けない(鍵素材の封印先を非対話で決めさせない)ので、パイプした stdin で
 * 儀式のプロンプトを埋める形もここで落とす。
 */
function ensureGuardianCeremonyAllowed(io: CliIoShape): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "Refused to run the guardian key confirmation ceremony: an AI agent environment was detected. Run `maruhi guardian add` yourself in a terminal",
    terminalError:
      "Designating guardians is only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/**
 * 保護者鍵の明示確認(CRYPTO_SPEC §6.5 の充足形を保護者の指名に適用): 帳のヒットは
 * 読み上げの再実施を免除するが、指名単位の yes 確認は残す。確認するのは保護者の
 * **各端末**の FP(分片はその端末へ封印される)。
 */
function confirmGuardianFingerprint(input: {
  readonly origin: string;
  readonly userId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<void, CliError, CliIo | FingerprintBook | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
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
    yield* io.log(`Guardian ${displayText(input.userId)} — device key fingerprint:`);
    yield* io.log(`  hex:  ${input.fingerprintHex}`);
    yield* io.log(`  word: ${formatWordList(words)}`);
    if (hit === null) {
      yield* io.log(
        "Check that this word list matches the 12 words this person reads to you out of band (e.g. over a call — `maruhi key show` on that device prints them). This device will be able to help restore your reserve key",
      );
    }
    yield* book.warnIfChanged;
    if (hit !== null) {
      yield* confirmKnownFingerprint({
        entry: hit,
        filePath: book.filePath,
        prompt: `Type yes to seal a share to this previously verified device of ${displayText(input.userId)}`,
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

/** チェーン導出の現メンバー(保護者候補)とその現端末集合。 */
interface GuardianMember {
  readonly userId: string;
  readonly devices: readonly ChainDevice[];
}

/** 分片の登録形(ワイヤ — AUTH_SPEC §13-9 GuardianShare。端末ごとに 1 要素)。 */
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
  readonly members: ReadonlyMap<string, ChainMember>;
  readonly userIds: readonly string[];
}): Effect.Effect<readonly GuardianMember[], CliError> {
  return Effect.forEach(input.userIds, (userId) => {
    const member = input.members.get(userId);
    if (member === undefined) {
      return Effect.fail(
        cliError(
          `${displayText(userId)} is not a current member of project ${displayText(input.projectId)}. Guardians must be members of a project you share (their keys come from that project's verified chain)`,
        ),
      );
    }
    // 保護者の鍵 = その人の現在有効な全端末鍵(§8.3 — 同じ分片を端末数ぶん封印する)
    return Effect.succeed({ userId, devices: devicesOf(member) });
  });
}

/** 1 端末分の分片を保護者のチェーン鍵へ封印する。 */
function sealShareFor(input: {
  readonly wardUserId: string;
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly device: ChainDevice;
  readonly share: Uint8Array;
}): Effect.Effect<SealedShare, CliError> {
  return Effect.gen(function* () {
    const encPub = decodeHex(input.device.encPubHex);
    const publicKey =
      encPub === null ? null : yield* Effect.promise(() => importEncryptionPublicKey(encPub));
    if (publicKey === null || !publicKey.ok) {
      return yield* Effect.fail(
        cliError(`The chain key of ${displayText(input.guardianUserId)} cannot be imported`),
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
            guardianUserId: input.guardianUserId,
          },
        }),
      catch: () => cliError("Failed to seal a guardian share (crypto error)"),
    });
    if (!sealed.ok) {
      return yield* Effect.fail(cliError("Failed to seal a guardian share"));
    }
    return {
      shareIndex: input.shareIndex,
      guardianUserId: input.guardianUserId,
      guardianEncPubHex: input.device.encPubHex,
      guardianKeyFingerprintHex: input.device.keyFingerprintHex,
      encHex: encodeHex(sealed.value.enc),
      ciphertextHex: encodeHex(sealed.value.ciphertext),
    };
  });
}

/** B(予備鍵)を乱数 KEK でラップし、KEK を分片へ割って各保護者の各端末へ封印する(§8.3)。 */
function prepareGroup(input: {
  readonly wardUserId: string;
  readonly reserve: ReserveKeys;
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
    const blob = new TextEncoder().encode(serializeStoredMasterKey(input.reserve.record));
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
      catch: () => cliError("Failed to wrap the reserve key for the guardian group (crypto error)"),
    });
    const split = splitGuardianKek({ kek, mode: input.mode, count: input.guardians.length });
    if (!wrapped.ok || !split.ok || split.value.length !== input.guardians.length) {
      return yield* Effect.fail(cliError("Failed to prepare the guardian group"));
    }
    const shares: SealedShare[] = [];
    for (const [index, guardian] of input.guardians.entries()) {
      for (const device of guardian.devices) {
        shares.push(
          yield* sealShareFor({
            wardUserId: input.wardUserId,
            groupId: input.groupId,
            mode: input.mode,
            shareIndex: index + 1,
            guardianUserId: guardian.userId,
            device,
            share: split.value[index] ?? new Uint8Array(),
          }),
        );
      }
    }
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
 * guardian group whose members can approve restoring your reserve key.
 * `openReserve` は台帳の開封(ledger-open.ts — 台帳変更の資格。K4-2)で、入力検査と
 * 儀式の後・封印の直前に 1 回だけ走らせる。
 */
export function guardianAddOp(input: {
  readonly flags: CommonFlags;
  readonly mode: GuardianMode;
  readonly userIds: readonly string[];
  readonly openReserve: (
    session: CliSession,
    client: MaruhiClient,
  ) => Effect.Effect<ReserveKeys, CliError, CliServices>;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureGuardianCeremonyAllowed(io);
    const context = yield* openMetadataProject(input.flags);
    const rejection = guardianInputRejection({
      selfUserId: context.session.userId,
      mode: input.mode,
      userIds: input.userIds,
    });
    if (rejection !== null) {
      return yield* Effect.fail(usageError(rejection));
    }
    const guardians = yield* resolveGuardians({
      projectId: context.projectId,
      members: context.verified.state.members,
      userIds: input.userIds,
    });
    for (const guardian of guardians) {
      for (const device of guardian.devices) {
        yield* confirmGuardianFingerprint({
          origin: context.origin,
          userId: guardian.userId,
          fingerprintHex: device.keyFingerprintHex,
        });
      }
    }
    // 台帳の変更は予備鍵の開封を要する(CRYPTO_SPEC §8 改訂 (4))
    const reserve = yield* input.openReserve(context.session, context.client);
    const groupId = newLedgerId();
    const prepared = yield* prepareGroup({
      wardUserId: context.session.userId,
      reserve,
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
    for (const [index, guardian] of guardians.entries()) {
      yield* io.log(
        `  ${index + 1}. ${displayText(guardian.userId)} (${guardian.devices.length === 1 ? "1 device" : `${guardian.devices.length} devices`}: ${guardian.devices.map((device) => device.keyFingerprintHex).join(", ")})`,
      );
    }
    yield* logNote(
      "shares are sealed to the guardians' current devices; a guardian who adds a device later or revokes one cannot open the share on it. Check with `maruhi guardian list --project <id>` and re-add the group if needed. To restore on a machine with no device key, run `maruhi key recover --handoff` there and send the code to a guardian",
    );
  });
}

/** 台帳の保護者 1 行(status の配布形 — 端末ごと)。 */
interface GuardianRow {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianKeyFingerprintHex: string;
}

/** チェーンの現端末集合との突合結果(null = 突合していない / 一致)。 */
type Staleness = "left" | "device-gone" | null;

function stalenessOf(
  guardian: GuardianRow,
  chainMembers: ReadonlyMap<string, ChainMember> | null,
): Staleness {
  if (chainMembers === null) {
    return null;
  }
  const current = chainMembers.get(guardian.guardianUserId);
  if (current === undefined) {
    return "left";
  }
  // 分片を封印した鍵が、いまもその人の有効な端末か(2026-09-19 DK — 端末単位)
  return current.devices.has(guardian.guardianKeyFingerprintHex) ? null : "device-gone";
}

function reportGroup(
  group: {
    readonly groupId: string;
    readonly mode: GuardianMode;
    readonly guardians: readonly GuardianRow[];
  },
  chainMembers: ReadonlyMap<string, ChainMember> | null,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const shareIndexes = [...new Set(group.guardians.map((row) => row.shareIndex))].toSorted(
      (a, b) => a - b,
    );
    yield* io.log(`${group.groupId}  mode ${group.mode}  ${shareIndexes.length} guardians`);
    for (const shareIndex of shareIndexes) {
      yield* reportShare(
        group.mode,
        shareIndex,
        group.guardians.filter((row) => row.shareIndex === shareIndex),
        chainMembers,
      );
    }
  });
}

/** 1 論理分片(保護者 1 人・端末ごとの行)の表示と、開けない / 一部失効の注記。 */
function reportShare(
  mode: GuardianMode,
  shareIndex: number,
  rows: readonly GuardianRow[],
  chainMembers: ReadonlyMap<string, ChainMember> | null,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const userId = rows[0]?.guardianUserId ?? "";
    const live = rows.filter((row) => stalenessOf(row, chainMembers) === null);
    const gone = rows.filter((row) => stalenessOf(row, chainMembers) !== null);
    const stale = chainMembers !== null && live.length === 0;
    yield* io.log(
      `  ${shareIndex}. ${displayText(userId)} (${countNoun(rows.length, "device")}: ${fingerprintsOf(rows)})${stale ? "  STALE" : ""}`,
    );
    if (stale) {
      const left = rows.some((row) => stalenessOf(row, chainMembers) === "left");
      yield* logWarning(staleShareWarning(userId, left, mode));
    } else if (chainMembers !== null && gone.length > 0) {
      // 一部の端末が失効(K1-13 — SHOULD: 全端末の失効を待たずに再作成を提案する)
      yield* logNote(partiallyRevokedNote(userId, gone, live.length));
    }
  });
}

function fingerprintsOf(rows: readonly GuardianRow[]): string {
  return rows.map((row) => row.guardianKeyFingerprintHex).join(", ");
}

function staleShareWarning(userId: string, left: boolean, mode: GuardianMode): string {
  const why = left
    ? "is no longer a member of that project"
    : "has none of these devices on the chain any more";
  const consequence =
    mode === "all" ? " — this all-mode group can no longer restore your reserve key" : "";
  return `${displayText(userId)} ${why}, so their share cannot be opened${consequence}. Remove the group and add it again`;
}

function partiallyRevokedNote(
  userId: string,
  gone: readonly GuardianRow[],
  liveCount: number,
): string {
  return `${displayText(userId)}: ${countNoun(gone.length, "sealed device")} (${fingerprintsOf(gone)}) ${gone.length === 1 ? "is" : "are"} no longer active on the chain; the share still opens on the remaining ${liveCount === 1 ? "device" : "devices"}. Consider re-creating the group (\`maruhi guardian remove\` + \`add\`) so the revoked device's copy of the share is retired`;
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
    // --project があれば、台帳の保護者鍵 FP をチェーン導出の現端末集合と突合する
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
      "When one of them asks you to help restore their reserve key, run `maruhi guardian approve` with the code they send you",
    );
  });
}

// ---------------------------------------------------------------------------
// guardian approve(§8.4 — 保護者の承認。旧端末経路は 2026-09-19 DK で削除)
// ---------------------------------------------------------------------------

function ensureApproveCeremonyAllowed(io: CliIoShape): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "Refused to approve a key handoff because an AI agent environment was detected (approving hands out key material; run this yourself on a human interactive terminal)",
    terminalError:
      "Key handoff approvals are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
  });
}

/** 承認者から見た要求(コードの復号結果 + サーバーの照会)。 */
interface ApprovalTarget {
  readonly requestId: string;
  readonly ephemeralPublicKey: EncryptionKey;
  readonly wardUserId: string;
  readonly wardLabel: string;
  readonly roles: readonly {
    readonly groupId: string;
    readonly mode: GuardianMode;
    readonly shareIndex: number;
  }[];
}

/** コードを復号し、要求を照会する。 */
function resolveApprovalTarget(
  client: MaruhiClient,
  code: string,
): Effect.Effect<ApprovalTarget, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const decoded = yield* Effect.promise(() => decodeHandoffCode(code));
    if (!decoded.ok) {
      return yield* Effect.fail(
        cliError(
          "The handoff code is malformed (58 characters in groups of 4; hyphens, spaces, and letter case are ignored). Copy it again from the requesting device",
        ),
      );
    }
    const requestId = yield* Effect.promise(() => computeHandoffRequestId(decoded.value));
    const ephemeralPublicKey = yield* Effect.promise(() =>
      importEncryptionPublicKey(decoded.value),
    );
    if (!requestId.ok || !ephemeralPublicKey.ok) {
      return yield* Effect.fail(cliError("The handoff code does not encode a usable key"));
    }
    const lookup = yield* client.keyWraps
      .handoffLookup({ params: { requestId: requestId.value } })
      .pipe(
        Effect.catchTag("HandoffNotFound", () =>
          Effect.fail(
            cliError(
              "No pending handoff request matches this code (it is unknown, expired, or you are not one of the requester's guardians)",
            ),
          ),
        ),
        Effect.mapError(toCliError),
      );
    return {
      requestId: requestId.value,
      ephemeralPublicKey: ephemeralPublicKey.value,
      wardUserId: lookup.wardUserId,
      wardLabel:
        lookup.wardLogin === null
          ? displayText(lookup.wardUserId)
          : `${displayText(lookup.wardLogin)} (${displayText(lookup.wardUserId)})`,
      roles: lookup.roles,
    };
  });
}

/** 要求の説明と yes 確認(yes 以外は何も送らない)。 */
function confirmApproval(io: CliIoShape, target: ApprovalTarget): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const groups = target.roles.map(
      (role) => `${displayText(role.groupId)} (${role.mode}, share ${role.shareIndex})`,
    );
    yield* io.log(`Handoff request from ${target.wardLabel} — you are their guardian`);
    yield* io.log(`  groups: ${groups.join(", ")}`);
    yield* io.log(
      "Confirm out of band (e.g. a call to a number you already know) that this person asked you for the approval right now. Anyone who took over their account could show you this code",
    );
    const answer = yield* io.promptLine({
      prompt: `Type yes to approve the handoff for ${target.wardLabel}: `,
    });
    if (answer.trim() !== "yes") {
      return yield* Effect.fail(cliError("The handoff approval was cancelled (nothing was sent)"));
    }
  });
}

/** 承認を送る(封印済みの分片)。 */
function sendApproval(input: {
  readonly client: MaruhiClient;
  readonly requestId: string;
  readonly approverKeyFingerprintHex: string;
  readonly source: string;
  readonly shareIndex: number;
  readonly sealed: { readonly enc: Uint8Array; readonly ciphertext: Uint8Array };
}): Effect.Effect<void, CliError, HttpClient.HttpClient> {
  return input.client.keyWraps
    .handoffApprove({
      params: { requestId: input.requestId },
      payload: {
        source: input.source,
        shareIndex: input.shareIndex,
        approverKeyFingerprintHex: input.approverKeyFingerprintHex,
        encHex: encodeHex(input.sealed.enc),
        ciphertextHex: encodeHex(input.sealed.ciphertext),
      },
    })
    .pipe(
      Effect.catchTag("HandoffConflict", () =>
        Effect.fail(cliError("This request was already approved from this account")),
      ),
      Effect.catchTag("KeyWrapRateLimited", (error) =>
        Effect.fail(
          cliError(
            `The approval limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
          ),
        ),
      ),
      Effect.mapError(toCliError),
    );
}

/** 自分宛の分片行のうち、この端末の鍵へ封印された行を選ぶ(K3-10 — `deviceShares`)。 */
function ownDeviceShare(
  share: {
    readonly deviceShares: readonly {
      readonly guardianKeyFingerprintHex: string;
      readonly encHex: string;
      readonly ciphertextHex: string;
    }[];
  },
  masterKeys: MasterKeys,
): { readonly encHex: string; readonly ciphertextHex: string } | null {
  const mine = share.deviceShares.find(
    (row) => row.guardianKeyFingerprintHex === masterKeys.fingerprintHex,
  );
  return mine === undefined ? null : { encHex: mine.encHex, ciphertextHex: mine.ciphertextHex };
}

/** 保護者としての承認: 自分宛の分片をこの端末の鍵で開き、その場で E.pub へ再封印する(§8.4)。 */
function approveAsGuardian(input: {
  readonly client: MaruhiClient;
  readonly target: ApprovalTarget;
  readonly masterKeys: MasterKeys;
  readonly selfUserId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (const role of input.target.roles) {
      const share = yield* input.client.keyWraps
        .myShare({ params: { groupId: role.groupId } })
        .pipe(Effect.mapError(toCliError));
      const mine = ownDeviceShare(share, input.masterKeys);
      if (mine === null) {
        return yield* Effect.fail(
          cliError(
            `Your share of group ${displayText(role.groupId)} is not sealed to this device (fingerprint ${input.masterKeys.fingerprintHex}). Approve from one of your devices it was sealed to, or ask ${input.target.wardLabel} to re-add the group after this device was registered`,
          ),
        );
      }
      const opened = yield* openOwnGuardianShare({
        masterKeys: input.masterKeys,
        wrapped: yield* decodeWrapped(mine),
        context: {
          userId: input.target.wardUserId,
          groupId: role.groupId,
          mode: role.mode,
          shareIndex: role.shareIndex,
          guardianUserId: input.selfUserId,
        },
      });
      const sealed = yield* sealForRequester({
        ephemeralPublicKey: input.target.ephemeralPublicKey,
        value: opened,
        context: {
          userId: input.target.wardUserId,
          requestId: input.target.requestId,
          source: role.groupId,
          shareIndex: role.shareIndex,
          approverUserId: input.selfUserId,
        },
      });
      yield* sendApproval({
        client: input.client,
        requestId: input.target.requestId,
        approverKeyFingerprintHex: input.masterKeys.fingerprintHex,
        source: role.groupId,
        shareIndex: role.shareIndex,
        sealed,
      });
      yield* io.log(
        `Approved share ${role.shareIndex} of group ${displayText(role.groupId)}${role.mode === "all" ? " (the other guardians must approve too)" : ""}`,
      );
    }
    yield* logNote(
      "the approval was sealed to the requester's one-time key and nothing was stored on this device",
    );
  });
}

/**
 * `maruhi guardian approve <code>`: approve a reserve-key handoff request as one
 * of the requester's guardians (旧 `key approve` — K4-15).
 */
export function guardianApproveOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly code: string;
}): Effect.Effect<void, CliError, Keychain | CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureApproveCeremonyAllowed(io);
    const target = yield* resolveApprovalTarget(input.client, input.code);
    if (target.wardUserId === input.session.userId) {
      // サーバーは ward 本人に要求を見せない(§13-7)が、応答を信用せず手元でも拒む
      return yield* Effect.fail(
        cliError(
          "This handoff request is your own. Only your guardians can approve it (device migration no longer goes through a handoff — register a new device with `maruhi device add` / `maruhi device approve`)",
        ),
      );
    }
    const masterKeys = yield* loadMasterKeys(input.session);
    yield* confirmApproval(io, target);
    yield* approveAsGuardian({
      client: input.client,
      target,
      masterKeys,
      selfUserId: input.session.userId,
    });
  });
}
