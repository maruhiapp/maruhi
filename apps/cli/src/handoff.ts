// 鍵のハンドオフ(CRYPTO_SPEC §8.4 / AUTH_SPEC §13-7 — KL3)。
//
// 要求者(新端末): `maruhi key recover --handoff` — 一時 X25519 鍵 E をメモリ内で
// 生成し、そのハンドオフコード(= E.pub のコード化。公開情報)を表示して承認を
// 待つ。承認が揃ったら分片 / KEK_h を開き、台帳(または同送)のラップから B を
// 復号してキーチェーン(または agent のメモリ)へ保存する。E は永続化しない。
//
// 承認者: `maruhi key approve <code>` — コードから E.pub と request_id を復元し、
// 要求を照会する。ward が自分なら端末移行(乱数 KEK_h で B をラップし KEK_h を
// E.pub へ封印)、他人なら保護者承認(自分宛の分片を開き、その場で E.pub へ再封印)。
// サーバーは E.pub を中継しない(コードは人が運ぶ — 鍵すり替えの余地が無い)。
//
// 儀式(承認・復元)は人間の対話端末でのみ行い、AI エージェント環境では拒否する
// (ADR-0016 決定 7 の既存ゲート)。平文の分片・KEK・B はローカル変数にのみ存在する。

import {
  computeHandoffRequestId,
  decodeHandoffCode,
  decodeHex,
  encodeHandoffCode,
  encodeHex,
  type EncryptionKey,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  generateMasterWrapKek,
  type GuardianMode,
  importEncryptionPublicKey,
  joinGuardianShares,
  openHandoffValue,
  unwrapMasterBlob,
} from "@maruhi/crypto";
import { Duration, Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import { ensureSensitiveTerminalAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { Keychain, parseStoredMasterKey, serializeStoredMasterKey } from "./keychain.ts";
import {
  decodeWrapped,
  openOwnGuardianShare,
  sealForRequester,
  wrapOwnBlobForHandoff,
} from "./master-ops.ts";
import { logNote } from "./notice.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";

/** 承認待ちのポーリング間隔。 */
const POLL_INTERVAL = Duration.seconds(3);

function ensureHandoffCeremonyAllowed(
  io: CliIoShape,
  action: "request" | "approve",
): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      action === "request"
        ? "Refused to request a key handoff because an AI agent environment was detected (the restored key would land in the agent's session; run this yourself on a human interactive terminal)"
        : "Refused to approve a key handoff because an AI agent environment was detected (approving hands out key material; run this yourself on a human interactive terminal)",
    terminalError: `Key handoff ${action === "request" ? "requests" : "approvals"} are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)`,
  });
}

/** サーバーが返す承認 1 件(ワイヤ形)。 */
interface ApprovalWire {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly blob: {
    readonly suite: string;
    readonly nonceHex: string;
    readonly ciphertextHex: string;
  } | null;
}

interface GroupSummary {
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly guardianCount: number;
}

/** 揃った承認の組(device 1 件、any 1 片、all 全片)。 */
type Assembled =
  | { readonly kind: "device"; readonly approval: ApprovalWire }
  | {
      readonly kind: "group";
      readonly group: GroupSummary;
      readonly approvals: readonly ApprovalWire[];
    };

/** 届いた承認から復元に足る組を選ぶ(端末移行 > 保護者グループの順)。 */
function assemble(
  approvals: readonly ApprovalWire[],
  groups: readonly GroupSummary[],
): Assembled | null {
  const device = approvals.find((a) => a.source === "device" && a.blob !== null);
  if (device !== undefined) {
    return { kind: "device", approval: device };
  }
  for (const group of groups) {
    const shares = approvals.filter((a) => a.source === group.groupId);
    if (group.mode === "any" && shares.length >= 1) {
      return { kind: "group", group, approvals: shares.slice(0, 1) };
    }
    if (group.mode === "all") {
      const indexes = new Set(shares.map((s) => s.shareIndex));
      const complete =
        indexes.size === group.guardianCount &&
        Array.from({ length: group.guardianCount }, (_, i) => i + 1).every((i) => indexes.has(i));
      if (complete) {
        return { kind: "group", group, approvals: shares };
      }
    }
  }
  return null;
}

function decodeBlobWrap(blob: {
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}): Effect.Effect<{ readonly nonce: Uint8Array; readonly ciphertext: Uint8Array }, CliError> {
  const nonce = decodeHex(blob.nonceHex);
  const ciphertext = decodeHex(blob.ciphertextHex);
  return nonce === null || ciphertext === null
    ? Effect.fail(cliError("The server response is malformed (cannot decode hex)"))
    : Effect.succeed({ nonce, ciphertext });
}

/** 承認の値(分片 / KEK_h)を一時鍵で開く。文脈の不一致は復号失敗 = 中止。 */
function openApproval(input: {
  readonly ephemeral: EncryptionKeyPair;
  readonly userId: string;
  readonly requestId: string;
  readonly approval: ApprovalWire;
}): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
    const wrapped = yield* decodeWrapped(input.approval);
    const opened = yield* Effect.tryPromise({
      try: () =>
        openHandoffValue({
          ephemeralKeyPair: input.ephemeral,
          wrapped,
          context: {
            userId: input.userId,
            requestId: input.requestId,
            source: input.approval.source,
            shareIndex: input.approval.shareIndex,
            approverUserId: input.approval.approverUserId,
          },
        }),
      catch: () => cliError("Failed to open an approval (crypto error)"),
    });
    if (!opened.ok) {
      return yield* Effect.fail(
        cliError(
          `Cannot open the approval from ${displayText(input.approval.approverUserId)}: it was not sealed to this request's key, or its context was altered in transit. The handoff was aborted — re-run and hand the new code to the approver again`,
        ),
      );
    }
    return opened.value;
  });
}

/** 揃った組から KEK と B のラップを得て復号する。 */
function recoverBlob(input: {
  readonly client: MaruhiClient;
  readonly ephemeral: EncryptionKeyPair;
  readonly userId: string;
  readonly requestId: string;
  readonly assembled: Assembled;
}): Effect.Effect<Uint8Array, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (input.assembled.kind === "device") {
      const kek = yield* openApproval({ ...input, approval: input.assembled.approval });
      const blob = input.assembled.approval.blob;
      if (blob === null) {
        return yield* Effect.fail(cliError("The device approval carries no wrapped key"));
      }
      return yield* unwrapOrFail(kek, yield* decodeBlobWrap(blob), {
        userId: input.userId,
        kind: "device",
        wrapRef: input.requestId,
      });
    }
    const values: Uint8Array[] = [];
    for (const approval of input.assembled.approvals) {
      values.push(yield* openApproval({ ...input, approval }));
    }
    const joined = joinGuardianShares({
      mode: input.assembled.group.mode,
      shares: values,
      expectedCount: input.assembled.group.guardianCount,
    });
    if (!joined.ok) {
      return yield* Effect.fail(cliError("Failed to reassemble the group key from the shares"));
    }
    const group = yield* input.client.keyWraps
      .guardianGet({ params: { groupId: input.assembled.group.groupId } })
      .pipe(Effect.mapError(toCliError));
    return yield* unwrapOrFail(joined.value, yield* decodeBlobWrap(group.wrap), {
      userId: input.userId,
      kind: "guardian",
      wrapRef: group.groupId,
      mode: group.mode,
    });
  });
}

function unwrapOrFail(
  kek: Uint8Array,
  wrapped: { readonly nonce: Uint8Array; readonly ciphertext: Uint8Array },
  context: Parameters<typeof unwrapMasterBlob>[0]["context"],
): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
    const unwrapped = yield* Effect.tryPromise({
      try: () => unwrapMasterBlob({ kek, wrapped, context }),
      catch: () => cliError("Failed to decrypt the wrapped master key (crypto error)"),
    });
    if (!unwrapped.ok) {
      return yield* Effect.fail(
        cliError(
          "Cannot decrypt the wrapped master key with the approvals received. The wrap and the approvals do not match (the ledger or the approvals were altered) — the handoff was aborted",
        ),
      );
    }
    return unwrapped.value;
  });
}

/** 一時鍵 E とそのコード / request_id(E はこのプロセスのメモリにだけ存在する — §8.4)。 */
interface HandoffRequest {
  readonly ephemeral: EncryptionKeyPair;
  readonly code: string;
  readonly requestId: string;
}

function newHandoffRequest(): Effect.Effect<HandoffRequest, CliError> {
  return Effect.gen(function* () {
    const ephemeral = yield* Effect.tryPromise({
      try: () => generateEncryptionKeyPair(),
      catch: () => cliError("Failed to generate the handoff key (crypto error)"),
    });
    const publicKey = yield* Effect.tryPromise({
      try: () => exportEncryptionPublicKey(ephemeral.publicKey),
      catch: () => cliError("Failed to export the handoff key (crypto error)"),
    });
    const code = yield* Effect.promise(() => encodeHandoffCode(publicKey));
    const requestId = yield* Effect.promise(() => computeHandoffRequestId(publicKey));
    if (!code.ok || !requestId.ok) {
      return yield* Effect.fail(cliError("Failed to derive the handoff code"));
    }
    return { ephemeral, code: code.value, requestId: requestId.value };
  });
}

/** コードと案内を表示する(コードは公開鍵 = 秘密ではないが、案内と同じ stderr に出す)。 */
function announceCode(
  io: CliIoShape,
  code: string,
  groups: readonly GroupSummary[],
): Effect.Effect<void> {
  return Effect.gen(function* () {
    yield* io.logError("");
    yield* io.logError("Handoff code (this is a public key, not a secret):");
    yield* io.logError("");
    yield* io.logError(`    ${code}`);
    yield* io.logError("");
    yield* io.logError(
      "On a device that still has your master key, run `maruhi key approve` with this code. Or send the code to a guardian and ask them to run the same command",
    );
    yield* io.logError(
      groups.length === 0
        ? "You have no guardians registered, so only one of your own devices can approve"
        : `Registered guardian groups: ${groups.map((g) => `${g.groupId} (${g.mode}, ${g.guardianCount} guardians)`).join(", ")}`,
    );
    yield* io.logError(
      "Waiting for approvals (the request expires after 15 minutes; press Ctrl+C to cancel)",
    );
  });
}

/** 承認が揃うまでポーリングする(期限切れは失敗)。 */
function awaitApprovals(input: {
  readonly client: MaruhiClient;
  readonly requestId: string;
  readonly groups: readonly GroupSummary[];
  readonly expiresAtMs: number;
}): Effect.Effect<Assembled, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    let received = 0;
    while (Date.now() < input.expiresAtMs) {
      const page = yield* input.client.keyWraps
        .handoffApprovals({ params: { requestId: input.requestId } })
        .pipe(Effect.mapError(toCliError));
      received = page.approvals.length;
      const assembled = assemble(page.approvals, input.groups);
      if (assembled !== null) {
        return assembled;
      }
      yield* Effect.sleep(POLL_INTERVAL);
    }
    return yield* Effect.fail(
      cliError(
        `The handoff request expired without enough approvals (${received} received). Re-run to issue a new code`,
      ),
    );
  });
}

/** 復号した B をレコードとして検証し、キーチェーン(または agent)へ保存する。 */
function storeRecoveredBlob(
  entryName: string,
  blob: Uint8Array,
): Effect.Effect<void, CliError, Keychain | CliIo> {
  return Effect.gen(function* () {
    const record = parseStoredMasterKey(new TextDecoder().decode(blob));
    if (record === null) {
      return yield* Effect.fail(
        cliError(
          "The decrypted blob is not a master-key record. The approver's device holds a broken key record, or a newer maruhi wrote it — update maruhi, or restore from another device",
        ),
      );
    }
    const validated = yield* importMasterKeys(record).pipe(
      Effect.mapError(() =>
        cliError(
          "The decrypted master-key record cannot be loaded (unknown suite or corrupt). Update maruhi, or restore from another device",
        ),
      ),
    );
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Restored the master key via handoff",
      fingerprintHex: validated.fingerprintHex,
    });
  });
}

/**
 * `maruhi key recover --handoff`: request approvals from another device of
 * yours or from your guardians, then restore the master key.
 */
export function requestHandoffOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureHandoffCeremonyAllowed(io, "request");
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "A master key already exists on this device. Overwriting it would lose the existing key, so this is refused (check it with `maruhi key show`)",
    );
    const request = yield* newHandoffRequest();
    const created = yield* input.client.keyWraps
      .handoffCreate({ payload: { requestId: request.requestId } })
      .pipe(
        Effect.catchTag("KeyWrapRateLimited", (error) =>
          Effect.fail(
            cliError(
              `The handoff request limit was reached. Retry after ${error.retryAfterSeconds} seconds`,
            ),
          ),
        ),
        Effect.mapError(toCliError),
      );
    const status = yield* input.client.keyWraps.status({}).pipe(Effect.mapError(toCliError));
    const groups: GroupSummary[] = status.guardianGroups.map((g) => ({
      groupId: g.groupId,
      mode: g.mode,
      guardianCount: g.guardians.length,
    }));
    yield* announceCode(io, request.code, groups);
    const assembled = yield* awaitApprovals({
      client: input.client,
      requestId: request.requestId,
      groups,
      expiresAtMs: created.expiresAtMs,
    });
    const blob = yield* recoverBlob({
      client: input.client,
      ephemeral: request.ephemeral,
      userId: input.session.userId,
      requestId: request.requestId,
      assembled,
    });
    yield* storeRecoveredBlob(entryName, blob);
    const approvers = assembled.kind === "device" ? [assembled.approval] : [...assembled.approvals];
    for (const approval of approvers) {
      yield* io.log(
        `approved by ${displayText(approval.approverUserId)} (${approval.source === "device" ? "your own device" : `guardian, group ${displayText(approval.source)}`}; key fingerprint ${approval.approverKeyFingerprintHex})`,
      );
    }
    // 要求は役目を終えた(承認は E とともに無価値になるが、行は消しておく)
    yield* input.client.keyWraps
      .handoffCancel({ params: { requestId: request.requestId } })
      .pipe(Effect.ignore);
  });
}

/** 承認者から見た要求(コードの復号結果 + サーバーの照会)。 */
interface ApprovalTarget {
  readonly requestId: string;
  readonly ephemeralPublicKey: EncryptionKey;
  readonly wardUserId: string;
  readonly wardLabel: string;
  readonly roles: HandoffLookup["roles"];
}

type HandoffLookup = {
  readonly wardUserId: string;
  readonly wardLogin: string | null;
  readonly roles: readonly (
    | "device"
    | { readonly groupId: string; readonly mode: GuardianMode; readonly shareIndex: number }
  )[];
};

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
    const lookup: HandoffLookup = yield* client.keyWraps
      .handoffLookup({ params: { requestId: requestId.value } })
      .pipe(
        Effect.catchTag("HandoffNotFound", () =>
          Effect.fail(
            cliError(
              "No pending handoff request matches this code (it is unknown, expired, or you are neither the requester nor one of their guardians)",
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
function confirmApproval(
  io: CliIoShape,
  target: ApprovalTarget,
  isSelf: boolean,
): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    if (isSelf) {
      yield* io.log("Handoff request from your own account (device migration)");
      yield* io.log(
        "Approve only if you generated this code yourself on the other device just now. Approving sends your master key to that device",
      );
    } else {
      const groups = target.roles
        .filter((role): role is Exclude<typeof role, "device"> => role !== "device")
        .map((role) => `${displayText(role.groupId)} (${role.mode}, share ${role.shareIndex})`);
      yield* io.log(`Handoff request from ${target.wardLabel} — you are their guardian`);
      yield* io.log(`  groups: ${groups.join(", ")}`);
      yield* io.log(
        "Confirm out of band (e.g. a call to a number you already know) that this person asked you for the approval right now. Anyone who took over their account could show you this code",
      );
    }
    const answer = yield* io.promptLine({
      prompt: isSelf
        ? "Type yes to hand your master key to the device that showed this code: "
        : `Type yes to approve the handoff for ${target.wardLabel}: `,
    });
    if (answer.trim() !== "yes") {
      return yield* Effect.fail(cliError("The handoff approval was cancelled (nothing was sent)"));
    }
  });
}

/** 承認を送る(封印済みの値 + device なら同送ラップ)。 */
function sendApproval(input: {
  readonly client: MaruhiClient;
  readonly requestId: string;
  readonly approverKeyFingerprintHex: string;
  readonly source: string;
  readonly shareIndex: number;
  readonly sealed: { readonly enc: Uint8Array; readonly ciphertext: Uint8Array };
  readonly blob?: { readonly nonce: Uint8Array; readonly ciphertext: Uint8Array };
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
        ...(input.blob === undefined
          ? {}
          : {
              blob: {
                suite: "maruhi/v1" as const,
                nonceHex: encodeHex(input.blob.nonce),
                ciphertextHex: encodeHex(input.blob.ciphertext),
              },
            }),
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

/** 旧端末としての承認: 乱数 KEK_h で B をラップし、KEK_h を E.pub へ封印する(§8.4)。 */
function approveAsDevice(input: {
  readonly client: MaruhiClient;
  readonly target: ApprovalTarget;
  readonly masterKeys: MasterKeys;
  readonly selfUserId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const kek = generateMasterWrapKek();
    const blob = yield* wrapOwnBlobForHandoff({
      masterKeys: input.masterKeys,
      kek,
      context: { userId: input.target.wardUserId, kind: "device", wrapRef: input.target.requestId },
    });
    const sealed = yield* sealForRequester({
      ephemeralPublicKey: input.target.ephemeralPublicKey,
      value: kek,
      context: {
        userId: input.target.wardUserId,
        requestId: input.target.requestId,
        source: "device",
        shareIndex: 0,
        approverUserId: input.selfUserId,
      },
    });
    yield* sendApproval({
      client: input.client,
      requestId: input.target.requestId,
      approverKeyFingerprintHex: input.masterKeys.fingerprintHex,
      source: "device",
      shareIndex: 0,
      sealed,
      blob,
    });
    yield* io.log("Approved. The other device can now finish `maruhi key recover --handoff`");
  });
}

/** 保護者としての承認: 自分宛の分片を開き、その場で E.pub へ再封印する(§8.4)。 */
function approveAsGuardian(input: {
  readonly client: MaruhiClient;
  readonly target: ApprovalTarget;
  readonly masterKeys: MasterKeys;
  readonly selfUserId: string;
}): Effect.Effect<void, CliError, CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    for (const role of input.target.roles) {
      if (role === "device") {
        continue;
      }
      const share = yield* input.client.keyWraps
        .myShare({ params: { groupId: role.groupId } })
        .pipe(Effect.mapError(toCliError));
      const opened = yield* openOwnGuardianShare({
        masterKeys: input.masterKeys,
        wrapped: yield* decodeWrapped(share),
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
 * `maruhi key approve <code>`: approve a handoff request — as the requester's
 * other device (device handoff) or as one of their guardians.
 */
export function approveHandoffOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly code: string;
}): Effect.Effect<void, CliError, Keychain | CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureHandoffCeremonyAllowed(io, "approve");
    const target = yield* resolveApprovalTarget(input.client, input.code);
    const masterKeys = yield* loadMasterKeys(input.session);
    const isSelf = target.wardUserId === input.session.userId;
    yield* confirmApproval(io, target, isSelf);
    const approval = {
      client: input.client,
      target,
      masterKeys,
      selfUserId: input.session.userId,
    };
    yield* isSelf ? approveAsDevice(approval) : approveAsGuardian(approval);
  });
}
