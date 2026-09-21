// 予備鍵のハンドオフ — 要求側(CRYPTO_SPEC §8.4 / AUTH_SPEC §13-7 — KL3、2026-09-19 DK)。
//
// `maruhi key recover --handoff`(鍵を持たない端末): 一時 X25519 鍵 E をメモリ内で
// 生成し、そのハンドオフコード(= E.pub のコード化。公開情報)を表示して**保護者**の
// 承認を待つ。承認が揃ったら分片を開いて KEK を組み、台帳のグループラップから
// 予備鍵 B を復号してレコードを返す(保存しない — 後段の key-recover.ts が新しい
// 端末鍵を発行し、B で `add_device` を署名してから B を捨てる)。E は永続化しない。
//
// 承認側は `maruhi guardian approve <code>`(guardian.ts)。旧端末の承認経路
// (`source = "device"` — 端末移行)は DK K4 で削除した: 日常の端末は B を持たないため
// 成立せず、端末の追加は `maruhi device add` / `approve`(秘密を運ばない)が担う。
//
// 儀式(要求・復元)は人間の対話端末でのみ行い、AI エージェント環境では拒否する
// (ADR-0016 決定 7 の既存ゲート)。平文の分片・KEK・B はローカル変数にのみ存在する。

import {
  computeHandoffRequestId,
  decodeHex,
  encodeHandoffCode,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  type GuardianMode,
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
import { parseStoredMasterKey, type StoredMasterKey } from "./keychain.ts";
import { decodeWrapped } from "./master-ops.ts";
import type { CliSession } from "./session.ts";

/** 承認待ちのポーリング間隔。 */
const POLL_INTERVAL = Duration.seconds(3);

function ensureHandoffRequestAllowed(io: CliIoShape): Effect.Effect<void, CliError, Stdio.Stdio> {
  return ensureSensitiveTerminalAllowed({
    agent: io.agentProfile(),
    stderrIsTerminal: io.stderrIsTerminal(),
    agentError:
      "Refused to request a key handoff because an AI agent environment was detected (the restored reserve key would land in the agent's session; run this yourself on a human interactive terminal)",
    terminalError:
      "Key handoff requests are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
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
}

interface GroupSummary {
  readonly groupId: string;
  readonly mode: GuardianMode;
  readonly guardianCount: number;
}

/** 揃った承認の組(any 1 片、all 全片)。 */
interface Assembled {
  readonly group: GroupSummary;
  readonly approvals: readonly ApprovalWire[];
}

/** 届いた承認から復元に足る組を選ぶ。 */
function assemble(
  approvals: readonly ApprovalWire[],
  groups: readonly GroupSummary[],
): Assembled | null {
  for (const group of groups) {
    const shares = approvals.filter((a) => a.source === group.groupId);
    if (group.mode === "any" && shares.length >= 1) {
      return { group, approvals: shares.slice(0, 1) };
    }
    if (group.mode === "all") {
      const indexes = new Set(shares.map((s) => s.shareIndex));
      const complete =
        indexes.size === group.guardianCount &&
        Array.from({ length: group.guardianCount }, (_, i) => i + 1).every((i) => indexes.has(i));
      if (complete) {
        return { group, approvals: shares };
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

/** 承認の値(分片)を一時鍵で開く。文脈の不一致は復号失敗 = 中止。 */
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
          `Cannot open the approval from ${displayText(input.approval.approverUserId)}: it was not sealed to this request's key, or its context was altered in transit. The handoff was aborted — re-run and hand the new code to the guardians again`,
        ),
      );
    }
    return opened.value;
  });
}

/** 揃った組から KEK を組み、台帳のグループラップを復号する。 */
function recoverBlob(input: {
  readonly client: MaruhiClient;
  readonly ephemeral: EncryptionKeyPair;
  readonly userId: string;
  readonly requestId: string;
  readonly assembled: Assembled;
}): Effect.Effect<Uint8Array, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
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
    const wrapped = yield* decodeBlobWrap(group.wrap);
    const unwrapped = yield* Effect.tryPromise({
      try: () =>
        unwrapMasterBlob({
          kek: joined.value,
          wrapped,
          context: {
            userId: input.userId,
            kind: "guardian",
            wrapRef: group.groupId,
            mode: group.mode,
          },
        }),
      catch: () => cliError("Failed to decrypt the wrapped reserve key (crypto error)"),
    });
    if (!unwrapped.ok) {
      return yield* Effect.fail(
        cliError(
          "Cannot decrypt the wrapped reserve key with the approvals received. The wrap and the approvals do not match (the ledger or the approvals were altered) — the handoff was aborted",
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
      "Send this code to a guardian and ask them to run `maruhi guardian approve` with it (confirm with them out of band that it is you)",
    );
    yield* io.logError(
      `Registered guardian groups: ${groups.map((g) => `${g.groupId} (${g.mode}, ${g.guardianCount} guardians)`).join(", ")}`,
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

/**
 * `maruhi key recover --handoff` の前段: request approvals from your guardians
 * and open the reserve key (memory only — key-recover.ts が後段を担う)。
 */
export function requestHandoffReserve(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<StoredMasterKey, CliError, CliIo | Stdio.Stdio | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* ensureHandoffRequestAllowed(io);
    const status = yield* input.client.keyWraps.status({}).pipe(Effect.mapError(toCliError));
    const groups: GroupSummary[] = status.guardianGroups.map((g) => ({
      groupId: g.groupId,
      mode: g.mode,
      guardianCount: new Set(g.guardians.map((row) => row.shareIndex)).size,
    }));
    if (groups.length === 0) {
      return yield* Effect.fail(
        cliError(
          "You have no guardians registered, so nobody can approve a handoff. Open the reserve key with your recovery code (`maruhi key recover`) or a passkey (`--passkey`) instead",
        ),
      );
    }
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
    const record = parseStoredMasterKey(new TextDecoder().decode(blob));
    if (record === null) {
      return yield* Effect.fail(
        cliError(
          "The decrypted blob is not a key record. The ledger holds a broken record, or a newer maruhi wrote it — update maruhi, or open the reserve key another way",
        ),
      );
    }
    for (const approval of assembled.approvals) {
      yield* io.log(
        `approved by ${displayText(approval.approverUserId)} (guardian, group ${displayText(approval.source)}; device key fingerprint ${approval.approverKeyFingerprintHex})`,
      );
    }
    // 要求は役目を終えた(承認は E とともに無価値になるが、行は消しておく)
    yield* input.client.keyWraps
      .handoffCancel({ params: { requestId: request.requestId } })
      .pipe(Effect.ignore);
    return record;
  });
}
