// `maruhi device` グループ(CRYPTO_SPEC §3 / §6.2「端末鍵」、AUTH_SPEC §13-11 — 2026-09-19
// DK。設計録 dk-design.md §9 K4-5 / K4-6 / K4-7 / K4-13 / K4-18)。
//
// - `device add [--label] [--replace]`(新端末側): 端末鍵を生成して要求を出し、FP(hex +
//   12 語)を表示して待つ。待機の合図は登録簿(advisory)、完了の確認は各プロジェクトの
//   検証済みチェーン(K4-5)。同じビューで、載ったプロジェクトの鍵の到達(自分宛の DEK が
//   全エポックにあるか — DK K12)と失効した鍵を確かめて報告する。ゲートなし(DK-D — 要求側は何も足さない)
// - `device approve <fp|words> [--cap] [--env…]`(登録済み端末側): 儀式ゲート(TTY +
//   非エージェント — agent-gate.ts)→ 要求一覧の公開鍵から FP を**再計算**して照合(K4-6)
//   → 各プロジェクトを開いて判定(既に載っている鍵の cap が今回の cap と違えば何も書かずに
//   止まる — K10-1)→ 各プロジェクトへ `add_device` → バックフィル → ローカル記録(approved)→ 登録簿へ
//   PUT(合図)→ 要求の取消(PUT が成功したときだけ — 失敗なら要求を残す: K9-1)
// - `device list [--project]`: チェーン(真実)・登録簿(server-reported)・ローカル記録
//   (出所)を突き合わせて表示する。値ゼロ・鍵不要・ゲートなし
// - `device revoke <ref…> [--user] [--project] [--yes] [--revoke-token]`: 参照は FP の
//   接頭辞(8 文字以上・一意)か登録簿の表示名(自分のみ — FP を併記して確認)。確認表 →
//   yes → 各プロジェクトへ `revoke_device` → sweep 第 5 種(K4-8)→ ローカル記録に revoked
//   → 登録簿の行を削除 → トークン失効の提案(K4-13 — `--revoke-token` の明示のみ自動)
//
// 登録簿は表示・合図にしか使わない: 承認する鍵は要求行の公開鍵から再計算した FP が
// 人の運んだ FP と一致するものだけ、失効する端末はチェーン上の端末だけ、ローカル記録は
// 封印・承認・観測の 3 経路だけが書く(K4-3)。

import {
  DEVICE_ADD_REQUEST_TTL_MS,
  DeviceRegistryConflictError,
  DeviceRegistryLimitError,
  ForbiddenError,
  MAX_DEVICE_REGISTRY_ROWS_PER_USER,
  TokenNotFoundError,
} from "@maruhi/api-schema";
import type { ChainDevice, ChainMember, DeviceCap, MemberScope, Role } from "@maruhi/crypto";
import {
  computeUserKeyFingerprint,
  decodeHex,
  effectivePermissionOf,
  encodeHex,
  scopeIncludesEnvironment,
} from "@maruhi/crypto";
import { Duration, Effect, Result } from "effect";

import { ensureDeviceApproveAllowed } from "./agent-gate.ts";
import type { MaruhiClient } from "./api.ts";
import {
  type CliServices,
  openMetadataProject,
  openProject,
  type ProjectContext,
  type ProjectContextBase,
} from "./context.ts";
import { ROLE_RANK } from "./dek-wrap.ts";
import { type DekRecipient, environmentKeysFor, missingEpochsOf } from "./deks.ts";
import { describeGapFillRoute, describeMissingOwnEpochs, gapFillCommandOf } from "./device-gaps.ts";
import {
  capWithinSignerCap,
  describeCap,
  describeDevice,
  deviceProvenanceOf,
  devicesOf,
  findOwnDevice,
  reAddDeviceRoute,
  revokedFingerprintsOf,
} from "./device-key.ts";
import {
  appendAddDevice,
  appendRevokeDevice,
  backfillToDevice,
  DEVICE_REVOKED_ROTATION_REASON,
  type DeviceBackfillOutcome,
  deviceEnvironmentsOf,
  type DeviceSweepOutcome,
  sweepAfterDeviceRevoke,
} from "./device-ops.ts";
import { countNoun, displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, masterKeyEntryName, serializeStoredMasterKey } from "./keychain.ts";
import { logNote, logWarning } from "./notice.ts";
import { type OwnDeviceEntry, OwnDeviceStore } from "./own-devices.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { compareCodePoints, requireScopeEnvironmentsExist, sameScope } from "./scope.ts";
import {
  type CliSession,
  importMasterKeys,
  loadMasterKeys,
  type MasterKeys,
  storeMasterKeyAndReport,
} from "./session.ts";
import { sweepRotateFor } from "./sweep-rotate.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

/** 登録簿 1 行(server-reported)。 */
interface RegistryRow {
  readonly keyFingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly tokenId?: string | undefined;
  readonly createdAtMs: number;
}

const FULL_FINGERPRINT = /^[0-9a-f]{32}$/;
const FINGERPRINT_PREFIX = /^[0-9a-f]{8,32}$/;
const WORD_COUNT = 12;

/** 公開鍵から FP を再計算する(登録簿・要求行の申告 FP を信用しない — §13-11)。 */
function recomputeFingerprint(
  encPubHex: string,
  sigPubHex: string,
): Effect.Effect<string | null, CliError> {
  const enc = decodeHex(encPubHex);
  const sig = decodeHex(sigPubHex);
  if (enc === null || sig === null) {
    return Effect.succeed(null);
  }
  return Effect.tryPromise({
    try: () => computeUserKeyFingerprint(enc, sig),
    catch: () => cliError("Failed to compute a key fingerprint (crypto error)"),
  }).pipe(Effect.map((result) => (result.ok ? encodeHex(result.value) : null)));
}

/** 登録簿の取得(読めない場合は null — 表示・合図にしか使わないので失敗させない)。 */
function fetchRegistry(client: MaruhiClient): Effect.Effect<readonly RegistryRow[] | null, never> {
  return client.devices.list({}).pipe(
    Effect.map((response) => response.devices as readonly RegistryRow[]),
    Effect.catch(() => Effect.succeed(null)),
  );
}

/** プロジェクト集合の解決: `--project` があればそれだけ、無ければ所属一覧(申告 = 発見用)。 */
function resolveProjectIds(
  client: MaruhiClient,
  project: string | undefined,
): Effect.Effect<readonly string[], CliError> {
  return project === undefined
    ? fetchProjectMemberships(client).pipe(
        Effect.map((rows) => rows.map((row) => row.projectId).toSorted(compareCodePoints)),
      )
    : Effect.succeed([project]);
}

// ---------------------------------------------------------------------------
// device add
// ---------------------------------------------------------------------------

/** 待機の間隔(登録簿のポーリング — K4-5。テストは短縮する)。 */
const DEVICE_ADD_POLL_INTERVAL_MS = 3_000;

/**
 * 待機の途中で 1 度だけ出す案内の閾値(K7-3): 要求の作成からこの時間が経っても合図が
 * 無ければ「承認側の出力を確認せよ」を出す。承認が全プロジェクトで失敗すると合図は
 * 来ない(K4-31)ので、15 分黙って待たせない。経過は要求の期限から逆算する
 * (再開した待機でも要求の年齢で判定)。docs(`devices.mdx`)が「five minutes」と
 * 写しているので、値は `cli-vocabulary.test.ts` の釘で留める。
 */
export const DEVICE_ADD_WAIT_HINT_AFTER_MS = DEVICE_ADD_REQUEST_TTL_MS / 3;

/** `maruhi device add [--label <name>] [--replace]`(新端末側)。 */
export function deviceAddOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly label: string;
  readonly replace: boolean;
  readonly pollIntervalMs?: number | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keys = yield* deviceKeyForRequest(input);
    const words = yield* fingerprintWords(keys.fingerprintHex, "The key fingerprint is malformed");
    const request = yield* createOrResumeRequest(input, keys);
    yield* io.log(`This device's key fingerprint: ${keys.fingerprintHex}`);
    yield* io.log(`fp words: ${formatWordList(words)}`);
    if (request.kind === "already-registered") {
      // 要求行は無い(登録簿の行が合図)— approve の案内は出さず、チェーンの確認へ
      yield* io.log(
        "This key is already in your device registry (no pending request); verifying it on each project's chain",
      );
    } else {
      yield* io.log(
        `On a device that is already registered, run \`maruhi device approve ${keys.fingerprintHex}\` (or pass the 12 words). The request expires at ${formatUtcMinutes(request.expiresAtMs)} (15 minutes); re-running \`maruhi device add\` with this key resumes waiting while the request is valid`,
      );
      yield* io.log("Waiting for approval (Ctrl+C to stop waiting; the request stays valid)…");
    }
    const signalled = yield* waitForRegistryRow({
      client: input.client,
      fingerprintHex: keys.fingerprintHex,
      // 登録簿に載っている鍵は 1 巡目で合図を拾う(期限は形式上 TTL ぶん先)
      expiresAtMs:
        request.kind === "pending" ? request.expiresAtMs : Date.now() + DEVICE_ADD_REQUEST_TTL_MS,
      intervalMs: input.pollIntervalMs ?? DEVICE_ADD_POLL_INTERVAL_MS,
      // 途中の案内は要求があるときだけ(登録簿の行が合図の待機では「承認側の出力」が無い)
      hintAfterMs: request.kind === "pending" ? DEVICE_ADD_WAIT_HINT_AFTER_MS : null,
    });
    if (!signalled) {
      // 期限切れ後の再実行は拒否される(鍵あり + 要求なし + 登録簿なし — K4-21)ので、
      // 先へ進む手は `--replace` だけ。ただし承認側の登録簿 PUT が落ち、承認側が期限までに
      // 再実行しなかったときは、鍵はチェーンに載っている(合図だけが無い — K9-3 の T3)。
      // `--replace` はその鍵を捨ててチェーンに孤児を残すので、承認側の出力を条件に分ける
      // (K7-1 / K9-3)。第 1 文も「承認前に」とは言わない(T3 では承認は済んでいる)
      return yield* Effect.fail(
        cliError(
          `The device-add request expired before this machine saw the completion signal (requests live 15 minutes). Check the output on the approving device: if it registered nothing, run \`maruhi device add --replace\` on this machine — this key (${keys.fingerprintHex}) is registered nowhere, so discarding it loses nothing — and approve the new fingerprint it prints from a registered device with \`maruhi device approve\`. If it registered this device but could not list it in your device registry, keep this key: it is already registered on the projects that output lists (\`maruhi device list\` on this machine shows where), and only its row in your device registry is missing`,
        ),
      );
    }
    // 真実はチェーン: 合図(登録簿の行)の後に各プロジェクトを同期して自分の端末を数え、
    // 載っているプロジェクトでは同じビューで鍵の到達を確かめる(DK K12-1)
    const confirmation = yield* confirmOnChains({
      session: input.session,
      client: input.client,
      keys,
    });
    yield* io.log(
      `Approved: this device is registered on ${countNoun(confirmation.registered.length, "project")} (verified on each project's chain)`,
    );
    // 完了の文は立場が分かった時点で出し、鍵の到達の確認(環境ごとの取得)はその後に回す
    // (pullfrog 指摘 — K12-14。出力の順序は K12-3 のまま)
    yield* reportConfirmation(confirmation, keys);
  });
}

/** 1 プロジェクトのチェーン上のこの鍵の立場(DK K12-6 — 同期できなければ absent)。 */
type KeyStanding =
  | {
      readonly kind: "present";
      readonly context: ProjectContextBase;
      readonly member: ChainMember;
      readonly device: ChainDevice;
    }
  | { readonly kind: "revoked" }
  | { readonly kind: "absent" };

/** 1 環境の鍵の到達の確認で報告する事実(DK K12-3 — 届いていれば何も運ばない)。 */
type KeyReachIssue =
  | {
      readonly kind: "missing";
      readonly environmentId: string;
      readonly epochs: readonly number[];
    }
  | {
      readonly kind: "unchecked";
      /** null = 環境の列挙そのものに失敗した。 */
      readonly environmentId: string | null;
      readonly message: string;
    };

/** 合図の後のチェーンでの確認の結果(プロジェクトごとの立場。載っている所は文脈つき)。 */
interface ChainConfirmation {
  readonly registered: readonly {
    readonly projectId: string;
    readonly standing: Extract<KeyStanding, { readonly kind: "present" }>;
  }[];
  readonly revoked: readonly string[];
  readonly missing: readonly string[];
}

function confirmOnChains(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly keys: MasterKeys;
}): Effect.Effect<ChainConfirmation, CliError, CliServices> {
  return Effect.gen(function* () {
    const projects = yield* fetchProjectMemberships(input.client);
    const registered: ChainConfirmation["registered"][number][] = [];
    const revoked: string[] = [];
    const missing: string[] = [];
    for (const project of projects) {
      const standing = yield* keyStandingOnProject({
        session: input.session,
        projectId: project.projectId,
        fingerprintHex: input.keys.fingerprintHex,
      });
      if (standing.kind === "present") {
        registered.push({ projectId: project.projectId, standing });
      } else {
        (standing.kind === "revoked" ? revoked : missing).push(project.projectId);
      }
    }
    return { registered, revoked, missing };
  });
}

/**
 * 1 プロジェクトの検証済みチェーンでのこの鍵の立場: 有効な端末(文脈つき — 鍵の到達の
 * 確認が同じビューを使う)、自分宛の `revoke_device` で失効した鍵、どちらでもない。
 */
function keyStandingOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<KeyStanding, never, CliServices> {
  return openMetadataProject({ server: input.session.origin, project: input.projectId }).pipe(
    Effect.map((context): KeyStanding => {
      const member = context.verified.state.members.get(input.session.userId);
      const device = member?.devices.get(input.fingerprintHex);
      if (member !== undefined && device !== undefined) {
        return { kind: "present", context, member, device };
      }
      return revokedFingerprintsOf(context.verified, input.session.userId).has(input.fingerprintHex)
        ? { kind: "revoked" }
        : { kind: "absent" };
    }),
    Effect.catch(() => Effect.succeed<KeyStanding>({ kind: "absent" })),
  );
}

/**
 * この端末宛の DEK が、承認側が配ったはずの各環境(`deviceEnvironmentsOf` — バックフィルと
 * 同じ集合)の全エポックに届いているか(DK K12-2): 値付き pull と同じ取得口
 * (`environmentKeysFor` — §5.1 / §5.2 の検証と開封)と同じ欠けの判定(`missingEpochsOf`)。
 * 開いた DEK は判定にだけ使い、ここから出さない。失敗は事実に畳む(`device add` の成否を
 * 変えない — K12-4)。
 */
function checkKeyReach(input: {
  readonly context: ProjectContextBase;
  readonly member: ChainMember;
  readonly device: ChainDevice;
  readonly keys: MasterKeys;
}): Effect.Effect<readonly KeyReachIssue[]> {
  return Effect.gen(function* () {
    const { client, verified } = input.context;
    const environments = yield* Effect.result(
      deviceEnvironmentsOf({
        client,
        verified,
        targetMember: input.member,
        targetDevice: input.device,
      }),
    );
    if (Result.isFailure(environments)) {
      return [{ kind: "unchecked", environmentId: null, message: environments.failure.message }];
    }
    const recipient: DekRecipient = {
      userId: input.context.session.userId,
      encPubHex: input.keys.record.encPubHex,
      encKeyPair: input.keys.encKeyPair,
    };
    const issues: KeyReachIssue[] = [];
    for (const environmentId of environments.success) {
      const opened = yield* Effect.result(
        environmentKeysFor({ client, verified, environmentId, recipient }),
      );
      if (Result.isFailure(opened)) {
        issues.push({ kind: "unchecked", environmentId, message: opened.failure.message });
        continue;
      }
      const epochs = missingEpochsOf(opened.success);
      if (epochs.length > 0) {
        issues.push({ kind: "missing", environmentId, epochs });
      }
    }
    return issues;
  });
}

/** 合図の後の確認の報告(完了の文の後に — 鍵の到達を確かめて欠け → 失効 → 未登録の順。K12-3)。 */
function reportConfirmation(
  confirmation: ChainConfirmation,
  keys: MasterKeys,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    for (const project of confirmation.registered) {
      const issues = yield* checkKeyReach({ ...project.standing, keys });
      for (const issue of issues) {
        yield* reportKeyReachIssue(project.projectId, issue);
      }
    }
    if (confirmation.revoked.length > 0) {
      // 承認は起きていない(登録簿の行が残った失効端末 — DK K12-6)。承認側の筋書きでなく、
      // このチェーンに載った失効の事実と足し直しの手順を言う
      yield* logNote(
        `this key was revoked on ${confirmation.revoked.map(displayText).join(", ")}, so it is not registered there again. To put this machine back there, ${reAddDeviceRoute("this machine")}${confirmation.registered.length > 0 ? `. This keychain then no longer holds this key, so revoke it on ${confirmation.registered.map((project) => displayText(project.projectId)).join(", ")}, where it is still registered (\`maruhi device revoke ${keys.fingerprintHex}\` from a registered device)` : ""}`,
      );
    }
    if (confirmation.missing.length > 0) {
      // 合図(登録簿の行)は承認側がプロジェクトのループの後に置くので、ここに来た時点で
      // 承認側の作業は終わっており、要求は取り消し済み(K4-31)。不足分を登録するのは
      // 「cap がそこを覆う端末」が**そのプロジェクトを対象に**打つ鍵付きコマンド(`device-sync.ts`
      // — 前段は 1 コマンド 1 プロジェクト: DK K10-5。cap 起因の skip は承認側の再同期では
      // 直らない: K6-V 補 2 / K7-2)。承認は失敗を `failed` に畳むので、一部成功の合図の後には
      // failed のプロジェクトも混じる(K7-15)。失効したプロジェクトはここに入れない(K12-6)
      yield* logNote(
        `not registered yet on ${confirmation.missing.map(displayText).join(", ")} — the approving device skipped or failed on them (its output says which, and why: its cap does not cover them, you are not a member there, or the append failed there), or you approved with --project. The request is used up. A device of yours whose cap covers them registers this key on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance) — the approving device itself if its cap was not the cause, another device otherwise, once it has synced a project that did register this key. \`maruhi device list\` shows where this key is registered`,
      );
    }
  });
}

/** 鍵の到達の確認の 1 件(欠けは pull と同じ警告の文言 — K12-3。確認の失敗は Note)。 */
function reportKeyReachIssue(
  projectId: string,
  issue: KeyReachIssue,
): Effect.Effect<void, never, CliIo> {
  const project = displayText(projectId);
  if (issue.kind === "missing") {
    return logWarning(
      `${project}: environment ${displayText(issue.environmentId)}: ${describeMissingOwnEpochs(projectId, issue.environmentId, issue.epochs)}`,
    );
  }
  return logNote(
    issue.environmentId === null
      ? `${project}: could not list its environments to check that their keys reached this device (${issue.message}); \`maruhi pull --project ${project} --env <environment>\` on this machine reports any missing epochs`
      : `${project}: could not check that the keys of environment ${displayText(issue.environmentId)} reached this device (${issue.message}); \`${gapFillCommandOf(projectId, issue.environmentId)}\` on this machine reports any missing epochs`,
  );
}

/**
 * 要求に使う鍵: 無ければ生成、あれば「同じ鍵の要求がある(待機の再開 — K4-5)」か
 * 「pre-DK の複製・失効した端末(`--replace` で作り直す — K4-18 / DK K12-5)」かを分ける。
 */
function deviceKeyForRequest(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly replace: boolean;
}): Effect.Effect<MasterKeys, CliError, CliServices> {
  return Effect.gen(function* () {
    const keychain = yield* Keychain;
    const entryName = masterKeyEntryName(input.session.origin, input.session.userId);
    const existing = yield* keychain.get(entryName);
    if (existing !== null && !input.replace) {
      const keys = yield* loadMasterKeys(input.session);
      const pending = yield* input.client.devices
        .requestGet({ params: { fp: keys.fingerprintHex } })
        .pipe(
          Effect.map(() => true),
          Effect.catchTag("DeviceNotFound", () => Effect.succeed(false)),
          Effect.mapError(toCliError),
        );
      const registered = yield* fetchRegistry(input.client).pipe(
        Effect.map(
          (rows) => rows?.some((row) => row.keyFingerprintHex === keys.fingerprintHex) === true,
        ),
      );
      if (pending) {
        yield* logNote(
          `this machine already has device key ${keys.fingerprintHex} with a device-add request — resuming the wait for its approval`,
        );
        return keys;
      }
      if (registered) {
        yield* logNote(
          `this machine already has device key ${keys.fingerprintHex} and it is in your device registry — verifying it on each project's chain`,
        );
        return keys;
      }
      return yield* Effect.fail(
        cliError(
          `This machine already has a device key (${keys.fingerprintHex}) with no pending device-add request, and it is not in your device registry. If this device was revoked, or its key is a copy of another device's key from an install before device keys, re-run with --replace: it removes this key from this keychain and generates a new one, whose fingerprint you then approve from a registered device (a revoked key is never registered again; the device a copy came from keeps its key). Do not pass --replace if this is your only device — recover from the ledger with \`maruhi key recover\` instead if you ever need to`,
        ),
      );
    }
    if (existing !== null) {
      yield* keychain.remove(entryName);
      yield* logNote("removed the previous key from this machine's keychain (--replace)");
    }
    const record = yield* generateKeyRecord();
    const validated = yield* importMasterKeys(record).pipe(
      Effect.mapError(() =>
        cliError(
          "Could not load the generated device key back (nothing was stored in the keychain). Report this as a maruhi bug",
        ),
      ),
    );
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Generated this device's key",
      fingerprintHex: validated.fingerprintHex,
    });
    return validated;
  });
}

/** 要求の作成の結果: 待機中の要求(期限つき)か、登録簿に既に載っている鍵か。 */
type RequestState =
  | { readonly kind: "pending"; readonly expiresAtMs: number }
  | { readonly kind: "already-registered" };

/** 要求の作成(409 は再開 — request-exists / device-registered)。 */
function createOrResumeRequest(
  input: { readonly client: MaruhiClient; readonly label: string },
  keys: MasterKeys,
): Effect.Effect<RequestState, CliError> {
  return input.client.devices
    .requestCreate({
      payload: {
        encPubHex: keys.record.encPubHex,
        sigPubHex: keys.record.sigPubHex,
        label: input.label,
      },
    })
    .pipe(
      Effect.map((response): RequestState => ({
        kind: "pending",
        expiresAtMs: response.expiresAtMs,
      })),
      Effect.catch((error) =>
        Effect.gen(function* () {
          if (error instanceof DeviceRegistryConflictError) {
            const conflict: DeviceRegistryConflictError = error;
            if (conflict.reason === "device-registered") {
              // 登録簿に既に自分の行がある = 合図は立っている(要求行は無い)
              return { kind: "already-registered" } satisfies RequestState;
            }
            // 同じ鍵の要求が生きている = 待機の再開(K4-5 第 2 巡)。照会の失敗は
            // 握り潰さず伝える(「失効した」と誤って案内しない — 409 は生存の証)
            const request = yield* input.client.devices
              .requestGet({ params: { fp: keys.fingerprintHex } })
              .pipe(Effect.mapError(toCliError));
            return { kind: "pending", expiresAtMs: request.expiresAtMs } satisfies RequestState;
          }
          if (error instanceof DeviceRegistryLimitError) {
            const limit: DeviceRegistryLimitError = error;
            return yield* Effect.fail(
              cliError(
                limit.reason === "add-requests"
                  ? `Too many device-add requests in the last hour (limit ${limit.limit}). Wait${limit.retryAfterSeconds === undefined ? "" : ` about ${Math.ceil(limit.retryAfterSeconds / 60)} minutes`} and re-run`
                  : `Your device registry is full (${limit.limit} rows). On a registered device, remove old rows with \`maruhi device list\` / \`maruhi device revoke\`, then re-run`,
              ),
            );
          }
          return yield* Effect.fail(toCliError(error));
        }),
      ),
    );
}

/**
 * 登録簿に自分の FP の行が現れるまで待つ(TTL まで)。true = 現れた。
 * `hintAfterMs` があれば、要求の作成(= 期限 − TTL)からその時間が経った最初の巡で
 * 1 度だけ「承認側の出力を確認せよ」を出す(K7-3 — 合図が無いという事実だけを言い、
 * 原因は承認側の画面に委ねる)。
 */
function waitForRegistryRow(input: {
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
  readonly expiresAtMs: number;
  readonly intervalMs: number;
  readonly hintAfterMs: number | null;
}): Effect.Effect<boolean, never, CliIo> {
  return Effect.gen(function* () {
    let hinted = false;
    for (;;) {
      const rows = yield* fetchRegistry(input.client);
      if (rows?.some((row) => row.keyFingerprintHex === input.fingerprintHex) === true) {
        return true;
      }
      if (Date.now() >= input.expiresAtMs) {
        return false;
      }
      const requestedAtMs = input.expiresAtMs - DEVICE_ADD_REQUEST_TTL_MS;
      if (
        !hinted &&
        input.hintAfterMs !== null &&
        Date.now() - requestedAtMs >= input.hintAfterMs
      ) {
        hinted = true;
        yield* logNote(
          `still waiting (${Math.round((Date.now() - requestedAtMs) / 60_000)} minutes since the request): this key is not in your device registry yet. If \`maruhi device approve\` already ran on the approving device and failed on every project, or could not list this device in your device registry, the cause is in its output and this request stays valid until ${formatUtcMinutes(input.expiresAtMs)} — fix it there and re-run it. Otherwise nothing is needed here`,
        );
      }
      yield* Effect.sleep(Duration.millis(input.intervalMs));
    }
  });
}

// ---------------------------------------------------------------------------
// device approve
// ---------------------------------------------------------------------------

/** `<fp-or-words>` の解釈(K4-6: hex 32 文字の全長、または 12 語。接頭辞は受けない)。 */
export type ApproveRef =
  | { readonly kind: "hex"; readonly fingerprintHex: string }
  | { readonly kind: "words"; readonly words: readonly string[] };

export function parseApproveRef(raw: string): Effect.Effect<ApproveRef, CliError> {
  const trimmed = raw.trim().toLowerCase();
  if (FULL_FINGERPRINT.test(trimmed)) {
    return Effect.succeed({ kind: "hex", fingerprintHex: trimmed });
  }
  const words = trimmed.split(/[\s,]+/).filter((word) => word.length > 0);
  if (words.length === WORD_COUNT && words.every((word) => /^[a-z]+$/.test(word))) {
    return Effect.succeed({ kind: "words", words });
  }
  return Effect.fail(
    usageError(
      "The device reference must be the full 32-character fingerprint or its 12 words (separated by spaces or commas) as shown by `maruhi device add` — fingerprints are never truncated for approval",
    ),
  );
}

/** 要求 1 行(承認候補 — FP は再計算済み)。 */
interface ApprovableRequest {
  readonly fingerprintHex: string;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly expiresAtMs: number;
}

/** 要求一覧から人の運んだ参照に一致する行を選ぶ(応答の FP は使わず再計算する)。 */
function matchRequest(
  client: MaruhiClient,
  ref: ApproveRef,
): Effect.Effect<ApprovableRequest, CliError, CliIo> {
  return Effect.gen(function* () {
    const { requests } = yield* client.devices.requestList({}).pipe(Effect.mapError(toCliError));
    const matches: ApprovableRequest[] = [];
    for (const row of requests) {
      const fingerprintHex = yield* recomputeFingerprint(row.encPubHex, row.sigPubHex);
      if (fingerprintHex === null) {
        continue;
      }
      if (fingerprintHex !== row.keyFingerprintHex) {
        yield* logWarning(
          `a device-add request claims fingerprint ${row.keyFingerprintHex} but its public keys compute to ${fingerprintHex} — ignored (the server's row does not match its own keys)`,
        );
        continue;
      }
      const hit =
        ref.kind === "hex"
          ? fingerprintHex === ref.fingerprintHex
          : (yield* fingerprintWords(fingerprintHex, "The key fingerprint is malformed")).join(
              " ",
            ) === ref.words.join(" ");
      if (hit) {
        matches.push({
          fingerprintHex,
          encPubHex: row.encPubHex,
          sigPubHex: row.sigPubHex,
          label: row.label,
          expiresAtMs: row.expiresAtMs,
        });
      }
    }
    const match = matches[0];
    if (match === undefined) {
      return yield* Effect.fail(
        cliError(
          "No pending device-add request matches that fingerprint. Requests expire 15 minutes after `maruhi device add`; re-run it on the new device and compare the fingerprint it prints (full hex or the 12 words) with what you typed",
        ),
      );
    }
    if (matches.length > 1) {
      // 同じ鍵の要求が複数(サーバーは FP で一意にするはず)。どれかを黙って選んで
      // チェーン権限を与えるより、止めて示す
      return yield* Effect.fail(
        cliError(
          `${countNoun(matches.length, "pending device-add request")} carry the same key fingerprint ${match.fingerprintHex} (labels: ${matches.map((item) => displayText(item.label)).join(", ")}). The server should hold at most one request per fingerprint, so refusing to pick one. Wait for them to expire (15 minutes), re-run \`maruhi device add\` on the new device and approve the single new request`,
        ),
      );
    }
    return match;
  });
}

/** 1 プロジェクトでの承認の結果。 */
export interface ProjectApproveOutcome {
  readonly projectId: string;
  readonly state: "registered" | "already" | "skipped" | "failed";
  readonly backfill: DeviceBackfillOutcome | null;
  readonly message: string | null;
}

/** `maruhi device approve <fp|words> [--cap <role>] [--env …|--all-envs|--no-envs] [--project]`。 */
export function deviceApproveOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly ref: ApproveRef;
  readonly cap: DeviceCap;
  readonly project: string | undefined;
}): Effect.Effect<readonly ProjectApproveOutcome[], CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    // 儀式ゲートは要求一覧の取得より前(K4-6 反例 3)
    yield* ensureDeviceApproveAllowed;
    const request = yield* matchRequest(input.client, input.ref);
    const masterKeys = yield* loadMasterKeys(input.session);
    if (request.fingerprintHex === masterKeys.fingerprintHex) {
      return yield* Effect.fail(
        cliError("That request carries this machine's own key; approve it from another device"),
      );
    }
    const words = yield* fingerprintWords(
      request.fingerprintHex,
      "The key fingerprint is malformed",
    );
    yield* io.log(
      `Approving device ${request.fingerprintHex} (label "${displayText(request.label)}", cap ${describeCap(input.cap)})`,
    );
    yield* io.log(`fp words: ${formatWordList(words)}`);
    // FP の出所の規律(K7-7 — docs `devices.mdx` と同じ主張): 要求を置けるのは
    // `ensureKeyMaterialAccess`(`*` × admin のトークン)なので、盗んだトークンで要求を
    // 置き FP を送って承認させる経路は、yes ではなく「追加する機械の画面から読む」で止まる
    yield* io.log(
      "Compare them with the screen of the machine you are adding, never with a fingerprint sent to you: a request can be placed by anyone holding an account-wide admin API token of yours, and approving it adds their key to your projects",
    );
    const projectIds = yield* resolveProjectIds(input.client, input.project);
    // 2 相(DK K10-4): 先に全プロジェクトを開いて決着と「既に載っている cap」を集め、
    // cap の食い違いがあれば**どこにも追記せずに**止まる(追記しながら判定すると、
    // 未登録のプロジェクトへ今回の cap で足した後で気づく)。開いた文脈は第 2 相で使う
    const plans: ProjectApprovePlan[] = [];
    for (const projectId of projectIds) {
      plans.push(
        yield* planApproveOnProject({
          session: input.session,
          projectId,
          request,
          cap: input.cap,
          masterKeys,
        }),
      );
    }
    yield* refuseCapMismatch({ plans, request, cap: input.cap, project: input.project });
    const outcomes: ProjectApproveOutcome[] = [];
    for (const plan of plans) {
      outcomes.push(
        plan.kind === "settled"
          ? plan.outcome
          : yield* appendOnProject({
              session: input.session,
              plan,
              request,
              cap: input.cap,
              masterKeys,
            }),
      );
    }
    // どのプロジェクトにも載らなかった(全部 failed / skipped)なら、後段(記録・登録簿・
    // 要求の取消)を行わない: 記録すると初回同期が同じ失敗を繰り返し、登録簿の行は
    // 要求側に偽の合図を送り、要求の取消は再実行の材料を消す(Bugbot 指摘)
    if (!outcomes.some((item) => item.state === "registered" || item.state === "already")) {
      yield* logWarning(
        "the device was not registered on any project, so nothing was recorded and the request was left in place. Fix the cause reported above and re-run `maruhi device approve` with the same fingerprint (the request stays valid until it expires)",
      );
      return outcomes;
    }
    // ローカル記録(approved — K4-3 の書き手 (2))。承認者の端末 FP を出所として残す
    const store = yield* OwnDeviceStore;
    const entry: OwnDeviceEntry = {
      keyFingerprintHex: request.fingerprintHex,
      encPubHex: request.encPubHex,
      sigPubHex: request.sigPubHex,
      roleCap: input.cap.roleCap,
      scope: input.cap.scope,
      source: "approved",
      label: request.label,
      addedByFingerprintHex: masterKeys.fingerprintHex,
      observedProjectId: null,
      recordedAtMs: Date.now(),
      revokedAtMs: null,
    };
    yield* store.record(input.session.origin, input.session.userId, entry);
    // 登録簿へ PUT(合図 — 最後に行う)。成否は値で取り出し、取消の条件にする(DK K9-1):
    // 合図を出せなかったのに要求を消すと、承認側の再実行が要求を見つけられず、合図を
    // 出し直す手が無くなる。失敗の種類は問わない(K9-2 — 種類は文言だけが見る)
    const listed = yield* Effect.result(
      input.client.devices.register({
        params: { fp: request.fingerprintHex },
        payload: {
          encPubHex: request.encPubHex,
          sigPubHex: request.sigPubHex,
          label: request.label,
        },
      }),
    );
    if (Result.isFailure(listed)) {
      // 要求は残す(期限まで)。再実行は全プロジェクト already(失敗していた分は再試行)→
      // PUT → 取消で収束する。期限を過ぎると登録簿の行を書く経路が無い(K9-3 の T3)
      const retry = `The request is left in place until ${formatUtcMinutes(request.expiresAtMs)}:`;
      // 打ち直しは同じ cap で(K10-1 — 違う cap は拒否される。フラグなしの再実行は既定の
      // owner / all になるので、コマンドをそのまま出す)
      const rerun = approveCommandOf(request.fingerprintHex, input.cap, input.project);
      const afterwards =
        "After that the device stays registered on the chains above but unlisted in your device registry";
      yield* logNote(
        listed.failure instanceof DeviceRegistryLimitError
          ? `the device registry is full (${MAX_DEVICE_REGISTRY_ROWS_PER_USER} rows), so the new device was not listed there and \`maruhi device add\` on it will not see the completion signal. ${retry} remove old rows (\`maruhi device list\`, then \`maruhi device revoke\`) and re-run \`${rerun}\` before then to list it. ${afterwards}`
          : `could not update the device registry (${toCliError(listed.failure).message}); the device is registered on the chains above regardless, but \`maruhi device add\` on it will not see the completion signal. ${retry} re-run \`${rerun}\` before then to list it. ${afterwards}`,
      );
      return outcomes;
    }
    yield* input.client.devices.requestCancel({ params: { fp: request.fingerprintHex } }).pipe(
      Effect.asVoid,
      Effect.catch(() => Effect.void),
    );
    return outcomes;
  });
}

/**
 * 第 1 相の結果(DK K10-4): 決着済み(skipped / already / failed)か、第 2 相で追記する
 * プロジェクトの文脈か。`chainCap` はこの鍵がこのチェーンに既に載っていればその cap
 * (署名する端末の有無と関係なくチェーンの事実 — K10-2 第 3 巡)。
 */
type ProjectApprovePlan =
  | {
      readonly kind: "settled";
      readonly outcome: ProjectApproveOutcome;
      readonly chainCap: DeviceCap | null;
    }
  | {
      readonly kind: "append";
      readonly projectId: string;
      readonly context: ProjectContext;
      readonly chainCap: null;
    };

/** 1 プロジェクトを開いて決着を判定する(失敗は結果に畳む — 1 つの失敗で止めない)。 */
function planApproveOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectApprovePlan, never, CliServices> {
  const settled = (
    state: ProjectApproveOutcome["state"],
    message: string | null,
    chainCap: DeviceCap | null = null,
  ): ProjectApprovePlan => ({
    kind: "settled",
    outcome: { projectId: input.projectId, state, backfill: null, message },
    chainCap,
  });
  return Effect.gen(function* () {
    const context = yield* openProject({ server: input.session.origin, project: input.projectId });
    const self = context.verified.state.members.get(input.session.userId);
    if (self === undefined) {
      return settled("skipped", "you are not a member of this project");
    }
    const present = self.devices.get(input.request.fingerprintHex);
    const chainCap: DeviceCap | null =
      present === undefined ? null : { roleCap: present.roleCap, scope: present.scope };
    const signer = findOwnDevice(self, { keyFingerprintHex: input.masterKeys.fingerprintHex });
    if (signer === undefined) {
      // 要求なしに承認し直す経路は無い(登録済みの鍵は要求を作り直せない — DK K10-5)。
      // 登録するのは、このプロジェクトに載っている自分の端末の同期(`device-sync.ts` の
      // 観測 → 登録)で、前段はこのプロジェクトを対象にした鍵付きコマンドだけが開く
      return settled(
        "skipped",
        `this machine's key is not one of your registered devices here, so it cannot register devices here. A device of yours that is registered here adds the new device (and this machine) when it runs a keyed command on this project at a terminal (\`maruhi pull --project ${displayText(input.projectId)}\`, for instance), if its cap covers them and it has synced a project that has them`,
        chainCap,
      );
    }
    if (present !== undefined) {
      return settled("already", null, chainCap);
    }
    // 通信前判定(K4-3 反例 3 / 4): 単調性と `listed` の環境の存在
    if (!capWithinSignerCap(input.cap, signer)) {
      return settled(
        "skipped",
        `the requested cap ${describeCap(input.cap)} exceeds this device's own cap ${describeCap(signer)} (a device may only register devices bounded by its own cap — CRYPTO_SPEC §6.2); approve from a device with a wider cap`,
      );
    }
    yield* requireScopeEnvironmentsExist(context.verified, input.cap.scope);
    return { kind: "append", projectId: input.projectId, context, chainCap: null } as const;
  }).pipe(Effect.catch((error) => Effect.succeed(settled("failed", error.message))));
}

/** cap の一致(role と scope — scope は集合として比べる)。 */
function sameCap(a: DeviceCap, b: DeviceCap): boolean {
  return a.roleCap === b.roleCap && sameScope(a.scope, b.scope);
}

/**
 * `device approve` を同じ cap で打ち直すコマンド(DK K10-1)。フラグの字面は help golden
 * (`--cap` / `--env` / `--all-envs` / `--no-envs` / `--project`)から写す。
 */
function approveCommandOf(
  fingerprintHex: string,
  cap: DeviceCap,
  project: string | undefined,
): string {
  const scope =
    cap.scope.kind === "all"
      ? ["--all-envs"]
      : cap.scope.environmentIds.length === 0
        ? ["--no-envs"]
        : cap.scope.environmentIds.map((id) => `--env ${displayText(id)}`);
  const target = project === undefined ? [] : [`--project ${displayText(project)}`];
  return ["maruhi device approve", fingerprintHex, "--cap", cap.roleCap, ...scope, ...target].join(
    " ",
  );
}

/**
 * 再実行の cap の規律(DK K10-1 / K10-2): 訪れるプロジェクトのどれかのチェーンにこの鍵が
 * 既に載っていて、その cap が今回の cap と違えば、何も追記・記録せず要求を残して止まる。
 * 端末の cap は最初の承認で決まり変えられないので、再実行(PUT の失敗後・中断後)は最初の
 * 承認の続きでしかない。比べる相手はチェーン(真実)だけで、ローカル記録は読まない(K4-5)。
 */
function refuseCapMismatch(input: {
  readonly plans: readonly ProjectApprovePlan[];
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly project: string | undefined;
}): Effect.Effect<void, CliError> {
  const present = input.plans.flatMap((plan) =>
    plan.chainCap === null ? [] : [{ projectId: plan.outcome.projectId, cap: plan.chainCap }],
  );
  if (present.every((item) => sameCap(item.cap, input.cap))) {
    return Effect.void;
  }
  const listed = present
    .map((item) => `${describeCap(item.cap)} on ${displayText(item.projectId)}`)
    .join(", ");
  const distinct = present.filter(
    (item, index) => present.findIndex((other) => sameCap(other.cap, item.cap)) === index,
  );
  const only = distinct.length === 1 ? distinct[0] : undefined;
  const rerun =
    only === undefined
      ? "Its cap differs between those projects, so re-run it once per project with `--project <id>` and the cap shown for that project."
      : `Re-run it with that cap: \`${approveCommandOf(input.request.fingerprintHex, only.cap, input.project)}\`.`;
  return Effect.fail(
    cliError(
      `Device ${input.request.fingerprintHex} is already registered with cap ${listed}, and this approval asks for ${describeCap(input.cap)}: a device's cap is set when it is first approved and cannot be changed later, so this approval appended nothing, recorded nothing and left the request in place. ${rerun} To give the device another cap, revoke it, then ${reAddDeviceRoute("that machine")} with the cap you want`,
    ),
  );
}

/** 第 2 相: 第 1 相で開いた文脈で `add_device` + バックフィル(失敗は結果に畳む)。 */
function appendOnProject(input: {
  readonly session: CliSession;
  readonly plan: Extract<ProjectApprovePlan, { readonly kind: "append" }>;
  readonly request: ApprovableRequest;
  readonly cap: DeviceCap;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectApproveOutcome, never, CliServices> {
  const { context, projectId } = input.plan;
  const outcome = (
    state: ProjectApproveOutcome["state"],
    message: string | null,
    backfill: DeviceBackfillOutcome | null = null,
  ): ProjectApproveOutcome => ({ projectId, state, backfill, message });
  return Effect.gen(function* () {
    const appended = yield* appendAddDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.masterKeys.sigKeyPair },
      candidate: {
        encPubHex: input.request.encPubHex,
        sigPubHex: input.request.sigPubHex,
        cap: input.cap,
      },
    });
    const verified = yield* context.resync;
    const current = verified.state.members.get(input.session.userId);
    const targetDevice = current?.devices.get(input.request.fingerprintHex);
    if (current === undefined || targetDevice === undefined) {
      return yield* Effect.fail(
        cliError(
          "The resync after add_device was accepted does not show the device on the chain (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
    const backfill = yield* backfillToDevice({
      client: context.client,
      verified,
      recipient: context.recipient,
      targetMember: current,
      targetDevice,
      signerUserId: input.session.userId,
      signingKeyPair: input.masterKeys.sigKeyPair,
    });
    return outcome(appended.appended ? "registered" : "already", null, backfill);
  }).pipe(Effect.catch((error) => Effect.succeed(outcome("failed", error.message))));
}

/** 承認結果の報告(effect-cli が呼ぶ)。 */
export function reportApproveOutcomes(
  outcomes: readonly ProjectApproveOutcome[],
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    // どこにも載らなかった(全部 skipped / failed — 記録も要求の取消も行っていない)
    // 承認は失敗として終える(skipped だけでも 0 にしない)
    let exitCode = outcomes.some((item) => item.state === "registered" || item.state === "already")
      ? 0
      : 1;
    for (const item of outcomes) {
      if ((yield* reportApproveOutcome(item)) !== 0) {
        exitCode = 1;
      }
    }
    return exitCode;
  });
}

/** バックフィルの要約(括弧書き。null = バックフィルなし)。 */
export function describeBackfill(backfill: DeviceBackfillOutcome | null): string {
  return backfill === null
    ? ""
    : ` (backfilled ${countNoun(backfill.registered, "DEK wrap")}, ${backfill.alreadyRegistered} already present, ${countNoun(backfill.environments, "environment")})`;
}

/** 1 プロジェクトの承認結果(終了コード: バックフィル失敗・失敗は 1)。 */
function reportApproveOutcome(item: ProjectApproveOutcome): Effect.Effect<number, never, CliIo> {
  const label = displayText(item.projectId);
  switch (item.state) {
    case "registered":
    case "already":
      return reportRegisteredDevice({
        label,
        action:
          item.state === "registered"
            ? "registered the device"
            : "the device was already registered",
        backfill: item.backfill,
        // `already` はバックフィルしないので、承認の再実行は欠けを補わない(DK K11 — 補うのは
        // 兄弟端末の pull。K10-12 の cap の拒否にも当たらない)
        rerun: (environmentId) => describeGapFillRoute(item.projectId, environmentId),
      });
    case "skipped":
      return logNote(`${label}: skipped — ${item.message ?? ""}`).pipe(Effect.as(0));
    case "failed":
      return logWarning(`${label}: failed — ${item.message ?? ""}`).pipe(Effect.as(1));
  }
}

/** 登録(済み)行 + バックフィル失敗の警告(承認と復元で共有 — 失敗があれば 1)。 */
export function reportRegisteredDevice(input: {
  readonly label: string;
  readonly action: string;
  readonly backfill: DeviceBackfillOutcome | null;
  /** 失敗した環境を補う経路の案内(DK K11-5 — 字面は device-gaps.ts が作る)。 */
  readonly rerun: (environmentId: string) => string;
}): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(`${input.label}: ${input.action}${describeBackfill(input.backfill)}`);
    const failed = input.backfill?.failed ?? [];
    for (const failure of failed) {
      yield* logWarning(
        `${input.label}: backfill of environment ${displayText(failure.environmentId)} failed (${failure.message}). ${input.rerun(failure.environmentId)}`,
      );
    }
    return failed.length > 0 ? 1 : 0;
  });
}

// ---------------------------------------------------------------------------
// device list
// ---------------------------------------------------------------------------

/** 表示行の材料: FP → チェーン上の出現(プロジェクトごとの 1 行)。 */
type ListRows = Map<string, { readonly projectId: string; readonly line: string }[]>;

/** 各プロジェクトのチェーンから自分の端末を集める(同期できないプロジェクトは Note)。 */
function collectChainRows(input: {
  readonly session: CliSession;
  readonly projectIds: readonly string[];
}): Effect.Effect<ListRows, never, CliServices> {
  return Effect.gen(function* () {
    const rows: ListRows = new Map();
    for (const projectId of input.projectIds) {
      const context = yield* openMetadataProject({
        server: input.session.origin,
        project: projectId,
      }).pipe(Effect.catch(() => Effect.succeed<ProjectContextBase | null>(null)));
      if (context === null) {
        yield* logNote(
          `${displayText(projectId)}: could not sync this project; its devices are not shown`,
        );
        continue;
      }
      const self = context.verified.state.members.get(input.session.userId);
      for (const device of self === undefined ? [] : devicesOf(self)) {
        const provenance = deviceProvenanceOf(context.verified, input.session.userId, device);
        const adder =
          provenance.addedByFingerprintHex === null
            ? "first key"
            : `added by ${provenance.addedByFingerprintHex}${provenance.adderStillActive ? "" : " (that device is now revoked)"}`;
        const lines = rows.get(device.keyFingerprintHex) ?? [];
        lines.push({
          projectId,
          line: `${displayText(projectId)}: cap=${describeCap(device)} seq=${device.addedSeq} ${adder}`,
        });
        rows.set(device.keyFingerprintHex, lines);
      }
    }
    return rows;
  });
}

/** 1 端末の見出し(登録簿の表示名・トークン id は server-reported、ローカル記録は出所)。 */
function describeListRow(input: {
  readonly fingerprintHex: string;
  readonly ownFingerprintHex: string | null;
  readonly registryRow: RegistryRow | undefined;
  readonly record: OwnDeviceEntry | undefined;
}): string {
  const tags: string[] = [];
  if (input.ownFingerprintHex === input.fingerprintHex) {
    tags.push("this machine");
  }
  if (input.registryRow !== undefined) {
    tags.push(`label "${displayText(input.registryRow.label)}" (server-reported)`);
    if (input.registryRow.tokenId !== undefined) {
      tags.push(`token ${displayText(input.registryRow.tokenId)} (server-reported)`);
    }
  }
  if (input.record !== undefined) {
    tags.push(
      input.record.revokedAtMs === null
        ? `recorded here as ${input.record.source}`
        : "recorded here as revoked",
    );
  }
  return `${input.fingerprintHex}${tags.length === 0 ? "" : `\t${tags.join(", ")}`}`;
}

/** `maruhi device list [--project]`(値ゼロ・鍵不要・ゲートなし)。 */
export function deviceListOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly project: string | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* OwnDeviceStore;
    const registry = yield* fetchRegistry(input.client);
    const lookup = yield* store.load(input.session.origin, input.session.userId);
    const local = lookup.state === "loaded" ? lookup.devices : [];
    const projectIds = yield* resolveProjectIds(input.client, input.project);
    const localKeys = yield* Effect.catch(loadMasterKeys(input.session), () =>
      Effect.succeed<MasterKeys | null>(null),
    );
    // FP → 表示行(チェーンが真実。登録簿とローカル記録は注記として並べる)
    const rows = yield* collectChainRows({ session: input.session, projectIds });
    const active = local.filter((entry) => entry.revokedAtMs === null);
    const fingerprints = [
      ...new Set([
        ...rows.keys(),
        ...(registry ?? []).map((row) => row.keyFingerprintHex),
        ...active.map((entry) => entry.keyFingerprintHex),
      ]),
    ].toSorted(compareCodePoints);
    if (fingerprints.length === 0) {
      yield* io.log(
        "No devices found (no project chain lists a device of yours, and the registry is empty)",
      );
      return;
    }
    if (registry === null) {
      yield* logNote(
        "the device registry could not be read (labels are server-reported and advisory anyway)",
      );
    }
    for (const fingerprintHex of fingerprints) {
      yield* io.log(
        describeListRow({
          fingerprintHex,
          ownFingerprintHex: localKeys?.fingerprintHex ?? null,
          registryRow: registry?.find((row) => row.keyFingerprintHex === fingerprintHex),
          record: local.find((entry) => entry.keyFingerprintHex === fingerprintHex),
        }),
      );
      yield* printChainLines(rows.get(fingerprintHex) ?? []);
    }
  });
}

/** 1 端末のチェーン上の出現(無ければその旨)。 */
function printChainLines(
  lines: readonly { readonly line: string }[],
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (lines.length === 0) {
      yield* io.log("  (not on any synced project chain)");
    }
    for (const project of lines) {
      yield* io.log(`  ${project.line}`);
    }
  });
}

// ---------------------------------------------------------------------------
// device revoke
// ---------------------------------------------------------------------------

/** 参照の解釈(K4-7: FP の接頭辞 8 文字以上、または登録簿の表示名 — 自分のみ)。 */
function resolveRevokeRefs(input: {
  readonly refs: readonly string[];
  readonly registry: readonly RegistryRow[] | null;
  readonly self: boolean;
}): Effect.Effect<readonly RevokeRef[], CliError> {
  return Effect.gen(function* () {
    const resolved: RevokeRef[] = [];
    for (const ref of input.refs) {
      const lowered = ref.trim().toLowerCase();
      if (FINGERPRINT_PREFIX.test(lowered)) {
        resolved.push({ ref, prefix: lowered, viaLabel: false });
        continue;
      }
      if (!input.self) {
        return yield* Effect.fail(
          usageError(
            `"${displayText(ref)}" is not a fingerprint prefix (at least 8 hex characters). Another member's devices are named by fingerprint only (see \`maruhi member list\`)`,
          ),
        );
      }
      const byLabel = (input.registry ?? []).filter((row) => row.label === ref.trim());
      if (byLabel.length !== 1) {
        return yield* Effect.fail(
          usageError(
            byLabel.length === 0
              ? `"${displayText(ref)}" matches neither a fingerprint prefix (at least 8 hex characters) nor a label in your device registry (\`maruhi device list\`)`
              : `label "${displayText(ref)}" names ${byLabel.length} registry rows; use the fingerprint instead`,
          ),
        );
      }
      resolved.push({ ref, prefix: byLabel[0]!.keyFingerprintHex, viaLabel: true });
    }
    return resolved;
  });
}

/** 1 プロジェクトの失効計画(確認表の 1 段)。 */
interface ProjectRevokePlan {
  readonly context: ProjectContext;
  readonly target: ChainMember;
  readonly revoking: readonly ChainDevice[];
  readonly remaining: readonly ChainDevice[];
  readonly warnings: readonly string[];
}

/** 1 プロジェクトでの失効結果(effect-cli が報告する)。 */
export interface ProjectRevokeOutcome {
  readonly projectId: string;
  readonly revoked: readonly string[];
  readonly sweep: DeviceSweepOutcome | null;
  readonly skipped: string | null;
  /** `revoke_device` の追記が失敗した(何も失効していない)。 */
  readonly failed: string | null;
  /** 追記は受理されたが、受理後の再同期か sweep が失敗した(失効は載っている)。 */
  readonly sweepFailed: string | null;
}

/** `device revoke` 全体の結果。 */
export interface DeviceRevokeSummary {
  readonly projects: readonly ProjectRevokeOutcome[];
  /** 提案したが失効していないトークン(名前・期限 — K4-13)。 */
  readonly tokenProposal: readonly string[];
}

/** 参照の解決結果(表示名経由かどうかを確認表に載せる)。 */
type RevokeRef = { readonly ref: string; readonly prefix: string; readonly viaLabel: boolean };

/** 確認表(K4-7): プロジェクトごとの失効 FP(全長)と残る端末、導いた警告。 */
function printRevokePlans(input: {
  readonly targetUserId: string;
  readonly plans: readonly ProjectRevokePlan[];
  readonly refs: readonly RevokeRef[];
}): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* io.log(`Revoking devices of ${displayText(input.targetUserId)}:`);
    for (const plan of input.plans) {
      yield* io.log(`  ${displayText(plan.context.projectId)}:`);
      for (const device of plan.revoking) {
        const via = input.refs.find((ref) => device.keyFingerprintHex.startsWith(ref.prefix));
        yield* io.log(
          `    revoke  ${device.keyFingerprintHex} (cap ${describeCap(device)})${via?.viaLabel === true ? ` — matched registry label "${displayText(via.ref)}"; check the fingerprint against \`maruhi device list\`` : ""}`,
        );
      }
      yield* io.log(`    remain  ${plan.remaining.map(describeDevice).join(", ")}`);
      for (const warning of plan.warnings) {
        yield* io.log(`    warning ${warning}`);
      }
    }
  });
}

/** 自分の端末を失効させた後始末: ローカル記録に revoked、登録簿の行を削除(advisory)。 */
function finishOwnRevocation(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly revoked: readonly string[];
}): Effect.Effect<void, CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    // ローカル記録に revoked(再登録を防ぐ — K4-3 反例 1)
    yield* store.markRevoked(input.session.origin, input.session.userId, input.revoked, Date.now());
    for (const fp of input.revoked) {
      yield* input.client.devices.remove({ params: { fp } }).pipe(
        Effect.asVoid,
        Effect.catch(() => Effect.void),
      );
    }
  });
}

/** `maruhi device revoke <ref…> [--user] [--project] [--yes] [--revoke-token]`。 */
export function deviceRevokeOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly refs: readonly string[];
  readonly user: string | undefined;
  readonly project: string | undefined;
  readonly yes: boolean;
  readonly revokeToken: boolean;
}): Effect.Effect<DeviceRevokeSummary, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const targetUserId = input.user ?? input.session.userId;
    const self = targetUserId === input.session.userId;
    const masterKeys = yield* loadMasterKeys(input.session);
    const { registry, refs, reserveFps } = yield* prepareRevokeRefs({
      session: input.session,
      client: input.client,
      refs: input.refs,
      self,
    });
    const projectIds = yield* resolveProjectIds(input.client, input.project);
    const { plans, outcomes } = yield* planRevokeAll({
      session: input.session,
      projectIds,
      targetUserId,
      refs,
      reserveFps,
      ownFingerprintHex: masterKeys.fingerprintHex,
    });
    if (plans.length === 0) {
      yield* io.log("Nothing to revoke: no synced project lists a matching active device");
    } else {
      yield* printRevokePlans({ targetUserId, plans, refs });
    }
    for (const outcome of outcomes) {
      yield* logNote(`${displayText(outcome.projectId)}: ${outcome.skipped ?? ""}`);
    }
    if (plans.length === 0) {
      return { projects: outcomes, tokenProposal: [] };
    }
    yield* confirmRevoke(input.yes);
    const revoked = yield* executeRevokeAll({
      session: input.session,
      plans,
      targetUserId,
      masterKeys,
      outcomes,
    });
    if (!self) {
      return { projects: outcomes, tokenProposal: [] };
    }
    if (revoked.length > 0) {
      yield* finishOwnRevocation({ session: input.session, client: input.client, revoked });
    }
    const tokenProposal = yield* proposeTokenRevocation({
      client: input.client,
      registry,
      revoked,
      revokeToken: input.revokeToken,
      interactive: !input.yes,
    });
    return { projects: outcomes, tokenProposal };
  });
}

/** 参照の解決に要る材料(自分の端末なら登録簿と予備鍵の記録、他人なら FP だけ)。 */
function prepareRevokeRefs(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly refs: readonly string[];
  readonly self: boolean;
}): Effect.Effect<
  {
    readonly registry: readonly RegistryRow[] | null;
    readonly refs: readonly RevokeRef[];
    readonly reserveFps: ReadonlySet<string>;
  },
  CliError,
  OwnDeviceStore
> {
  return Effect.gen(function* () {
    const registry = input.self ? yield* fetchRegistry(input.client) : null;
    const refs = yield* resolveRevokeRefs({ refs: input.refs, registry, self: input.self });
    const reserveFps = input.self
      ? yield* recordedReserveFingerprints(input.session)
      : new Set<string>();
    return { registry, refs, reserveFps };
  });
}

/** 各プロジェクトで失効を実行し、結果を積む。戻り値 = 失効した FP の和集合。 */
function executeRevokeAll(input: {
  readonly session: CliSession;
  readonly plans: readonly ProjectRevokePlan[];
  readonly targetUserId: string;
  readonly masterKeys: MasterKeys;
  readonly outcomes: ProjectRevokeOutcome[];
}): Effect.Effect<readonly string[], never, CliServices> {
  return Effect.gen(function* () {
    const revokedAll = new Set<string>();
    for (const plan of input.plans) {
      const outcome = yield* executeRevoke({
        session: input.session,
        plan,
        targetUserId: input.targetUserId,
        masterKeys: input.masterKeys,
      });
      for (const fp of outcome.revoked) {
        revokedAll.add(fp);
      }
      input.outcomes.push(outcome);
    }
    return [...revokedAll];
  });
}

/** 各プロジェクトの失効計画(飛ばしたプロジェクトは結果に skipped として先に積む)。 */
function planRevokeAll(input: {
  readonly session: CliSession;
  readonly projectIds: readonly string[];
  readonly targetUserId: string;
  readonly refs: readonly RevokeRef[];
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): Effect.Effect<
  { readonly plans: ProjectRevokePlan[]; readonly outcomes: ProjectRevokeOutcome[] },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const plans: ProjectRevokePlan[] = [];
    const outcomes: ProjectRevokeOutcome[] = [];
    for (const projectId of input.projectIds) {
      const planned = yield* planRevoke({ ...input, projectId });
      if (typeof planned === "string") {
        outcomes.push({
          projectId,
          revoked: [],
          sweep: null,
          skipped: planned,
          failed: null,
          sweepFailed: null,
        });
      } else {
        plans.push(planned);
      }
    }
    return { plans, outcomes };
  });
}

/** yes の確認(`--yes` で省略 — 失効は儀式ではない。K4-7)。 */
function confirmRevoke(yes: boolean): Effect.Effect<void, CliError, CliIo> {
  if (yes) {
    return Effect.void;
  }
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const answer = yield* io.promptLine({ prompt: "Type yes to revoke: " });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(cliError("Cancelled: nothing was revoked"));
    }
  });
}

/** ローカル記録の予備鍵(失効していないもの)の FP 集合(確認表の警告材料 — K4-7)。 */
function recordedReserveFingerprints(
  session: CliSession,
): Effect.Effect<ReadonlySet<string>, CliError, OwnDeviceStore> {
  return Effect.gen(function* () {
    const store = yield* OwnDeviceStore;
    const lookup = yield* store.load(session.origin, session.userId);
    return new Set(
      (lookup.state === "loaded" ? lookup.devices : [])
        .filter((entry) => entry.source === "reserve" && entry.revokedAtMs === null)
        .map((entry) => entry.keyFingerprintHex),
    );
  });
}

/** 参照に一致する現端末(接頭辞は一意でなければ usage エラー)。 */
function matchRevokeTargets(input: {
  readonly projectId: string;
  readonly devices: readonly ChainDevice[];
  readonly refs: readonly { readonly prefix: string }[];
}): Effect.Effect<readonly ChainDevice[], CliError> {
  return Effect.gen(function* () {
    const revoking: ChainDevice[] = [];
    for (const ref of input.refs) {
      const hits = input.devices.filter((device) =>
        device.keyFingerprintHex.startsWith(ref.prefix),
      );
      if (hits.length > 1) {
        return yield* Effect.fail(
          usageError(
            `fingerprint prefix ${ref.prefix} matches ${hits.length} devices on ${displayText(input.projectId)}; use a longer prefix`,
          ),
        );
      }
      const hit = hits[0];
      if (hit !== undefined && !revoking.includes(hit)) {
        revoking.push(hit);
      }
    }
    return revoking;
  });
}

/** 残る端末の cap から導く警告(K4-7 / K4-8 / §2-bis)。 */
function revokeWarnings(input: {
  readonly verified: VerifiedProject;
  readonly target: ChainMember;
  readonly remaining: readonly ChainDevice[];
  readonly revokingFps: ReadonlySet<string>;
  readonly self: boolean;
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): readonly string[] {
  const { target, remaining } = input;
  const warnings: string[] = [];
  if (
    target.role === "owner" &&
    remaining.every((device) => ROLE_RANK[device.roleCap] < ROLE_RANK.owner)
  ) {
    warnings.push(
      "no remaining device carries an owner cap — the owner could no longer act as owner (approve proposals, change roles) from any device until a device without the cap is added",
    );
  }
  const uncovered = uncoveredEnvironments(input.verified, target, remaining);
  if (uncovered.length > 0) {
    warnings.push(
      `no remaining device's cap covers ${uncovered.map(displayText).join(", ")} — the person keeps those environments in scope but no device could open them`,
    );
  }
  if (input.self && !remaining.some((device) => input.reserveFps.has(device.keyFingerprintHex))) {
    warnings.push(
      "no remaining device is recorded as your reserve key on this machine — if the reserve key is among the revoked ones, create a new one afterwards with `maruhi key recovery --replace`",
    );
  }
  if (input.revokingFps.has(input.ownFingerprintHex)) {
    warnings.push(
      "this revokes the device you are running on: after the entry lands this machine can no longer sign here, and the rotation sweep cannot be fulfilled from it (another of your devices, or a member whose scope covers the environments, must rotate)",
    );
  }
  if (ROLE_RANK[target.role] < ROLE_RANK.member) {
    warnings.push(
      "the person is a reader, so the rotation the revocation mandates cannot be run by them — a member whose scope covers the environments converges it",
    );
  }
  return warnings;
}

/** 確認表の材料を 1 プロジェクトぶん組み立てる(string = 飛ばす理由)。 */
function planRevoke(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly targetUserId: string;
  readonly refs: readonly { readonly prefix: string }[];
  readonly reserveFps: ReadonlySet<string>;
  readonly ownFingerprintHex: string;
}): Effect.Effect<ProjectRevokePlan | string, CliError, CliServices> {
  return Effect.gen(function* () {
    const context = yield* openProject({ server: input.session.origin, project: input.projectId });
    const target = context.verified.state.members.get(input.targetUserId);
    if (target === undefined) {
      return `${displayText(input.targetUserId)} is not a member of this project`;
    }
    const self = context.verified.state.members.get(input.session.userId);
    if (
      self === undefined ||
      findOwnDevice(self, { keyFingerprintHex: input.ownFingerprintHex }) === undefined
    ) {
      return "this machine's key is not one of your registered devices here (revoke from a device that is)";
    }
    const devices = devicesOf(target);
    const revoking = yield* matchRevokeTargets({
      projectId: input.projectId,
      devices,
      refs: input.refs,
    });
    if (revoking.length === 0) {
      return "no active device matches the reference (already revoked, or never registered here)";
    }
    const revokingFps = new Set(revoking.map((device) => device.keyFingerprintHex));
    const remaining = devices.filter((device) => !revokingFps.has(device.keyFingerprintHex));
    if (remaining.length === 0) {
      return "it would revoke the last device (last-device-protected — CRYPTO_SPEC §6.2). To remove the person, use `maruhi member remove`";
    }
    const warnings = revokeWarnings({
      verified: context.verified,
      target,
      remaining,
      revokingFps,
      self: input.targetUserId === input.session.userId,
      reserveFps: input.reserveFps,
      ownFingerprintHex: input.ownFingerprintHex,
    });
    return { context, target, revoking, remaining, warnings };
  });
}

/** 対象の scope 内で、残る端末のどれも実効 scope に含まない環境(K4-7 の警告材料)。 */
function uncoveredEnvironments(
  verified: VerifiedProject,
  target: ChainMember,
  remaining: readonly ChainDevice[],
): readonly string[] {
  const covered = remaining.map((device) => effectivePermissionOf(target, device).scope);
  return [...verified.state.environments.keys()]
    .filter(
      (environmentId) =>
        scopeIncludesEnvironment(target.scope, environmentId) &&
        !covered.some((scope: MemberScope) => scopeIncludesEnvironment(scope, environmentId)),
    )
    .toSorted(compareCodePoints);
}

/** 1 プロジェクトで `revoke_device` → sweep(失敗は結果に畳む)。 */
function executeRevoke(input: {
  readonly session: CliSession;
  readonly plan: ProjectRevokePlan;
  readonly targetUserId: string;
  readonly masterKeys: MasterKeys;
}): Effect.Effect<ProjectRevokeOutcome, never, CliServices> {
  const { context } = input.plan;
  const base = {
    projectId: context.projectId,
    revoked: [] as readonly string[],
    sweep: null,
    skipped: null,
    failed: null,
    sweepFailed: null,
  } satisfies ProjectRevokeOutcome;
  return Effect.gen(function* () {
    const appended = yield* appendRevokeDevice({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      signer: { userId: input.session.userId, signingKeyPair: input.masterKeys.sigKeyPair },
      targetUserId: input.targetUserId,
      fingerprintsHex: input.plan.revoking.map((device) => device.keyFingerprintHex),
    });
    const { revoked } = appended;
    // 追記の受理後は失効が載っている: 再同期・sweep の失敗は「失効の失敗」に畳まず、
    // 失効は残したまま sweep の失敗として報告する(ローカル記録・登録簿の後段を飛ばさない)
    return yield* sweepAfterRevoke({ ...input, appended }).pipe(
      Effect.map((sweep) => ({ ...base, revoked, sweep })),
      Effect.catch((error) =>
        Effect.succeed({
          ...base,
          revoked,
          sweepFailed: error.message,
        } satisfies ProjectRevokeOutcome),
      ),
    );
  }).pipe(Effect.catch((error) => Effect.succeed({ ...base, failed: error.message })));
}

/** 受理後の再同期と sweep(失敗はそのまま返す — 呼び出し側が sweepFailed に畳む)。 */
function sweepAfterRevoke(input: {
  readonly session: CliSession;
  readonly plan: ProjectRevokePlan;
  readonly targetUserId: string;
  readonly masterKeys: MasterKeys;
  readonly appended: { readonly verified: VerifiedProject; readonly revoked: readonly string[] };
}): Effect.Effect<DeviceSweepOutcome | null, CliError, CliServices> {
  const { context } = input.plan;
  return Effect.gen(function* () {
    // 受理後の再同期(追記前のビューには失効の義務が無い — sweep は掲載を確認した
    // ビューで導出する。member remove と同じ規律: サーバー申告を真実源にしない)
    const verified =
      input.appended.revoked.length === 0
        ? input.appended.verified
        : yield* resyncExtended(context.resync, input.appended.verified);
    const self = verified.state.members.get(input.session.userId);
    const actorDevice =
      self === undefined
        ? undefined
        : findOwnDevice(self, { keyFingerprintHex: input.masterKeys.fingerprintHex });
    // 自分の端末自身を失効させた場合、sweep はこの端末では履行できない(K4-7 反例 5)
    return actorDevice === undefined
      ? null
      : yield* sweepAfterDeviceRevoke({
          client: context.client,
          verified,
          targetUserId: input.targetUserId,
          actorUserId: input.session.userId,
          actorDevice,
          rotate: sweepRotateFor({ ...context, verified }, DEVICE_REVOKED_ROTATION_REASON),
        });
  });
}

/**
 * トークン失効の提案(K4-13): 候補 = 登録簿の `tokenId`、無ければ名前 `cli:<label>`。
 * `--revoke-token` なら失効、対話なら yes を聞き、非対話(`--yes`)では提案だけ返す。
 * 一覧が 403(admin でないトークン)なら事実だけ伝える。
 */
function proposeTokenRevocation(input: {
  readonly client: MaruhiClient;
  readonly registry: readonly RegistryRow[] | null;
  readonly revoked: readonly string[];
  readonly revokeToken: boolean;
  readonly interactive: boolean;
}): Effect.Effect<readonly string[], CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.revoked.length === 0) {
      return [];
    }
    const listed = yield* input.client.auth.listTokens({}).pipe(
      Effect.map((response) => response.tokens),
      Effect.catch((error) =>
        error instanceof ForbiddenError ? Effect.succeed(null) : Effect.fail(toCliError(error)),
      ),
    );
    if (listed === null) {
      yield* logNote(
        "revoking a device does not revoke its API token (AUTH_SPEC §6). This token cannot list tokens; revoke the lost device's token from the web dashboard or with an admin token (`maruhi token revoke <id>`)",
      );
      return [];
    }
    const rows = (input.registry ?? []).filter((row) =>
      input.revoked.includes(row.keyFingerprintHex),
    );
    const candidates = listed.filter((token) =>
      rows.some((row) =>
        row.tokenId === undefined ? token.name === `cli:${row.label}` : row.tokenId === token.id,
      ),
    );
    if (candidates.length === 0) {
      yield* logNote(
        "revoking a device does not revoke its API token (AUTH_SPEC §6). No token could be matched to the revoked devices (the registry row carries no token id and no token is named after its label) — check `maruhi token list`",
      );
      return [];
    }
    const describe = describeToken;
    yield* io.log(
      `The revoked devices' API tokens are still valid (the match is server-reported): ${candidates.map(describe).join("; ")}`,
    );
    let revoke = input.revokeToken;
    if (!revoke && input.interactive) {
      const answer = yield* io.promptLine({ prompt: "Revoke these tokens too? Type yes: " });
      revoke = answer.trim().toLowerCase() === "yes";
    }
    if (!revoke) {
      yield* logNote(
        "tokens were left as they are — revoke them later with `maruhi token revoke <id>` (pass --revoke-token to do it in the same run)",
      );
      return candidates.map(describe);
    }
    for (const token of candidates) {
      yield* input.client.auth.revokeTokenById({ params: { tokenId: token.id } }).pipe(
        Effect.asVoid,
        Effect.catch((error) =>
          error instanceof TokenNotFoundError ? Effect.void : Effect.fail(toCliError(error)),
        ),
      );
      yield* io.log(`Revoked token ${describe(token)}`);
    }
    return [];
  });
}

/** トークン候補の 1 行(id・名前・期限 — K4-13 の提案表示)。 */
function describeToken(token: {
  readonly id: string;
  readonly name: string;
  readonly expiresAtMs: number | null;
}): string {
  return `${displayText(token.id)} (${displayText(token.name)}, expires ${token.expiresAtMs === null ? "never" : formatUtcMinutes(token.expiresAtMs)})`;
}

/** cap の組み立て(`--cap <role>` + scope フラグ)。 */
export function parseCapRole(raw: string | undefined): Effect.Effect<Role, CliError> {
  if (raw === undefined) {
    return Effect.succeed("owner");
  }
  const roles: readonly Role[] = ["owner", "admin", "member", "reader"];
  const role = roles.find((candidate) => candidate === raw);
  return role === undefined
    ? Effect.fail(usageError(`--cap must be one of ${roles.join(", ")}`))
    : Effect.succeed(role);
}
