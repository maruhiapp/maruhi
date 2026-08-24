// 暗号化 + 値署名 + メタステートメント付き push(AUTH_SPEC §12-5 =
// CRYPTO_SPEC §4.1 / §4.2。session-14 裁定 G の PR-3 拡張)。
//
// - 名前 → variableId の解決は**検証済みステートメント経由が必須**(§4.2 /
//   §12-7 — session-14 まで「非認証」と記録していた既知制約を閉じる)。
//   解決は**メタデータのみ pull**(§12-7 — 値・DEK を運ばず var.read が記録
//   されない。session-11 裁定 3)で行い、既存変数への push のみ値付き pull で
//   検証済み最新値と同梱 DEK を取得する(listMine との二重取得はしない)。
//   ルックアップキーは NFC 正規化してから byte-exact で照合する(§12-1)。
//   同名 active の重複は検証側(values.ts)が拒否する
// - 新規作成: `VariableMetaStatement`(metaVersion 1・active・prev 空)を自分の
//   鍵で著者署名して version 1 の値と同梱する(§12-5)。名前は署名前に NFC
//   正規化する(正規化の実施主体はクライアント — §4.2)
// - 通常 push: 既存変数でも pull で取得した最新値を §6.3 で全検証し、自前で
//   再構築した signed-bytes hash を prev にする(サーバー申告のハッシュに連鎖
//   署名しない)。version = 検証済み latest + 1、宣言ヘッド = 最後に検証した
//   チェーンヘッド、DEK は現エポックのコミットメント検証済み・nonce は fresh、
//   署名は自分の user id + master sig 鍵
// - 409 VersionConflict: currentVersion 番号だけで次 version / prev を決めない。
//   bulk pull を再取得 → winner 特定(既存変数は stable id、create の
//   duplicate-name race は現行 name の再解決)→ winner を値署名検証 → 自計算
//   hash を prev → fresh nonce で再暗号・再署名。pull が 409 より古ければ
//   不整合拒否、新しければ実 winner を採用。欠落・同一 version で異なる
//   signed bytes(equivocation の証拠)は拒否。上限 5 回。
//   **メタ側も同型の巻き戻し・fork 検査**(検証済み latest metaVersion からの
//   後退拒否・同一 metaVersion の signed bytes 相違 = equivocation 拒否)を
//   winner 採用時に行う。409 MetaVersionConflict(並行 rename との競合)は
//   名前から解決し直す(値と同型: 再取得 → 検証 → 再署名。再暗号化なし)
// - 409 EpochConflict: 延長検査付き再同期(サーバーの currentEpoch 申告を
//   真実源にしない)→ chain-derived epoch とコミットメント検証済み DEK で
//   再暗号・新ヘッドで再署名。prev は検証済み predecessor hash を維持
// - 値は stdin から読み、argv に載せない。平文はメモリ上のみ

import {
  EpochConflictError,
  ManifestVersionConflictError,
  MetaVersionConflictError,
  type RecipientDek,
  VariableConflictError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import {
  computeValueSignedBytesHash,
  encodeHex,
  encryptVariable,
  signValue,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { type FloorHandle, rejectIntentOnServerRejection } from "./floor-check.ts";
import type { ManifestFloor, VariableFloor } from "./floor.ts";
import { type ManifestDigestEntry, signNextManifest } from "./manifest.ts";
import { signCreateStatement } from "./meta-statement.ts";
import { retryOnConflict } from "./retry.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";
import {
  pullVerifiedEnvironment,
  pullVerifiedEnvironmentMetadata,
  type VerifiedPulledValue,
} from "./values.ts";

const MAX_ATTEMPTS = 5;

/** stdin の値: 末尾の改行 1 つ(LF / CRLF)は落とす(`echo` 由来の混入対策)。 */
export function normalizeStdinValue(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0 && bytes[bytes.length - 1] === 0x0a) {
    const end = bytes.length > 1 && bytes[bytes.length - 2] === 0x0d ? -2 : -1;
    return bytes.slice(0, end);
  }
  return bytes;
}

/** Result of an accepted push. */
export interface PushedVersion {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
  /** 検証中に収集した SHOULD 警告(非 NFC 名の配布等 — 呼び出し側が表示)。 */
  readonly warnings: readonly string[];
}

/** クライアント採番の変数 ID(§12-1 形式)。名前とは独立な乱数 ID にする:
 * 表示名の変更・削除済み ID の再利用禁止(tombstone)と衝突しないため。 */
function generateVariableId(): string {
  return `v${encodeHex(crypto.getRandomValues(new Uint8Array(12)))}`;
}

interface PushTarget {
  readonly variableId: string;
  readonly create: boolean;
  /** 検証済みの現行最新値(create = 新規変数なら null)。prev と equivocation 検査の基準。 */
  readonly latest: VerifiedPulledValue | null;
}

function nextVersionOf(target: PushTarget): number {
  return target.latest === null ? 1 : target.latest.version + 1;
}

function prevHashOf(target: PushTarget): string {
  return target.latest === null ? "" : target.latest.signedBytesHashHex;
}

/**
 * 変数作成の同梱マニフェスト(§12-5)の発行材料(検証済みメタデータ pull 由来)。
 * 既存変数への push はマニフェストを発行しない(発行契機の限定 — §4.3)ため null。
 */
interface ManifestIssueBase {
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  };
  /** 現在のメタ集合(tombstone 込み)— 新変数のエントリは試行ごとに足す。 */
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
}

interface ResolvedTarget {
  readonly target: PushTarget;
  /** pull 検証で前進していることがあるビュー(future head の有界再同期)。 */
  readonly verified: VerifiedProject;
  readonly warnings: readonly string[];
  /**
   * 既存変数の解決で行った値付き pull の同梱 DEK(create 解決では null)。
   * verified と同じビューで検証・開封する前提の生ワイヤ形(§12-7 — listMine
   * との二重取得の解消: session-11 裁定 3)。
   */
  readonly deks: readonly RecipientDek[] | null;
  /** 作成経路のみ: 同梱マニフェストの発行材料(既存変数への push は null)。 */
  readonly issueBase: ManifestIssueBase | null;
}

/**
 * 表示名から push 先を解決する。解決はメタデータのみ pull(§12-7 — 値・DEK を
 * 運ばず、サーバーは var.read を記録しない)の検証済みステートメントに対する
 * byte-exact 比較で行う(ルックアップキーは呼び出し側で NFC 正規化済み —
 * §12-1。同名 active の重複は検証側が拒否済み)。
 *
 * 既存変数だった場合のみ値付き pull を行う: prev 連鎖(§4.1)は検証済み最新値の
 * signed-bytes ハッシュを要し、これは暗号文込みの取得なしに自計算できない
 * (var.read はこの取得に対して正しく記録される)。新規作成は値を一切読まない
 * (prev は空・version 1)ため var.read が記録されない — 「読んでいないものを
 * 読んだと記録しない」の CLI 側(session-11 裁定 3)。
 */
function resolveTarget(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** ローカル床(§6.3 — 解決に使う検証済み pull にも床検査〔+ 値付きは床コミット〕が掛かる)。 */
  readonly floor: FloorHandle;
}): Effect.Effect<ResolvedTarget, CliError> {
  return Effect.gen(function* () {
    const metadata = yield* pullVerifiedEnvironmentMetadata(input);
    // 同名 active の重複は検証側が拒否済みだが、push 先の同定が応答の並び順に
    // 依存しない防衛線として残す(§4.2 の解決拒否)
    const matches = metadata.variables.filter((variable) => variable.name === input.name);
    if (matches.length > 1) {
      return yield* Effect.fail(
        cliError(
          `Multiple active statements with the same name passed verification (server equivocation): ${input.name}. Refusing to resolve the push target`,
        ),
      );
    }
    const existing = matches[0];
    if (existing === undefined) {
      return {
        target: { variableId: generateVariableId(), create: true, latest: null },
        verified: metadata.verified,
        warnings: metadata.warnings,
        deks: null,
        // 作成の同梱マニフェスト(§12-5)の材料: 検証済みメタデータ pull の
        // 直前マニフェスト・現在の集合(tombstone 込み)・環境メタの最新形
        issueBase: {
          previous: {
            manifestVersion: metadata.manifest.manifestVersion,
            signedBytesHashHex: metadata.manifest.signedBytesHashHex,
          },
          entries: [
            ...metadata.variables.map((statement) => ({
              variableId: statement.variableId,
              status: "active" as const,
              metaVersion: statement.metaVersion,
              metaSigHashHex: statement.metaSigHashHex,
            })),
            ...metadata.tombstones.map((tombstone) => ({
              variableId: tombstone.variableId,
              status: "deleted" as const,
              metaVersion: tombstone.metaVersion,
              metaSigHashHex: tombstone.metaSigHashHex,
            })),
          ],
          envMeta: {
            metaVersion: metadata.environment.metaVersion,
            sigHashHex: metadata.environment.metaSigHashHex,
          },
        },
      };
    }
    const pulled = yield* pullVerifiedEnvironment({ ...input, verified: metadata.verified });
    const latest = pulled.variables.find((variable) => variable.variableId === existing.variableId);
    if (latest === undefined) {
      // 解決と値取得の間の並行削除、または応答間の不整合(欠落は床検査でも
      // 変数単位の証拠になる)。誤った prev で作成へ倒さず明示エラーにする
      return yield* Effect.fail(
        cliError(
          `The resolved variable ${existing.variableId} (${input.name}) is missing from the value-carrying pull (a concurrent deletion by another member, or an inconsistent server response). Re-run the command`,
        ),
      );
    }
    if (latest.name !== input.name) {
      // 解決と値取得の間の並行 rename。入力した名前と別の名前へ変わった変数に
      // push を向けない(単一応答で解決していた旧フローのスナップショット整合の
      // 回復 — PR #41 レビュー指摘)。latest.name は検証済みステートメントの
      // name(§12-2)なので byte-exact 比較で足りる
      return yield* Effect.fail(
        cliError(
          `The resolved variable ${existing.variableId} was renamed from ${displayText(input.name)} to ${displayText(latest.name)} before the value fetch (a concurrent rename by another member). Re-run the command`,
        ),
      );
    }
    return {
      target: { variableId: existing.variableId, create: false, latest },
      verified: pulled.verified,
      warnings: [...metadata.warnings, ...pulled.warnings],
      deks: pulled.deks,
      // 既存変数への push はメタ状態を変えない = マニフェストを発行しない(§4.3)
      issueBase: null,
    };
  });
}

/**
 * 暗号化(fresh nonce)+ §4.1 の値署名。宣言ヘッドは検証済みビューの現ヘッド。
 *
 * ローテーションの再暗号化(env-rotate.ts)も同じ実装を通す: 再暗号化は
 * 「実行者が writer として署名する通常 push」(§7 / §4.1)であり、署名対象の
 * 組み立てが 2 実装に割れると片方だけが規律を失う。
 */
export function encryptAndSignPayload(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
}) {
  const context = {
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
  };
  return Effect.gen(function* () {
    const encrypted = yield* Effect.tryPromise({
      // 剥がす理由: 暗号化の入力(平文 → 暗号文)。産物は暗号文なので、
      // 剥がした平文はこの呼び出しの外へ出ない
      try: () =>
        encryptVariable({
          dek: Redacted.value(input.dek),
          context,
          plaintext: Redacted.value(input.value),
        }),
      catch: () => cliError("Failed to encrypt the value"),
    });
    if (!encrypted.ok) {
      return yield* Effect.fail(cliError("Failed to encrypt the value"));
    }
    const nonceHex = encodeHex(encrypted.value.nonce);
    const ciphertextHex = encodeHex(encrypted.value.ciphertext);
    const signatureContext = {
      suite: SUITE_ID,
      ...context,
      nonceHex,
      ciphertextHex,
      prevValueSigHashHex: input.prevValueSigHashHex,
      writerUserId: input.writerUserId,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
    } as const;
    const signature = yield* Effect.tryPromise({
      try: () => signValue({ context: signatureContext, signingKey: input.signingKey }),
      catch: () => cliError("Failed to create the value signature"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("Failed to create the value signature"));
    }
    // 自分の署名対象の signed bytes ハッシュ(受理されたらローカル床に昇格する
    // — サーバー申告ではなく自計算値。次 version の prev の根拠と同じ姿勢)
    const signedBytesHash = yield* Effect.tryPromise({
      try: () => computeValueSignedBytesHash(signatureContext),
      catch: () => cliError("Failed to compute the value-signature signed-bytes hash"),
    });
    if (!signedBytesHash.ok) {
      return yield* Effect.fail(
        cliError("Failed to compute the value-signature signed-bytes hash"),
      );
    }
    return {
      payload: {
        suite: SUITE_ID,
        aad: context,
        nonceHex,
        ciphertextHex,
        prevValueSigHashHex: input.prevValueSigHashHex,
        chainHeadHashHex: input.verified.state.headHashHex,
        chainHeadSeq: input.verified.state.headSeq,
        signatureHex: signature.value,
      },
      signedBytesHashHex: signedBytesHash.value,
    } as const;
  });
}

interface AcceptedPush {
  readonly accepted: {
    readonly variableId: string;
    readonly version: number;
    readonly epoch: number;
  };
  /** 受理された自分の書き込みの床レコード(自計算値 — サーバー echo でない)。 */
  readonly floorVariable: VariableFloor;
  /**
   * 作成経路のみ: 自分が発行したマニフェスト(自計算値)。**床へは直接昇格
   * しない** — メタ操作の成功は「検証可能な配布物での効果確認」(§12-10 (3))を
   * 通過して初めて成立し、床のマニフェスト前進は確認 pull の検証済み観測が担う。
   */
  readonly selfManifest: ManifestFloor | null;
  /** 作成経路のみ: 送信前に追記した intent(3-F)の id。効果確認が閉じる。 */
  readonly intentId: string | null;
  /** 受理時点の状態(床コミットのヘッド・変数 ID の源)。 */
  readonly state: PushState;
}

type PushConflict =
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict" }
  | { readonly kind: "variable-conflict" };

/** CAS 競合(§12-5)のリトライ可能な分類。それ以外は null(定的エラー)。 */
function classifyPushConflict(error: unknown): PushConflict | null {
  if (error instanceof VersionConflictError) {
    return { kind: "version-conflict", currentVersion: error.currentVersion };
  }
  if (error instanceof EpochConflictError) {
    return { kind: "epoch-conflict" };
  }
  if (
    error instanceof VariableConflictError ||
    error instanceof MetaVersionConflictError ||
    error instanceof ManifestVersionConflictError
  ) {
    // create の name 競合 / metaVersion 競合(並行作成・並行 rename)/
    // manifestVersion 競合(並行メタ操作 — §12-5 (6))は名前から解決し直す
    // (§12-5 の再試行 = 再取得 → 検証 → ステートメントとマニフェストの両方を
    // 再署名。ID 競合は乱数 ID の衝突で実質起こらない)
    return { kind: "variable-conflict" };
  }
  return null;
}

interface PushInput {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly verified: VerifiedProject;
  /** 再同期(チェーン全再検証)。呼び出し側は resyncExtended で延長検査を通す。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** 値署名の writer(自分の内部 user_id)と master sig 鍵(§4.1)。 */
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  /** ローカル床(§6.3 — 内部 pull の検査・コミットと、受理後の変数床前進)。 */
  readonly floor: FloorHandle;
}

interface PushState {
  readonly verified: VerifiedProject;
  readonly epoch: number;
  readonly deks: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly target: PushTarget;
  /** 作成経路のみ: 同梱マニフェストの発行材料(reresolveTarget が取り直す)。 */
  readonly issueBase: ManifestIssueBase | null;
  readonly warnings: readonly string[];
}

function initialState(input: PushInput): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget(input);
    const verified = resolved.verified;
    // 現エポック(チェーン導出値 — §6.2。環境未作成の push はここで止まる)と
    // DEK 集合は同じ検証済みビューから一括導出する(deks.ts の environmentKeysFor)。
    // DEK は 1 経路で 1 回だけ取得する(session-11 裁定 3 の二重取得解消):
    // 既存変数 = 値付き pull の同梱分(prefetched)を検証・開封 / 新規作成 = listMine
    const keys = yield* environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      prefetched: resolved.deks,
    });
    return {
      verified,
      epoch: keys.currentEpoch,
      deks: keys.deksByEpoch,
      target: resolved.target,
      issueBase: resolved.issueBase,
      warnings: resolved.warnings,
    };
  });
}

/** 1 試行(暗号化・署名・送信)。競合の分類は retryOnConflict の classify が担う。 */
function attemptOnce(input: PushInput, state: PushState): Effect.Effect<AcceptedPush, unknown> {
  return Effect.gen(function* () {
    const dek = state.deks.get(state.epoch);
    if (dek === undefined) {
      return yield* Effect.fail(
        cliError(
          `No DEK for the current epoch ${state.epoch} is registered for you (possibly awaiting a re-wrap after a rotation)`,
        ),
      );
    }
    const version = nextVersionOf(state.target);
    const signed = yield* encryptAndSignPayload({
      verified: state.verified,
      environmentId: input.environmentId,
      variableId: state.target.variableId,
      epoch: state.epoch,
      version,
      prevValueSigHashHex: prevHashOf(state.target),
      dek,
      value: input.value,
      writerUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    const valueFloor = {
      status: "active",
      version,
      epoch: state.epoch,
      valueSigHashHex: signed.signedBytesHashHex,
    } as const;
    const params = { projectId: state.verified.projectId, environmentId: input.environmentId };
    if (state.target.create) {
      // 作成 = version 1 の値 + metaVersion 1 のステートメント + 作成後の集合を
      // 反映したマニフェストの同梱(§12-5)。宣言ヘッドは値署名と同じ「最後に
      // 検証したチェーンヘッド」で、CAS リトライで検証ビューが進めば試行ごとに
      // 三つとも作り直される(meta-statement.ts / manifest.ts の共有実装)
      const issueBase = state.issueBase;
      if (issueBase === null) {
        return yield* Effect.fail(
          cliError(
            `Variable ${state.target.variableId} resolved as a creation without manifest material (internal inconsistency)`,
          ),
        );
      }
      const created = yield* signCreateStatement({
        verified: state.verified,
        environmentId: input.environmentId,
        target: { kind: "variable", variableId: state.target.variableId },
        name: input.name,
        authorUserId: input.writerUserId,
        signingKey: input.signingKey,
      });
      // 採番した variableId は乱数生成なので、検証済み集合に既に存在することは
      // ない。もし存在したら握り潰して digest から落とさず(サーバーの 422 に
      // 化けて原因が遠くなる)、内部不整合として明示的に失敗させる
      if (issueBase.entries.some((entry) => entry.variableId === state.target.variableId)) {
        return yield* Effect.fail(
          cliError(
            `Variable ${state.target.variableId} resolved as a creation but already exists in the verified statement set (internal inconsistency)`,
          ),
        );
      }
      const manifest = yield* signNextManifest({
        verified: state.verified,
        environmentId: input.environmentId,
        epoch: state.epoch,
        previous: issueBase.previous,
        entries: [
          ...issueBase.entries,
          {
            variableId: state.target.variableId,
            status: "active" as const,
            metaVersion: 1,
            metaSigHashHex: created.metaSigHashHex,
          },
        ],
        envMeta: issueBase.envMeta,
        issuerUserId: input.writerUserId,
        signingKey: input.signingKey,
        chainHead: {
          seq: state.verified.state.headSeq,
          hashHex: state.verified.state.headHashHex,
        },
      });
      // journal-before-send(3-F): security-critical mutation(メタ操作 —
      // §12-10)の送信前に intent を追記する。永続化に失敗したら送信しない
      // (fail-closed)。クラッシュ・応答消失で失われるのは「成功したという
      // 思い込み」ではなく「確認義務の記録」になる
      const intentId = yield* input.floor.appendIntent({
        op: "meta-op",
        environmentId: input.environmentId,
        epoch: state.epoch,
        dekCommitmentHex: null,
        variableId: state.target.variableId,
        manifestVersion: manifest.manifestVersion,
        manifestSigHashHex: manifest.manifestSigHashHex,
        declaredHead: {
          seq: state.verified.state.headSeq,
          hashHex: state.verified.state.headHashHex,
        },
      });
      const accepted = yield* input.client.variables
        .create({
          params,
          payload: {
            statement: created.statement,
            value: signed.payload,
            manifest: manifest.manifest,
          },
        })
        .pipe(
          // サーバー自身のエラー本文で拒否された = 効果は生じていない(確定)—
          // intent を閉じる(floor-check.ts の共有コールバック)
          Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)),
        );
      return {
        accepted,
        floorVariable: { ...valueFloor, metaVersion: 1, metaSigHashHex: created.metaSigHashHex },
        selfManifest: {
          manifestVersion: manifest.manifestVersion,
          epoch: manifest.epoch,
          manifestSigHashHex: manifest.manifestSigHashHex,
        },
        intentId,
        state,
      };
    }
    // 既存変数の push はメタを変更しない — 床のメタ記録は検証済み latest のまま
    const latest = state.target.latest;
    if (latest === null) {
      return yield* Effect.fail(
        cliError(
          `Variable ${state.target.variableId} has no verified latest value (internal inconsistency)`,
        ),
      );
    }
    // 既存変数への値 push は 1-E′ / 3-F の適用外(§12-10 (3) — 効果確認に使える
    // 配布物が値 pull しかなく、書き込み経路へ var.read 監査を持ち込むため)。
    // 成功は従来どおりサーバーの CAS + 値署名検証と自床の commitPush が担う
    const accepted = yield* input.client.variables.push({
      params: { ...params, variableId: state.target.variableId },
      payload: { value: signed.payload },
    });
    return {
      accepted,
      floorVariable: {
        ...valueFloor,
        metaVersion: latest.metaVersion,
        metaSigHashHex: latest.metaSignedBytesHashHex,
      },
      selfManifest: null,
      intentId: null,
      state,
    };
  });
}

/** エポックが変わった(または初出の)場合のみ DEK 集合を取り直す(cached の意味論)。 */
function refreshEpochState(
  input: PushInput,
  state: PushState,
  verified: VerifiedProject,
): Effect.Effect<Pick<PushState, "verified" | "epoch" | "deks">, CliError> {
  return Effect.map(
    environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      cached: state.deks,
    }),
    (keys) => ({ verified, epoch: keys.currentEpoch, deks: keys.deksByEpoch }),
  );
}

/**
 * 検証済み既知 latest(このセッションで §6.3 検証を通した値)に対する winner の
 * 後退・equivocation・連鎖の整合検査。正直サーバーでは latest_version は単調増加
 * (バージョン行の個別削除なし。変数削除は tombstone + 全行削除 = 以後 404)なので
 * 後退はすべて巻き戻し・equivocation の証拠であり、誤拒否はない。
 */
function winnerValueRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (currentVersion < known.version || winner.version < known.version) {
    // このセッションで検証済みの latest からの後退 = 巻き戻しの証拠。採用して
    // prev を付け替えると、巻き戻しブランチへ自分の署名で連鎖してしまう
    return `The 409 response / re-fetch for variable ${variableId} (version ${Math.min(currentVersion, winner.version)}) is older than the verified latest (version ${known.version}) — evidence of a version rollback`;
  }
  if (winner.version === known.version && winner.signedBytesHashHex !== known.signedBytesHashHex) {
    // 同一座標に内容の異なる 2 つの有効署名 = equivocation の暗号学的証拠
    return `Variable ${variableId} version ${winner.version} was served with signed bytes different from the verified value (evidence of server equivocation)`;
  }
  // エポック単調性(§4.1)は推移的なので、winner が検証済み latest より新しければ
  // 版番号のギャップに関わらず epoch 非減少を要求できる(レビューループ 2 [低] —
  // 版番号の選び方で隣接検査を迂回する旧エポック注入を塞ぐ)。正直サーバーは
  // 受理順にエポック非減少なので誤拒否はない
  if (winner.version > known.version && winner.epoch < known.epoch) {
    return `Variable ${variableId} version ${winner.version} has an epoch (${winner.epoch}) that regressed from the verified predecessor version's (${known.epoch}) — an epoch-monotonicity violation (§4.1)`;
  }
  // 隣接 predecessor を保持している場合は §6.3-6 の prev 実在一致も無償で検査できる
  // (レビューループ 1 [中] — pull の latest-only 制約の例外)
  if (
    winner.version === known.version + 1 &&
    winner.prevValueSigHashHex !== known.signedBytesHashHex
  ) {
    return `Variable ${variableId} version ${winner.version} has a prev that does not match the verified predecessor version's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

/**
 * メタ側の同型の巻き戻し・fork 検査(§12-5 のメタ再試行の規律。値の
 * winnerValueRegression の PR-3 拡張): 検証済み latest metaVersion からの後退と、
 * 同一 metaVersion の signed bytes 相違 = equivocation を拒否する。正直サーバー
 * では latest_meta_version も単調増加(ステートメント行の個別削除なし)のため
 * 誤拒否はない。
 */
function winnerMetaRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
): string | null {
  if (winner.metaVersion < known.metaVersion) {
    return `The re-fetched statement for variable ${variableId} (metaVersion ${winner.metaVersion}) is older than the verified latest (metaVersion ${known.metaVersion}) — evidence of a metadata rollback`;
  }
  if (
    winner.metaVersion === known.metaVersion &&
    winner.metaSignedBytesHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} was served with signed bytes different from the verified statement (evidence of server equivocation)`;
  }
  // 隣接 predecessor を保持している場合は prev 連鎖の一致も無償で検査できる
  // (winnerValueRegression の §6.3-6 検査の同型 — レビュー② [minor])
  if (
    winner.metaVersion === known.metaVersion + 1 &&
    winner.prevMetaSigHashHex !== known.metaSignedBytesHashHex
  ) {
    return `Variable ${variableId} metaVersion ${winner.metaVersion} has a prev that does not match the verified predecessor metaVersion's signed-bytes hash (chaining onto a diverged history — evidence of equivocation)`;
  }
  return null;
}

function winnerRegression(
  variableId: string,
  known: VerifiedPulledValue,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  return (
    winnerValueRegression(variableId, known, winner, currentVersion) ??
    winnerMetaRegression(variableId, known, winner)
  );
}

/**
 * 409 winner の整合検査(§12-5)。null = 採用可、非 null = 拒否理由。
 *
 * 検査は 2 層: (1) 応答間の整合(再取得の最新が「存在すると分かっている
 * version」より古い = サーバーの自己矛盾)、(2) 検証済み既知 latest からの
 * 後退・同一座標の signed bytes 相違・隣接 prev の不一致。**ローテーションの
 * 再暗号化(env-rotate.ts)も同じ検査を通す**: 勝者への prev 付け替えは push
 * 経路と同型であり、片方だけが分岐した履歴への連鎖署名を許すと、床(SHOULD・
 * 初回同期では不在)頼みの穴になる。
 *
 * `currentVersion` の出所は経路で異なる(push = 409 の申告、ローテーション =
 * 409 の申告または**自分が受理させた version**)ため、文言は「既知の最新」で
 * 統一する。
 */
export function winnerInconsistency(
  variableId: string,
  known: VerifiedPulledValue | null,
  winner: VerifiedPulledValue,
  currentVersion: number,
): string | null {
  if (winner.version < currentVersion) {
    // 409 が申告した最新より古い値しか配布されない = 応答間の不整合
    return `The re-fetched pull's latest version (${winner.version}) is older than the known latest version (${currentVersion}) — inconsistent (the server response contradicts itself)`;
  }
  return known === null ? null : winnerRegression(variableId, known, winner, currentVersion);
}

/**
 * 409 VersionConflict 後の winner 再取得(§12-5 の再試行手順): bulk pull を
 * 再取得し、stable id で winner を特定して検証し、その signed-bytes hash へ
 * prev を付け替える。409 応答に勝者のハッシュを要求しない。
 */
function adoptConflictWinner(
  input: PushInput,
  state: PushState,
  currentVersion: number,
): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: state.verified,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
    });
    const winner = pulled.variables.find(
      (variable) => variable.variableId === state.target.variableId,
    );
    if (winner === undefined) {
      return yield* Effect.fail(
        cliError(
          `The version-conflict winner (variable ${state.target.variableId}) is missing from the re-fetched pull (a concurrent deletion by another member, or an inconsistent server response)`,
        ),
      );
    }
    const inconsistency = winnerInconsistency(
      state.target.variableId,
      state.target.latest,
      winner,
      currentVersion,
    );
    if (inconsistency !== null) {
      return yield* Effect.fail(cliError(inconsistency));
    }
    const refreshed = yield* refreshEpochState(input, state, pulled.verified);
    return {
      ...refreshed,
      target: { ...state.target, create: false, latest: winner },
      // winner の採用 = 既存変数への push(メタ状態を変えない — マニフェスト非発行)
      issueBase: null,
      warnings: [...state.warnings, ...pulled.warnings],
    };
  });
}

function reresolveTarget(input: PushInput, state: PushState): Effect.Effect<PushState, CliError> {
  return Effect.gen(function* () {
    const resolved = yield* resolveTarget({ ...input, verified: state.verified });
    // 再解決の DEK は既知エポックの手持ちを優先し、エポックが進んだ時のみ
    // 取り直す(refreshEpochState)。resolved.deks は初回解決専用 — 競合
    // リトライの稀な経路で開封をやり直さない
    const refreshed = yield* refreshEpochState(input, state, resolved.verified);
    return {
      ...refreshed,
      target: resolved.target,
      issueBase: resolved.issueBase,
      warnings: [...state.warnings, ...resolved.warnings],
    };
  });
}

/**
 * 競合からの回復(§12-5 の再試行手順のドメイン固有部)。retryOnConflict の
 * recover として、最終試行後にも走る(定的エラー — equivocation の証拠・
 * サーバー応答とチェーンの矛盾 — の表面化)。
 */
function nextState(
  input: PushInput,
  state: PushState,
  outcome: PushConflict,
): Effect.Effect<PushState, CliError> {
  switch (outcome.kind) {
    case "version-conflict":
      // create 経路への VersionConflict は「並行作成された」を意味する
      // (自分の乱数 ID はサーバーに存在しない)ため、名前から解決し直す
      if (state.target.create) {
        return reresolveTarget(input, state);
      }
      return adoptConflictWinner(input, state, outcome.currentVersion);
    case "epoch-conflict":
      // エポックの真実源はチェーン(§6.3)。延長検査付きで再同期して導出値を
      // 使い、新エポックのコミットメント検証済み DEK を取得する。prev は
      // 検証済み predecessor hash のまま(値は変わっていない — 変わっていれば
      // 次の試行が VersionConflict になり上の手順へ入る)
      return Effect.gen(function* () {
        const verified = yield* resyncExtended(input.resync, state.verified);
        // 現エポックと DEK は同じ再同期ビューから一括導出(手持ちの検証済み
        // 集合に現エポックがあれば再取得しない — environmentKeysFor の cached)
        const keys = yield* environmentKeysFor({
          client: input.client,
          verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          cached: state.deks,
        });
        if (keys.currentEpoch === state.epoch) {
          // 再同期してもチェーン導出エポックが変わらないなら、サーバーの
          // EpochConflict 申告はチェーンと矛盾している(リトライで解けない)
          return yield* Effect.fail(
            cliError(
              `The server reported an epoch conflict, but the chain-derived current epoch is still ${keys.currentEpoch} (the server response contradicts the chain)`,
            ),
          );
        }
        return { ...state, verified, epoch: keys.currentEpoch, deks: keys.deksByEpoch };
      });
    case "variable-conflict":
      return reresolveTarget(input, state);
  }
}

/**
 * 変数作成(メタ操作)の効果確認(AUTH_SPEC §12-10 (3) — 1-E′): 成功 =
 * 「2xx を受け取った」ではなく「検証可能な配布物で効果を確認した」。確認材料は
 * metadata-only pull(var.read を記録しない経路)で、自己発行マニフェストの
 * (version, epoch, signed-bytes hash) と自分の変数 ID の存在を照合する。
 *
 * - 配布マニフェストが自己発行と完全一致 → 確認完了(床のマニフェスト前進は
 *   確認 pull の検証済み観測 — enforceMetadataFloor — が join 済み)
 * - 版が前進していても自分の variableId(乱数採番 — 他者は生成できない)が
 *   検証済み集合に存在 → 効果は確認済み(直後の並行メタ操作に追い越された形)
 * - マニフェスト欠落(旧サーバーの黙殺)・別マニフェスト(同版異ハッシュ)・
 *   variableId の不在 → 失敗。**床は自己発行マニフェストへ前進していない**
 *   (自分の思い込みを床に書かない — 記録されるのは検証済み観測のみ)
 */
function confirmVariableCreation(input: {
  readonly push: PushInput;
  readonly accepted: AcceptedPush;
  readonly selfManifest: ManifestFloor;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const variableId = input.accepted.state.target.variableId;
    const metadata = yield* pullVerifiedEnvironmentMetadata({
      client: input.push.client,
      verified: input.accepted.state.verified,
      environmentId: input.push.environmentId,
      resync: input.push.resync,
      floor: input.push.floor,
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `The variable creation was accepted (2xx), but the post-acceptance confirmation against the verified distribution failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}`,
        ),
      ),
    );
    const distributed = metadata.manifest;
    const resolve = (outcome: Parameters<FloorHandle["resolveIntent"]>[1]) =>
      input.accepted.intentId === null
        ? Effect.void
        : input.push.floor.resolveIntent(input.accepted.intentId, outcome);
    if (
      distributed.manifestVersion === input.selfManifest.manifestVersion &&
      distributed.signedBytesHashHex === input.selfManifest.manifestSigHashHex
    ) {
      return yield* resolve("accepted");
    }
    const present =
      metadata.variables.some((statement) => statement.variableId === variableId) ||
      metadata.tombstones.some((tombstone) => tombstone.variableId === variableId);
    if (distributed.manifestVersion > input.selfManifest.manifestVersion && present) {
      // 並行メタ操作に追い越されたが、自分の作成の効果は検証済み集合に存在する
      return yield* resolve("accepted-superseded");
    }
    if (distributed.manifestVersion === input.selfManifest.manifestVersion) {
      yield* resolve("not-accepted");
      return yield* Effect.fail(
        cliError(
          `The variable creation was accepted (2xx), but the server distributes a different manifest at the issued manifestVersion ${input.selfManifest.manifestVersion} (issued signed-bytes hash ${input.selfManifest.manifestSigHashHex}, distributed ${distributed.signedBytesHashHex}). The issued manifest was not stored — treating the creation as unconfirmed (AUTH_SPEC §12-10 (3)); the local floor was not advanced with the issued manifest`,
        ),
      );
    }
    return yield* Effect.fail(
      cliError(
        `The variable creation was accepted (2xx), but its effect could not be confirmed in the verified distribution (variable ${variableId} is absent and the distributed manifestVersion is ${distributed.manifestVersion} vs the issued ${input.selfManifest.manifestVersion}). Treating the creation as unconfirmed (AUTH_SPEC §12-10 (3)) — re-run the command after investigating the server`,
      ),
    );
  });
}

/**
 * Pushes one variable value: resolve the target by display name through the
 * verified metadata statements of a metadata-only pull (§4.2 / §12-7 — the
 * lookup key is NFC-normalized, matching is byte-exact; only a push to an
 * existing variable fetches values, so a creation is never recorded as a
 * `var.read`), encrypt under the
 * chain-derived current epoch with a commitment-verified DEK, sign as the
 * caller (§4.1: prev = the verified latest value's signed-bytes hash, head =
 * the last verified chain head; creation additionally author-signs a
 * metaVersion-1 statement), and retry through the CAS conflicts (§12-5).
 * The chain — not the server's claim — stays the epoch authority.
 *
 * 変数作成は 1-E′ の効果確認(confirmVariableCreation)を通過して初めて成功と
 * する(§12-10 (3) — 床への記録とユーザーへの成功報告は確認通過後のみ)。
 */
export function pushVariable(input: PushInput): Effect.Effect<PushedVersion, CliError> {
  return Effect.gen(function* () {
    // 正規化の実施主体は署名前のクライアント(§4.2 / §12-1): ルックアップキーと
    // 新規作成時に署名する名前の両方を NFC 正規形にする
    const normalized: PushInput = { ...input, name: input.name.normalize("NFC") };
    const initial = yield* initialState(normalized);
    const outcome = yield* retryOnConflict(initial, {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) => attemptOnce(normalized, state),
      classify: classifyPushConflict,
      recover: (state, conflict) => nextState(normalized, state, conflict),
      exhaustedMessage: `The push conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
    });
    const acceptedState = outcome.state;
    if (outcome.selfManifest !== null) {
      // メタ操作(変数作成)の成功の定義 = 検証可能な配布物での効果確認(1-E′)。
      // **床への記録は確認通過後のみ**(§12-10 (3)): 2xx だけを根拠に自分の
      // 書き込みを床へ植えると、サーバーが実際には保存していなかった場合に
      // 「配布されない変数を床が要求し続ける」= 以後の pull がすべて
      // variable-omitted で恒久拒否される(未確認の思い込みが equivocation
      // 証拠に化ける)。env create が確認後にのみ v1 床を書くのと同じ規律
      yield* confirmVariableCreation({
        push: normalized,
        accepted: outcome,
        selfManifest: outcome.selfManifest,
      });
    }
    // 受理された自分の書き込みを床へ昇格する(§6.3 — 以後の pull で自分の
    // 書き込みの巻き戻しも検出できる。journal-before-release: 成功報告より先)。
    // 既存変数への値 push は 1-E′ の適用外なので受理直後 = ここ、作成は上の
    // 効果確認を通過した後。規則 (c) 基準は動かさない。push 自体は受理済み
    // なので、床の書き込み失敗はその旨を明示する
    yield* input.floor
      .commitPush(
        // 床のキーは自分が署名した変数 ID(サーバー echo を信用しない)
        acceptedState.target.variableId,
        outcome.floorVariable,
        {
          seq: acceptedState.verified.state.headSeq,
          hashHex: acceptedState.verified.state.headHashHex,
        },
      )
      .pipe(Effect.mapError((error) => cliError(`The push was accepted, but ${error.message}`)));
    // 成功として報告する座標は**ローカルで署名した値**(床の更新と同じ姿勢 —
    // deepsec B7)。サーバー echo は突合のみに使い、食い違えば型付きエラーで
    // 明示する(echo を表示に昇格させると、サーバー申告の座標をユーザーが
    // 事実として引用しうる)
    const floorVariable = outcome.floorVariable;
    if (floorVariable.status !== "active") {
      // attemptOnce は常に active の床レコードを組む — ここに来たら内部不整合
      return yield* Effect.fail(
        cliError("The accepted push produced a non-active floor record (internal inconsistency)"),
      );
    }
    const local = {
      variableId: acceptedState.target.variableId,
      version: floorVariable.version,
      epoch: floorVariable.epoch,
    };
    const echo = outcome.accepted;
    if (
      echo.variableId !== local.variableId ||
      echo.version !== local.version ||
      echo.epoch !== local.epoch
    ) {
      return yield* Effect.fail(
        cliError(
          `The push was accepted and recorded locally as ${local.variableId} version=${local.version} epoch=${local.epoch}, but the server's response echoes different coordinates (${displayText(echo.variableId)} version=${echo.version} epoch=${echo.epoch}). The locally signed values are authoritative — verify the server with maruhi pull`,
        ),
      );
    }
    return { ...local, warnings: acceptedState.warnings };
  });
}
