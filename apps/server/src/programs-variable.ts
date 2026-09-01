// 変数とバージョニングの Effect プログラム(AUTH_SPEC §12-5)。
//
// 判定順(§12-3)と permit 直列化の前提は旧 data-programs.ts のとおり:
// requireMemberState → 環境・変数の存在 → CAS → 署名検証 → 数量ポリシー →
// 原子書き込み + 監査(AUDIT_SPEC §3.3)。

import type { ChainHistoryIndex, ChainMember, ChainState } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type {
  DataActor,
  DataRejection,
  EnvManifestInput,
  MetaStatementInput,
  SchemaPolicy,
  ValueInput,
  VariableVersionValue,
} from "./data-plane.ts";
import { currentEpochOf, dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import type { DataWriteOps, VariableRow } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import { MAX_VERSIONS_PER_VARIABLE } from "./policy.ts";
import {
  ensureProjectCapacity,
  ensureVariableQuota,
  requireActiveEnvironment,
  requireActiveVariable,
} from "./quotas.ts";
import { acceptManifestForMetaOp } from "./verify-manifest.ts";
import {
  acceptMetaStatement,
  ensureDescriptionPolicy,
  ensureMetaCas,
  ensureMetaStatementSignature,
  ensureNfcName,
  ensureSchemaPolicyAllowsLayout,
  ensureSupportedLayout,
  statementLayoutVersion,
} from "./verify-meta.ts";
import { ensureValueCas, ensureValueSignature } from "./verify-value.ts";

function variableIdUnavailable(
  existing: VariableRow | null,
  variableId: string,
): DataRejection | null {
  if (existing === null) {
    return null;
  }
  const reason = existing.deletedAtMs === null ? "exists" : "retired";
  return { kind: "variable-conflict", variableId, reason };
}

/**
 * バージョン行の書き込み + var.version_pushed の記録(create / push 共通の末尾)。
 * 同期関数: 呼び出し側の書き込みフェーズ(単一の Effect.sync)内で使う。
 * writer は受理時点のチェーン導出メンバー(値署名の検証に使った鍵の持ち主 —
 * CRYPTO_SPEC §4.1)。監査は chain-derived writer FP のみを写す(AUDIT_SPEC §3.3 —
 * 署名・signed bytes・hash・nonce・暗号文は監査に載せない)。
 *
 * `reencryption` は writer 申告の再暗号化マーカー(AUTH_SPEC §12-5)。true の
 * ときだけ payload に写す(§3.3 — 未申告・false は写さない)。受理判定には
 * 一切関与しない — 読むのは要ローテーション検出の解消導出(§4.1-5)だけ。
 */
function writeVersionWithAudit(
  write: DataWriteOps,
  appendAudit: (event: AuditEventInput) => void,
  actor: DataActor,
  writer: ChainMember,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  reencryption: boolean,
  signedBytesHashHex: string,
  nowMs: number,
): void {
  write.insertVersion(
    environmentId,
    variableId,
    value,
    value.ciphertextHex.length / 2,
    signedBytesHashHex,
    { userId: writer.userId, keyFingerprintHex: writer.keyFingerprintHex },
    nowMs,
  );
  appendAudit(
    dataEvent(actor, nowMs, "var.version_pushed", {
      environmentId,
      variableId,
      epoch: value.epoch,
      version: value.version,
      actorKeyFingerprintHex: writer.keyFingerprintHex,
      ...(reencryption ? { payload: { reencryption: true } } : {}),
    }),
  );
}

/**
 * schema-locked(§12-11 / §12-5): locked のプロジェクトでは変数作成
 * (metaVersion 1 — declared・値同梱の両方)に layoutVersion 2 かつ varType
 * 非空を要求する(typo による影の変数の黙った創出の書き込み時遮断)。
 * **作成時の一回検査**であり継続的な不変条件ではない — 後続のスキーマ再発行で
 * varType を "" へ戻すことは locked 下でも妨げず、declared の activation にも
 * 遡及しない。
 */
function ensureSchemaLockedCreation(
  schemaPolicy: SchemaPolicy,
  statement: MetaStatementInput,
): Effect.Effect<void, ReturnType<typeof rejectData>> {
  if (schemaPolicy !== "locked") {
    return Effect.void;
  }
  if (statementLayoutVersion(statement) !== 2 || (statement.schema?.varType ?? "") === "") {
    return Effect.fail(rejectData({ kind: "schema-policy-rejected", reason: "schema-required" }));
  }
  return Effect.void;
}

/**
 * 作成(metaVersion 1)のスキーマ系受理検査(§12-11 / §12-8)を受理時点の
 * ポリシーで通す: disabled の有効化ゲート(v2 の新規採用拒否)→ schema-locked の
 * 作成時検査 → description の受理ポリシー。layoutVersion のサポート範囲検査は
 * 呼び出し側(createVariableProgram)が statement 依存の全検査より前に行う。
 */
const ensureCreationSchemaGates = (statement: MetaStatementInput) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const schemaPolicy = yield* store.schemaPolicy;
    yield* ensureSchemaPolicyAllowsLayout({
      schemaPolicy,
      statement,
      predecessorLayoutVersion: 1,
    });
    yield* ensureSchemaLockedCreation(schemaPolicy, statement);
    yield* ensureDescriptionPolicy(statement);
  });

/**
 * 作成の前段検査(§12-1 / §12-8): ID の可用性(tombstone 再利用禁止)→
 * 数量ポリシー → NFC → 名前の一意性。
 */
const ensureVariableCreatable = (
  environmentId: string,
  statement: MetaStatementInput,
  variableId: string,
) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const existing = yield* store.findVariable(environmentId, variableId);
    const unavailable = variableIdUnavailable(existing, variableId);
    if (unavailable !== null) {
      return yield* rejectData(unavailable);
    }
    yield* ensureVariableQuota(environmentId);
    yield* ensureNfcName(statement.name);
    if (yield* store.variableNameTaken(environmentId, statement.name, null)) {
      return yield* rejectData({
        kind: "variable-conflict",
        variableId,
        reason: "duplicate-name",
      });
    }
  });

/** 同梱 version 1 の値の検証列(値ありの作成のみ): 値 CAS → 値署名 → 容量。 */
const acceptCreationValue = (context: {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly value: ValueInput;
}) =>
  Effect.gen(function* () {
    yield* ensureValueCas(context.state, context.environmentId, 0, context.value);
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId: context.projectId,
      environmentId: context.environmentId,
      variableId: context.variableId,
      history: context.history,
      member: context.member,
      value: context.value,
    });
    return { value: context.value, signedBytesHashHex };
  });

/**
 * 変数作成(§12-5): active(version 1 の値同梱)または declared(値なし —
 * 「値のない変数は存在しない」の唯一の例外。レイアウト v2 限定)。ワイヤ
 * Schema が status と値の有無の結合を固定する(deleted の創出は構造的に不可)。
 */
export const createVariableProgram = (
  actor: DataActor,
  environmentId: string,
  input: {
    readonly variableId: string;
    readonly statement: MetaStatementInput;
    /** active 作成の version 1 の値。declared 作成(値なし)では undefined。 */
    readonly value?: ValueInput;
    readonly manifest: EnvManifestInput;
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    // サポート範囲検査は statement 依存の全検査(NFC・重複名を含む前段検査 —
    // ensureVariableCreatable)より前(rename / 削除 / activation と同じ規律 —
    // 名前が衝突している v3 クライアントに duplicate-name を返さない)
    yield* ensureSupportedLayout(input.statement);
    yield* ensureVariableCreatable(environmentId, input.statement, input.variableId);
    // スキーマポリシー(§12-11 — 受理時点のポリシーを permit 下で読む):
    // disabled は v2 の新規採用(metaVersion 1 の v2 作成)を拒否し、locked は
    // 作成に v2 + varType 非空を要求する。description の上限・文字種は §12-8
    yield* ensureCreationSchemaGates(input.statement);
    // 作成 = version 1 の値 + metaVersion 1 のステートメントの同梱(§12-5)。
    // ワイヤ Schema が metaVersion 1・active/declared・prev 空を固定するが、
    // CAS は防衛線として残す(latest = 0 相当)
    yield* ensureMetaCas(0, input.statement);
    // 同梱 version 1 の値・同梱ステートメントとも通常経路と同一の署名検証を
    // 受ける(§12-5 — 作成経由の検証迂回は値・メタとも不可。declared 作成は
    // 値がないため値署名の検証のみ対象外)。判定順:
    // CAS → メタ署名 → 値署名 → 数量ポリシー(裁定 D への挿入)
    const metaSignedBytesHashHex = yield* ensureMetaStatementSignature({
      projectId,
      environmentId,
      target: { kind: "variable", variableId: input.variableId },
      history,
      member,
      statement: input.statement,
    });
    const acceptedValue =
      input.value === undefined
        ? null
        : yield* acceptCreationValue({
            state,
            history,
            member,
            projectId,
            environmentId,
            variableId: input.variableId,
            value: input.value,
          });
    // 環境マニフェストの複合受理(§12-5 — 2026-08-18): 作成後のメタ状態
    // (新変数のステートメントを含む集合)からダイジェストを再計算して申告と
    // 突合する。manifestVersion CAS は metaVersion CAS と同一トランザクション
    // (同一プログラム・同一 permit)で判定される
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member,
      manifest: input.manifest,
      digestOverride: {
        variableId: input.variableId,
        status: input.statement.status,
        metaVersion: input.statement.metaVersion,
        signedBytesHashHex: metaSignedBytesHashHex,
      },
    });
    if (acceptedValue !== null) {
      yield* ensureProjectCapacity(acceptedValue.value.ciphertextHex.length / 2);
    }
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): 変数行 + ステートメント行 +(active 作成
    // なら)version 1 + マニフェスト(最新 1 通の upsert)+ 監査行を原子的に
    // 書く(「latest_version = 0 のまま ID だけ占有された active 変数」を
    // 残さない — declared だけが正当な version 0 状態)
    yield* Effect.sync(() => {
      store.write.insertVariable(environmentId, input.variableId, input.statement.name, now);
      acceptedManifest.writeSync(now);
      store.write.insertVariableMetaStatement(
        environmentId,
        input.variableId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      // var.created の FP = author FP(declared 作成 — 値署名なし — は
      // ステートメント署名の author 鍵 FP のみを写す。AUDIT_SPEC §3.3)
      audit.appendSync(
        dataEvent(actor, now, "var.created", {
          environmentId,
          variableId: input.variableId,
          payload: { name: input.statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
      if (acceptedValue !== null) {
        // 作成は定義上、再暗号化ではない(マーカーの申告面も持たない — §12-5)
        writeVersionWithAudit(
          store.write,
          audit.appendSync,
          actor,
          member,
          environmentId,
          input.variableId,
          acceptedValue.value,
          false,
          acceptedValue.signedBytesHashHex,
          now,
        );
      }
    });
    return {
      variableId: input.variableId,
      // declared 作成は保存バージョン 0 のまま(§12-5)
      version: acceptedValue?.value.version ?? 0,
      epoch: acceptedValue?.value.epoch ?? currentEpochOf(state, environmentId),
    } satisfies VariableVersionValue;
  });

export const pushVersionProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  reencryption: boolean,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    // declared 変数への通常 push は受理しない(§12-5): 最初の値は activation
    // 複合(値 version 1 + status active のステートメント + マニフェスト)のみ
    if (variable.latestStatus === "declared") {
      return yield* rejectData({ kind: "activation-required", variableId });
    }
    yield* ensureValueCas(state, environmentId, variable.latestVersion, value);
    // 判定順(裁定 D): epoch / version CAS → 値署名(署名 → 宣言 head →
    // head 時点状態 → predecessor)→ 数量ポリシー → 原子書き込み。
    // 不受理時は variable / version / latest / audit のいずれも変更しない
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId,
      history,
      member,
      value,
    });
    if (value.version > MAX_VERSIONS_PER_VARIABLE) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "versions",
        limit: MAX_VERSIONS_PER_VARIABLE,
      });
    }
    yield* ensureProjectCapacity(value.ciphertextHex.length / 2);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        member,
        environmentId,
        variableId,
        value,
        reencryption,
        signedBytesHashHex,
        now,
      );
    });
    return {
      variableId,
      version: value.version,
      epoch: value.epoch,
    } satisfies VariableVersionValue;
  });

/**
 * activation(declared → active — §12-5): declared 変数への最初の値 push を
 * 「EncryptedPayload(version 1)+ status active のステートメント(metaVersion
 * + 1・v2)+ EnvironmentManifest」の複合として受理する。値署名・ステートメント
 * 署名・マニフェストの検証は既存規則の合成。直前が v2(declared は v2 限定)の
 * ため継続ステートメントとしてポリシーに依らず受理される(§12-11 の可逆性 —
 * schema-locked の varType 検査も遡及しない: activation は創出ではない)。
 */
export const activateVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  input: {
    readonly value: ValueInput;
    readonly statement: MetaStatementInput;
    readonly manifest: EnvManifestInput;
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    // サポート範囲検査は statement 依存の全検査より前(rename / 削除と同じ
    // 規律 — v3 クライアントには下の status / name ガードや値 CAS の誤誘導
    // エラーでなく、常に正直な update-required を返す)
    yield* ensureSupportedLayout(input.statement);
    // activation の対象は declared のみ(§12-5 — 「値 push + メタ再発行」の
    // 汎用複合ではない)。値 CAS は version = latestVersion + 1 しか強制しない
    // ため対象判定を兼ねられず(active 変数へ version N+1 を送れば通過して
    // しまう)、この明示ガードが下の schemaPolicy 免除の前提「直前は必ず v2
    // (declared は v2 限定)」を成立させる — 無いと disabled 下で active な
    // v1 変数を v2 へ昇格でき、§12-11 の有効化ゲートが迂回される
    // (PR #119 pullfrog レビュー指摘)
    if (variable.latestStatus !== "declared") {
      return yield* rejectData({ kind: "payload-mismatch", field: "status" });
    }
    // activation は改名を兼ねない: name は宣言時の名をそのまま保持する
    // (delete の name 保持と同じ受理検査 — 改名は rename 経路が var.renamed の
    // 監査と共に担い、「名前の変更 ⇔ var.renamed 行」の対応を崩さない)。
    // 保持一致により NFC・一意性は宣言受理時の検査結果がそのまま生きる
    if (input.statement.name !== variable.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    // declared は latestVersion 0 の唯一の正当な状態なので、CAS が値 version 1 を
    // 強制する(§12-5 の「値 version 1」)
    yield* ensureValueCas(state, environmentId, variable.latestVersion, input.value);
    // メタ受理列(§12-5): CAS → アンカー → description 受理検査 → 署名検証
    // (declared → active の遷移と v2 単調性は crypto の predecessor 検査)。
    // schemaPolicy は渡さない — 上の declared ガードにより直前は必ず v2 で、
    // 継続ステートメントはポリシーに依らず受理される(§12-11)
    const metaSignedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement: input.statement,
    });
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId,
      history,
      member,
      value: input.value,
    });
    // マニフェストの複合受理(§12-5): activation はメタ状態が変わるため
    // マニフェスト再発行を伴う(「値の push はマニフェストに触れない」不変条件の
    // 対象は通常 push — CRYPTO_SPEC §4.3)
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member,
      manifest: input.manifest,
      digestOverride: {
        variableId,
        status: "active",
        metaVersion: input.statement.metaVersion,
        signedBytesHashHex: metaSignedBytesHashHex,
      },
    });
    yield* ensureProjectCapacity(input.value.ciphertextHex.length / 2);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): ステートメント行 + version 1 +
    // マニフェスト + var.version_pushed(version 1 — AUDIT_SPEC §3.3。
    // 存在区間の開始は declared 作成時の var.created が既に保持する)
    yield* Effect.sync(() => {
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      acceptedManifest.writeSync(now);
      // activation は最初の値であり、定義上再暗号化ではない
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        member,
        environmentId,
        variableId,
        input.value,
        false,
        signedBytesHashHex,
        now,
      );
    });
    return {
      variableId,
      version: input.value.version,
      epoch: input.value.epoch,
    } satisfies VariableVersionValue;
  });

export const renameVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  manifest: EnvManifestInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    // サポート範囲検査は statement 依存の全検査より前(裁定 CR — サポート外
    // レイアウトには以降の検査の誤誘導エラーを返さない)
    yield* ensureSupportedLayout(statement);
    // rename / スキーマ再発行は status 不変(§12-5): declared → active は
    // activation 複合(値同梱)のみ、active → declared は禁止。ワイヤは両
    // status を運べるため、現状態との一致を受理検査で固定する(name の保持
    // 検査と同じ payload-mismatch)
    if (statement.status !== variable.latestStatus) {
      return yield* rejectData({ kind: "payload-mismatch", field: "status" });
    }
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.variableNameTaken(environmentId, statement.name, variableId)) {
      return yield* rejectData({ kind: "variable-conflict", variableId, reason: "duplicate-name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement,
      // 有効化ゲート(§12-11): disabled 下の「v1 変数への v2 再発行」を拒否する
      // (直前が v2 の継続はポリシーに依らず通る — アンカー実値で判定)
      schemaPolicy: yield* store.schemaPolicy,
    });
    // マニフェストの複合受理(§12-5): rename 適用後の集合で再計算・突合
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member,
      manifest,
      digestOverride: {
        variableId,
        status: statement.status,
        metaVersion: statement.metaVersion,
        signedBytesHashHex,
      },
    });
    const audit = yield* AuditStore;
    const now = Date.now();
    // 監査イベントの分岐(AUDIT_SPEC §3.3 — 2026-09-01): 名前が実際に変わった
    // 再発行のみ var.renamed、名前不変の再発行(スキーマ欄の設定・変更 —
    // §12-5 のスキーマ再発行)は var.schema_reissued。ワイヤは同一操作形の
    // ため受理時の直前ステートメント名との byte 比較で分岐する(改名して
    // いない操作を「renamed」と記録しない)。名前とスキーマ欄の同時変更は
    // var.renamed 1 行(名前変更が主事象 — 1 操作 1 行の記録規律)
    const event = statement.name === variable.name ? "var.schema_reissued" : "var.renamed";
    yield* Effect.sync(() => {
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      acceptedManifest.writeSync(now);
      audit.appendSync(
        dataEvent(actor, now, event, {
          environmentId,
          variableId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  manifest: EnvManifestInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    // サポート範囲検査は statement 依存の全検査より前(rename と同じ規律)
    yield* ensureSupportedLayout(statement);
    // deleted の name は直前 active 名を保持する(§4.2 — byte-exact)
    if (statement.name !== variable.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement,
    });
    // マニフェストの複合受理(§12-5): tombstone を含む集合で再計算・突合
    // (tombstone 隠しの digest 不一致はここで落ちる — §4.3 (3))
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member,
      manifest,
      digestOverride: {
        variableId,
        status: "deleted",
        metaVersion: statement.metaVersion,
        signedBytesHashHex,
      },
    });
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ: tombstone + 全バージョン削除 + deleted ステートメント行
    // (保存・配布し続ける — §12-5)+ マニフェスト + var.deleted(author FP —
    // AUDIT_SPEC §3.3)
    yield* Effect.sync(() => {
      store.write.retireVariable(environmentId, variableId, now);
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      acceptedManifest.writeSync(now);
      audit.appendSync(
        dataEvent(actor, now, "var.deleted", {
          environmentId,
          variableId,
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });
