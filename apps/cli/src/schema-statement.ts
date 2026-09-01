// レイアウト v2 の変数メタステートメント(CRYPTO_SPEC §4.2 — スキーマ欄付き)の
// 著者署名とワイヤ導出の共有実装。meta-statement.ts(v1 作成形)と同じ規律:
// 「署名した context」と「ワイヤに載せる statement」を独立の 2 リテラルで書くと
// 1 フィールドの食い違いが静かな検証失敗になるため、context を 1 回だけ構築し
// ワイヤは機械的に導出する。
//
// 使う側:
//   - `maruhi schema set`(schema.ts)— 宣言作成(declared・metaVersion 1)と
//     スキーマ再発行(status 不変・metaVersion + 1)
//   - `maruhi push` の activation(push.ts)— declared → active(metaVersion + 1・
//     スキーマ欄は宣言時の値を byte-exact に引き継ぐ)
//
// required は署名対象では "true" | "false" の明示文字列(§4.2 — 省略時解釈の
// 実装分散を許さない fail-closed)、ワイヤでは boolean(§12-2)。変換はこの
// モジュールの中に閉じる。

import { SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { CliError } from "./errors.ts";
import type { VerifiedSchemaFields } from "./floor-check.ts";
import { signStatementAndHash } from "./meta-statement.ts";
import type { VerifiedProject } from "./sync.ts";

/** v2 ステートメントの共通入力(作成 / 継続の別は下の 2 関数が固定する)。 */
export interface VariableStatementV2Input {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly variableId: string;
  /** 表示名(呼び出し側で NFC 正規化済み — §4.2 / §12-1)。 */
  readonly name: string;
  /** スキーマ欄(§4.2 — required は boolean。署名時に文字列形へ写す)。 */
  readonly schema: VerifiedSchemaFields;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}

/** v2 ステートメントのワイヤ形(§12-2 — layoutVersion 2 + スキーマ欄)。 */
interface WireVariableStatementV2Base {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly layoutVersion: 2;
  readonly varType: VerifiedSchemaFields["varType"];
  readonly required: boolean;
  readonly description: string;
}

/** 宣言作成のワイヤ形(DeclareVariableMetaStatementSchema と構造一致)。 */
export type WireDeclareStatement = WireVariableStatementV2Base & {
  readonly status: "declared";
  readonly metaVersion: 1;
  readonly prevMetaSigHashHex: "";
};

/** 継続(activation / スキーマ再発行)のワイヤ形(Rename V2 / Activate と構造一致)。 */
export type WireContinuationStatementV2 = WireVariableStatementV2Base & {
  readonly status: "active" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
};

export interface SignedStatementV2<Wire> {
  readonly statement: Wire;
  /** 受理されたらローカル床のメタ記録になる自計算ハッシュ(§6.3 — サーバー申告でない)。 */
  readonly metaSigHashHex: string;
}

interface LifecycleFields {
  readonly status: "active" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
}

/** 署名対象 context の唯一の構築点(宣言ヘッド = 最後に検証したチェーンヘッド)。 */
function statementContextV2(input: VariableStatementV2Input, lifecycle: LifecycleFields) {
  return {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: { kind: "variable", variableId: input.variableId },
    name: input.name,
    status: lifecycle.status,
    layoutVersion: 2,
    schema: {
      varType: input.schema.varType,
      // §4.2: v2 の required は明示必須の文字列("true" | "false")
      required: input.schema.required ? "true" : "false",
      description: input.schema.description,
    },
    metaVersion: lifecycle.metaVersion,
    prevMetaSigHashHex: lifecycle.prevMetaSigHashHex,
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
}

type StatementContextV2 = ReturnType<typeof statementContextV2>;

/** ワイヤ statement を署名済み context から機械的に導出する(meta-statement.ts と同じ規律)。 */
function toWireStatementV2(
  context: StatementContextV2,
  signatureHex: string,
): WireContinuationStatementV2 {
  return {
    suite: context.suite,
    environmentId: context.environmentId,
    variableId: context.target.variableId,
    name: context.name,
    status: context.status,
    metaVersion: context.metaVersion,
    prevMetaSigHashHex: context.prevMetaSigHashHex,
    chainHeadHashHex: context.chainHeadHashHex,
    chainHeadSeq: context.chainHeadSeq,
    signatureHex,
    layoutVersion: context.layoutVersion,
    varType: context.schema.varType,
    // ワイヤは boolean(§12-2)— 署名対象の文字列形から機械的に写す
    required: context.schema.required === "true",
    description: context.schema.description,
  };
}

function signV2(
  input: VariableStatementV2Input,
  lifecycle: LifecycleFields,
): Effect.Effect<SignedStatementV2<WireContinuationStatementV2>, CliError> {
  return Effect.gen(function* () {
    const context = statementContextV2(input, lifecycle);
    // 署名 + 自計算ハッシュは v1 作成形と共有(meta-statement.ts)
    const signed = yield* signStatementAndHash(context, input.signingKey);
    return {
      statement: toWireStatementV2(context, signed.signatureHex),
      metaSigHashHex: signed.metaSigHashHex,
    };
  });
}

/**
 * Author-signs a declared creation statement (metaVersion 1, status declared,
 * empty prev — CRYPTO_SPEC §4.2: the only value-free variable creation).
 */
export function signDeclareStatement(
  input: VariableStatementV2Input,
): Effect.Effect<SignedStatementV2<WireDeclareStatement>, CliError> {
  return Effect.map(
    signV2(input, { status: "declared", metaVersion: 1, prevMetaSigHashHex: "" }),
    (signed) => ({
      // lifecycle は上のリテラルで固定済み — ワイヤ形の narrowing のみ
      statement: signed.statement as WireDeclareStatement,
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}

/**
 * Author-signs a layout-v2 continuation statement (metaVersion = prev + 1):
 * a schema reissue (status preserved — AUTH_SPEC §12-5) or an activation
 * (declared → active, bundled with value version 1 — the activation
 * composite). 遷移の正当性(declared → active のみ・active → declared 禁止)は
 * 呼び出し側が検証済みの直前ステートメントから status を決めることで担保する
 * (受理の正はサーバー §12-5)。
 */
export function signContinuationStatementV2<Status extends "active" | "declared">(
  input: VariableStatementV2Input & {
    readonly status: Status;
    readonly prev: { readonly metaVersion: number; readonly metaSigHashHex: string };
  },
): Effect.Effect<
  SignedStatementV2<WireContinuationStatementV2 & { readonly status: Status }>,
  CliError
> {
  return Effect.map(
    signV2(input, {
      status: input.status,
      metaVersion: input.prev.metaVersion + 1,
      prevMetaSigHashHex: input.prev.metaSigHashHex,
    }),
    (signed) => ({
      // status は入力リテラルで固定済み — ワイヤ形の narrowing のみ
      statement: signed.statement as WireContinuationStatementV2 & { readonly status: Status },
      metaSigHashHex: signed.metaSigHashHex,
    }),
  );
}
