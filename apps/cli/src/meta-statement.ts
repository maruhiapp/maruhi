// 作成ステートメント(metaVersion 1・active・prev 空 — AUTH_SPEC §12-4 / §12-5 =
// CRYPTO_SPEC §4.2)の著者署名とワイヤ導出の共有実装。
//
// 「署名した context」と「ワイヤに載せる statement」を独立の 2 リテラルで書くと、
// 1 フィールドの食い違いが「署名がワイヤと異なるバイト列に対して検証される」
// 静かな欠陥になる(型では捕まらず、他クライアントの検証失敗として発現する)。
// MetaStatementContext は 1 回だけ構築し、ワイヤは toWireStatement で機械的に
// 導出する。push.ts(variable)/ env-create.ts(environment)の差分は target のみ。
//
// 注意: test/support/crypto.ts はワイヤ形式を意図的に独立再実装しており、本番
// 実装とのドリフトを検出する相互チェックとして機能するため、ここへ統合しない。

import { computeMetaSignedBytesHash, signMetaStatement, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { VerifiedProject } from "./sync.ts";

/** 作成ステートメントの対象(§4.2 の target — 変数か環境自身)。 */
export type CreateStatementTarget =
  | { readonly kind: "variable"; readonly variableId: string }
  | { readonly kind: "environment" };

export interface CreateStatementInput {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly target: CreateStatementTarget;
  /** 表示名(呼び出し側で NFC 正規化済み — §4.2 / §12-1)。 */
  readonly name: string;
  readonly authorUserId: string;
  readonly signingKey: CryptoKey;
}

/**
 * 署名対象 context の唯一の構築点。宣言ヘッドは「最後に検証したチェーン
 * ヘッド」(値署名と同じ)。CAS リトライで検証ビューが進めば呼び出し側が
 * 作り直す(試行ごとに署名するため)。
 */
function createStatementContext(input: CreateStatementInput) {
  return {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: input.target,
    name: input.name,
    status: "active",
    metaVersion: 1,
    prevMetaSigHashHex: "",
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
}

type CreateStatementContext = ReturnType<typeof createStatementContext>;

interface WireCreateStatementBase {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: string;
  readonly name: string;
  readonly status: "active";
  readonly metaVersion: 1;
  readonly prevMetaSigHashHex: "";
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/** 変数作成の同梱ステートメントのワイヤ形(variableId 付き)。 */
export type WireVariableCreateStatement = WireCreateStatementBase & {
  readonly variableId: string;
};

/** 環境作成の同梱ステートメントのワイヤ形。 */
export type WireEnvironmentCreateStatement = WireCreateStatementBase;

/**
 * ワイヤ statement を署名済み context から機械的に導出する。フィールドの出所は
 * 常に context(独立リテラルの再列挙を作らない — このモジュールの存在理由)。
 */
function toWireStatement(
  context: CreateStatementContext,
  signatureHex: string,
): WireCreateStatementBase & { readonly variableId?: string } {
  const base = {
    suite: context.suite,
    environmentId: context.environmentId,
    name: context.name,
    status: context.status,
    metaVersion: context.metaVersion,
    prevMetaSigHashHex: context.prevMetaSigHashHex,
    chainHeadHashHex: context.chainHeadHashHex,
    chainHeadSeq: context.chainHeadSeq,
    signatureHex,
  };
  return context.target.kind === "variable"
    ? { ...base, variableId: context.target.variableId }
    : base;
}

export interface SignedCreateStatement<Wire> {
  readonly statement: Wire;
  /** 受理されたらローカル床のメタ記録になる自計算ハッシュ(§6.3 — サーバー申告でない)。 */
  readonly metaSigHashHex: string;
}

/**
 * Author-signs a creation statement (metaVersion 1, active, empty prev) and
 * derives the wire statement mechanically from the very context that was
 * signed, so the signed bytes and the wire can never drift apart (§4.2).
 */
export function signCreateStatement(
  input: CreateStatementInput & {
    readonly target: { readonly kind: "variable"; readonly variableId: string };
  },
): Effect.Effect<SignedCreateStatement<WireVariableCreateStatement>, CliError>;
export function signCreateStatement(
  input: CreateStatementInput & { readonly target: { readonly kind: "environment" } },
): Effect.Effect<SignedCreateStatement<WireEnvironmentCreateStatement>, CliError>;
export function signCreateStatement(
  input: CreateStatementInput,
): Effect.Effect<SignedCreateStatement<WireCreateStatementBase>, CliError> {
  return Effect.gen(function* () {
    const context = createStatementContext(input);
    const signature = yield* Effect.tryPromise({
      try: () => signMetaStatement({ context, signingKey: input.signingKey }),
      catch: () => cliError("メタステートメントの署名に失敗しました"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("メタステートメントの署名に失敗しました"));
    }
    // 受理されたらローカル床のメタ記録になる自計算ハッシュ(§6.3)
    const metaSigHash = yield* Effect.tryPromise({
      try: () => computeMetaSignedBytesHash(context),
      catch: () => cliError("メタステートメント署名対象のハッシュ計算に失敗しました"),
    });
    if (!metaSigHash.ok) {
      return yield* Effect.fail(cliError("メタステートメント署名対象のハッシュ計算に失敗しました"));
    }
    return {
      statement: toWireStatement(context, signature.value),
      metaSigHashHex: metaSigHash.value,
    };
  });
}
