// 配布された値の検証(CRYPTO_SPEC §6.3 = session-14 裁定 G の pull 側)。
//
// 復号より前に、すべての値について §4.1 の値署名を検証済みチェーン履歴に対して
// 検証する。期待座標は申告値を信用せず自前で組み立てる: projectId = 検証済み
// genesis ハッシュ、environmentId = リクエストに使った ID、variableId = pull
// 応答の外側メタデータ。writer は配布された user_id + 鍵 FP(チェーン履歴と
// 照合)。epoch / version / nonce / ciphertext / prev / head は署名対象なので
// 申告値をそのまま検証に使い、座標側の一致は明示検査する(§6.3-5)。
//
// future head(宣言 seq > 自ビューのヘッド)は即時拒否せず、**1 回だけ**再同期
// して延長検査(sync.ts の ensureExtensionOf)を通し、新ビューで全値を再検証
// する(有界 — §6.3-2b)。seq ≤ 自ヘッドのハッシュ不一致・別整合チェーン・
// 旧 head 欠落・再同期後も未来のままの宣言はすべて拒否する。
//
// latest-only の限界(裁定 B): pull は最新版のみ運ぶため predecessor を持たず、
// prev の実在一致・エポック非減少はここでは検査できない(形の検査のみ)。
// 検査済みと偽らない — 永続床による検出は PR-4 の領分。

import type { DistributedEncryptedPayload } from "@maruhi/api-schema";
import type { RecipientDek } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import { verifyDistributedValue } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { resyncExtended, type VerifiedProject } from "./sync.ts";

/** One pulled variable whose write signature passed the §6.3 verification. */
export interface VerifiedPulledValue {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** 署名済みの prev(直前 version の signed bytes ハッシュ。version 1 は空)。 */
  readonly prevValueSigHashHex: string;
  /**
   * Locally recomputed hash of the value's signed bytes — the prev anchor
   * for pushing the next version (§4.1 の連鎖) and the comparator for
   * same-coordinate equivocation evidence (§14.2-5).
   */
  readonly signedBytesHashHex: string;
}

/** A bulk pull whose values all passed verification (§12-7 / §6.3). */
export interface VerifiedEnvironmentPull {
  /** 検証に使ったビュー(future head の有界再同期で前進していることがある)。 */
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedPulledValue[];
  /** 自分宛ラップ(検証は deks.ts の §5.1 / §5.2 経路が担う)。 */
  readonly deks: readonly RecipientDek[];
}

interface PulledWire {
  readonly variableId: string;
  readonly name: string;
  readonly value: DistributedEncryptedPayload;
}

type VerifyOutcome =
  | { readonly kind: "ok"; readonly value: VerifiedPulledValue }
  | { readonly kind: "future" }
  | { readonly kind: "rejected"; readonly message: string };

/** 申告 AAD の座標成分が期待座標(検証済み genesis / 要求 env / 応答外側 id)と一致するか(§6.3-5)。 */
function coordinatesMatch(
  verified: VerifiedProject,
  environmentId: string,
  variable: PulledWire,
): boolean {
  const aad = variable.value.aad;
  return (
    aad.projectId === verified.projectId &&
    aad.environmentId === environmentId &&
    aad.variableId === variable.variableId
  );
}

/**
 * 検証失敗理由 → VerifyOutcome。chain-head-future と「未同期区間の新規メンバーが
 * 宣言する自ビューより先のヘッド(writer-unknown かつ宣言 seq > 自ヘッド)」は
 * 有界再同期の入口(future)へ。それ以外は拒否(レビューループ 1 [低])。
 */
function failureOutcome(
  verified: VerifiedProject,
  variable: PulledWire,
  error: { readonly kind: string; readonly reason?: string },
): VerifyOutcome {
  if (error.kind === "ValueInvalid") {
    if (
      error.reason === "chain-head-future" ||
      (error.reason === "writer-unknown" && variable.value.chainHeadSeq > verified.history.headSeq)
    ) {
      return { kind: "future" };
    }
  }
  const reason = error.reason ?? error.kind;
  return {
    kind: "rejected",
    message: `変数 ${displayText(variable.name)} の値署名の検証に失敗しました(reason=${reason})。サーバーによる差し替え・偽造の可能性があります`,
  };
}

async function verifyOne(
  verified: VerifiedProject,
  environmentId: string,
  variable: PulledWire,
): Promise<VerifyOutcome> {
  const payload = variable.value;
  // 座標整合(§6.3-5): 検証・復号は期待座標で行うため不一致はどのみち失敗するが、
  // 明示検査で「どの座標が食い違ったか」を可視化する
  if (!coordinatesMatch(verified, environmentId, variable)) {
    return {
      kind: "rejected",
      message: `変数 ${displayText(variable.name)} の申告 AAD 座標が要求文脈と一致しません(サーバー応答の不整合)`,
    };
  }
  const result = await verifyDistributedValue({
    history: verified.history,
    context: {
      suite: payload.suite,
      projectId: verified.projectId,
      environmentId,
      epoch: payload.aad.epoch,
      variableId: variable.variableId,
      version: payload.aad.version,
      nonceHex: payload.nonceHex,
      ciphertextHex: payload.ciphertextHex,
      prevValueSigHashHex: payload.prevValueSigHashHex,
      writerUserId: payload.writerUserId,
      chainHeadHashHex: payload.chainHeadHashHex,
      chainHeadSeq: payload.chainHeadSeq,
    },
    writerKeyFingerprintHex: payload.writerKeyFingerprintHex,
    signatureHex: payload.signatureHex,
  });
  if (!result.ok) {
    return failureOutcome(verified, variable, result.error);
  }
  return {
    kind: "ok",
    value: {
      variableId: variable.variableId,
      name: variable.name,
      version: payload.aad.version,
      epoch: payload.aad.epoch,
      nonceHex: payload.nonceHex,
      ciphertextHex: payload.ciphertextHex,
      prevValueSigHashHex: payload.prevValueSigHashHex,
      signedBytesHashHex: result.value.signedBytesHashHex,
    },
  };
}

function verifyAll(
  verified: VerifiedProject,
  environmentId: string,
  variables: readonly PulledWire[],
): Effect.Effect<
  | { readonly kind: "ok"; readonly values: readonly VerifiedPulledValue[] }
  | { readonly kind: "future" },
  CliError
> {
  return Effect.gen(function* () {
    const seenIds = new Set<string>();
    const values: VerifiedPulledValue[] = [];
    for (const variable of variables) {
      // 同一応答内の variableId 重複は無条件拒否(同一座標に異なる signed bytes を
      // 併置する equivocation の運搬形を含む — 裁定 G)
      if (seenIds.has(variable.variableId)) {
        return yield* Effect.fail(
          cliError(
            `変数 ID が同一応答内で重複しています(サーバー応答の不整合): ${variable.variableId}`,
          ),
        );
      }
      seenIds.add(variable.variableId);
      const outcome = yield* Effect.promise(() => verifyOne(verified, environmentId, variable));
      if (outcome.kind === "future") {
        return { kind: "future" } as const;
      }
      if (outcome.kind === "rejected") {
        return yield* Effect.fail(cliError(outcome.message));
      }
      values.push(outcome.value);
    }
    return { kind: "ok", values } as const;
  });
}

/**
 * Pulls one environment and verifies every value's write signature before
 * anything is decrypted (§6.3 / §12-7). A declared head beyond the local
 * view triggers one bounded re-sync with the extension check; the values are
 * then re-verified against the advanced view.
 */
export function pullVerifiedEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** future head 時の有界再同期(1 回)。 */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<VerifiedEnvironmentPull, CliError> {
  return Effect.gen(function* () {
    const response = yield* input.client.variables
      .pull({ params: { projectId: input.verified.projectId, environmentId: input.environmentId } })
      .pipe(Effect.mapError(toCliError));
    const first = yield* verifyAll(input.verified, input.environmentId, response.variables);
    if (first.kind === "ok") {
      return { verified: input.verified, variables: first.values, deks: response.deks };
    }
    // 宣言ヘッドが自ビューより先 = 自チェーンが古いだけの可能性(§6.3-2b)。
    // 1 回だけ再同期し、旧ビューの延長であることを検査してから全値を再検証する
    const advanced = yield* resyncExtended(input.resync, input.verified);
    const second = yield* verifyAll(advanced, input.environmentId, response.variables);
    if (second.kind === "ok") {
      return { verified: advanced, variables: second.values, deks: response.deks };
    }
    return yield* Effect.fail(
      cliError(
        "再同期後もチェーンに存在しないヘッドへ束縛された値が配布されています(チェーン分岐または偽造の証拠)",
      ),
    );
  });
}
