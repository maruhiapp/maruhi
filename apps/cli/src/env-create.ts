// 環境作成(AUTH_SPEC §12-4)とエポック 1 の DEK ラップ完全集合の生成。
//
// ラップ集合は検証済み ChainState の現メンバー集合と厳密一致させて生成する
// (CRYPTO_SPEC §6.3 のラップ先一致検査 = ゴーストメンバー対策のクライアント側。
// サーバーの §12-6 検証は補助線であり、こちらが本線 — session-07 §5)。
// ラップ生成 → signDekWrap → 登録は一続きで行う(署名者 = 呼び出し主体 —
// session-10 §5)。
//
// grant_server が有効なプロジェクトは拒否する: サーバー宛ラップのデータ
// プレーンは Phase 2 未実装で、メンバー宛のみの登録は §7 の開示契約を
// 黙って破ることになるため。

import type { WrappedDek } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainMember, SigningKeyPair } from "@maruhi/crypto";
import {
  decodeHex,
  encodeHex,
  generateDek,
  importEncryptionPublicKey,
  signDekWrap,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

async function wrapAndSignFor(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly member: ChainMember;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Promise<WrappedDek | null> {
  const { verified, environmentId, epoch, dek, member } = input;
  const recipientKeyBytes = decodeHex(member.encPubHex);
  if (recipientKeyBytes === null) {
    return null;
  }
  const recipientKey = await importEncryptionPublicKey(recipientKeyBytes);
  if (!recipientKey.ok) {
    return null;
  }
  const wrapped = await wrapDek({
    recipientPublicKey: recipientKey.value,
    dek,
    context: {
      projectId: verified.projectId,
      environmentId,
      epoch,
      recipientUserId: member.userId,
    },
  });
  if (!wrapped.ok) {
    return null;
  }
  const encHex = encodeHex(wrapped.value.enc);
  const ciphertextHex = encodeHex(wrapped.value.ciphertext);
  const signature = await signDekWrap({
    context: {
      suite: SUITE_ID,
      projectId: verified.projectId,
      environmentId,
      epoch,
      recipientUserId: member.userId,
      recipientEncPubHex: member.encPubHex,
      encHex,
      ciphertextHex,
      signerUserId: input.signerUserId,
    },
    signingKey: input.signingKeyPair.privateKey,
  });
  if (!signature.ok) {
    return null;
  }
  return {
    suite: SUITE_ID,
    epoch,
    recipientUserId: member.userId,
    recipientEncPubHex: member.encPubHex,
    encHex,
    ciphertextHex,
    signatureHex: signature.value,
  };
}

/**
 * Builds the wrap set for one epoch: exactly the verified current member set
 * (§6.3), each wrap signed by the caller (§5.1). Deterministic recipient
 * order (userId ascending) for reproducible requests.
 */
function buildWrapSetForMembers(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<readonly WrappedDek[], CliError> {
  return Effect.gen(function* () {
    const members = [...input.verified.state.members.values()].toSorted((a, b) =>
      a.userId < b.userId ? -1 : 1,
    );
    const wraps: WrappedDek[] = [];
    for (const member of members) {
      const wrap = yield* Effect.promise(() => wrapAndSignFor({ ...input, member }));
      if (wrap === null) {
        return yield* Effect.fail(
          cliError(`メンバー ${member.userId} 宛の DEK ラップ生成に失敗しました`),
        );
      }
      wraps.push(wrap);
    }
    return wraps;
  });
}

/** `maruhi env create`: create an environment with its epoch-1 wrap set (§12-4). */
export function envCreateOp(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<{ readonly currentEpoch: number }, CliError> {
  return Effect.gen(function* () {
    if (input.verified.state.serverGrants.size > 0) {
      return yield* Effect.fail(
        cliError(
          "このプロジェクトは grant_server が有効です。サーバー宛 DEK ラップは Phase 2 未実装のため、CLI からの環境作成は行えません",
        ),
      );
    }
    // 作成時の現エポックは常に 1(チェーン観測済み ID は作成不可 — §12-4)。
    // サーバーの 409 を待たずクライアントでも早期検出する
    if (input.verified.state.environmentEpochs.has(input.environmentId)) {
      return yield* Effect.fail(
        cliError(
          `環境 ID ${input.environmentId} はチェーン上で使用済みです(rotate_epoch 観測済み)。別の ID を使ってください`,
        ),
      );
    }
    const dek = generateDek();
    const deks = yield* buildWrapSetForMembers({
      verified: input.verified,
      environmentId: input.environmentId,
      epoch: 1,
      dek,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
    const created = yield* input.client.environments
      .create({
        params: { projectId: input.verified.projectId },
        payload: { environmentId: input.environmentId, name: input.name, deks },
      })
      .pipe(Effect.mapError(toCliError));
    return { currentEpoch: created.currentEpoch };
  });
}
