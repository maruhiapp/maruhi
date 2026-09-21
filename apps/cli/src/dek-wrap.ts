// エポック DEK のラップ完全集合の生成(CRYPTO_SPEC §5 / §5.1 / §6.3、
// AUTH_SPEC §12-4 / §12-6)。
//
// 複合リクエスト(環境作成 = エポック 1、ローテーション = 新エポック)が同梱する
// 「ラップ完全集合」を、検証済み ChainState の「現メンバー集合 + 対象環境が
// 開示スコープに含まれる有効 grant_server のサーバー鍵」(§12-4)と
// 厳密一致させて生成する共有実装。ラップ先一致検査(§6.3 のゴーストメンバー
// 対策)のクライアント側が本線であり、サーバーの §12-6 検証は補助線
// (session-07 §5)。サーバー宛ラップの HPKE info / 登録署名の recipient 位置は
// サーバー鍵 FP(CRYPTO_SPEC §9)。
//
// ラップ生成 → signDekWrap → 登録は一続きで行う(署名者 = 呼び出し主体 —
// §5.1 / session-10 §5)。CAS リトライでの作り直しは、再同期で受信者集合
// (メンバー + スコープ内 grant)が変わった場合のみ(§12-4 — HPKE Seal は
// ランダムなので不要な再ラップを避ける)。

import type { WrappedDek } from "@maruhi/api-schema";
import type {
  ChainDevice,
  ChainMember,
  EffectivePermission,
  Role,
  ServerGrant,
  SigningKeyPair,
} from "@maruhi/crypto";
import {
  decodeHex,
  effectivePermissionOf,
  encodeHex,
  importEncryptionPublicKey,
  scopeIncludesEnvironment,
  signDekWrap,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import { devicesOf, ownDeviceBySigningKey } from "./device-key.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { outOfScopeMessage } from "./scope.ts";
import type { VerifiedProject } from "./sync.ts";

/**
 * ラップ受信者(受信者クラス — AUTH_SPEC §12-6)。member の識別子は user_id、
 * server の識別子はサーバー鍵 FP(HPKE info / §5.1 署名対象の recipient 位置に
 * そのまま入る — CRYPTO_SPEC §9)。
 */
export type WrapRecipient =
  | {
      readonly kind: "member";
      readonly member: ChainMember;
      /** The device the wrap is sealed to (R(E) は (人, 端末) の対 — CRYPTO_SPEC §6.2、DK K4)。 */
      readonly device: ChainDevice;
    }
  | { readonly kind: "server"; readonly grant: ServerGrant };

function recipientId(recipient: WrapRecipient): string {
  return recipient.kind === "member"
    ? recipient.member.userId
    : recipient.grant.serverKeyFingerprintHex;
}

function recipientEncPubHex(recipient: WrapRecipient): string {
  return recipient.kind === "member" ? recipient.device.encPubHex : recipient.grant.serverEncPubHex;
}

/**
 * 受信者集合 R(E) の member 側の所属述語(CRYPTO_SPEC §6.2 — 端末軸、2026-09-19 DK):
 * E ∈ 端末の実効 scope(人の scope ∩ 端末の scope — `effectivePermissionOf` が唯一の
 * 計算点)。サーバーの期待数(`expectedWrapRecipientCount`)と同じ述語(設計録 §9 K4)。
 */
export function deviceReceivesEnvironment(
  member: ChainMember,
  device: ChainDevice,
  environmentId: string,
): boolean {
  return scopeIncludesEnvironment(effectivePermissionOf(member, device).scope, environmentId);
}

/**
 * 対象環境 E のラップ完全集合の受信者 = R(E)(CRYPTO_SPEC §6.2 の 1 定義 —
 * 2026-09-15 ES K4、端末展開は 2026-09-19 DK K4): { (m, d) | m 現メンバー, d ∈
 * devices(m), E ∈ 実効 scope(m, d) } ∪ { 有効 grant g | E ∈ scope_environments(g) }。
 * 判定は受信者クラスを跨いで同じ「E ∈ scope」の述語。順序は決定論(member を
 * user_id 昇順 → 端末を FP 昇順 → server を FP 昇順)。重複除去は保存キーの粒度
 * (識別子 + enc 鍵 — サーバーの `wrapStorageKey` と同じ)。環境作成・rotate 複合・
 * CAS リトライの再利用判定(sameWrapRecipientSet)がすべてここを通る。
 * scope 外の端末宛はサーバーが 422 `scope-out-of-range` で拒否する(§12-6)。
 */
function wrapRecipientsFor(
  verified: VerifiedProject,
  environmentId: string,
): readonly WrapRecipient[] {
  const seen = new Set<string>();
  const recipients: WrapRecipient[] = [];
  const push = (recipient: WrapRecipient) => {
    const key = `${recipientId(recipient)}:${recipientEncPubHex(recipient)}`;
    if (!seen.has(key)) {
      seen.add(key);
      recipients.push(recipient);
    }
  };
  for (const member of [...verified.state.members.values()].toSorted((a, b) =>
    a.userId < b.userId ? -1 : 1,
  )) {
    for (const device of devicesOf(member)) {
      if (deviceReceivesEnvironment(member, device, environmentId)) {
        push({ kind: "member", member, device });
      }
    }
  }
  for (const grant of [...verified.state.serverGrants.values()]
    .filter((candidate) => candidate.scopeEnvironmentIds.includes(environmentId))
    .toSorted((a, b) => (a.serverKeyFingerprintHex < b.serverKeyFingerprintHex ? -1 : 1))) {
    push({ kind: "server", grant });
  }
  return recipients;
}

/**
 * ラップ完全集合の期待受信者数(通信前の自己検査 — サーバーの
 * `expectedWrapRecipientCount` と同じ述語・同じ重複除去粒度)。
 */
export function expectedWrapRecipientCount(
  verified: VerifiedProject,
  environmentId: string,
): number {
  return wrapRecipientsFor(verified, environmentId).length;
}

/** 1 ラップの生成結果(実理由コード付きのタグ付き Result — 複数原因を 1 汎用文言に潰さない)。 */
type WrapBuildResult =
  | { readonly kind: "ok"; readonly wrap: WrappedDek }
  | { readonly kind: "failed"; readonly reason: string };

export async function wrapAndSignFor(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly recipient: WrapRecipient;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Promise<WrapBuildResult> {
  const { environmentId, epoch, dek, recipient } = input;
  // 受信者識別子: member = user_id / server = サーバー鍵 FP(§9 — HPKE info と
  // §5.1 署名対象の recipient_user_id 位置に同じ値が入る)
  const id = recipientId(recipient);
  const encPubHex = recipientEncPubHex(recipient);
  const recipientKeyBytes = decodeHex(encPubHex);
  if (recipientKeyBytes === null) {
    return { kind: "failed", reason: "Cannot decode the recipient's enc public-key hex" };
  }
  const recipientKey = await importEncryptionPublicKey(recipientKeyBytes);
  if (!recipientKey.ok) {
    return { kind: "failed", reason: "Cannot load the recipient's enc public key" };
  }
  const wrapped = await wrapDek({
    recipientPublicKey: recipientKey.value,
    // 剥がす理由: HPKE ラップの入力(暗号境界)。産物はラップ済み暗号文
    dek: Redacted.value(dek),
    context: {
      projectId: input.projectId,
      environmentId,
      epoch,
      recipientUserId: id,
    },
  });
  if (!wrapped.ok) {
    return { kind: "failed", reason: "The HPKE wrap failed" };
  }
  const encHex = encodeHex(wrapped.value.enc);
  const ciphertextHex = encodeHex(wrapped.value.ciphertext);
  const signature = await signDekWrap({
    context: {
      suite: SUITE_ID,
      projectId: input.projectId,
      environmentId,
      epoch,
      recipientUserId: id,
      recipientEncPubHex: encPubHex,
      encHex,
      ciphertextHex,
      signerUserId: input.signerUserId,
    },
    signingKey: input.signingKeyPair.privateKey,
  });
  if (!signature.ok) {
    return { kind: "failed", reason: "Failed to create the registration signature" };
  }
  return {
    kind: "ok",
    wrap: {
      suite: SUITE_ID,
      epoch,
      ...(recipient.kind === "server" ? { recipientClass: "server" as const } : {}),
      recipientUserId: id,
      recipientEncPubHex: encPubHex,
      encHex,
      ciphertextHex,
      signatureHex: signature.value,
    },
  };
}

/**
 * Builds the wrap set for one epoch: exactly the verified current member set
 * plus the server keys of active grants whose scope covers the environment
 * (§6.3 / §12-4), each wrap signed by the caller (§5.1).
 * Deterministic recipient order for reproducible requests.
 */
export function buildWrapCompleteSet(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<readonly WrappedDek[], CliError> {
  return Effect.gen(function* () {
    const recipients = wrapRecipientsFor(input.verified, input.environmentId);
    const wraps: WrappedDek[] = [];
    for (const recipient of recipients) {
      // 識別子はチェーン由来の自由文字列 — 端末へ出す前に必ず中和する
      const label =
        recipient.kind === "member"
          ? `member ${displayText(recipient.member.userId)} (device ${recipient.device.keyFingerprintHex})`
          : `server key ${displayText(recipient.grant.serverKeyFingerprintHex)}`;
      const built = yield* Effect.tryPromise({
        try: () =>
          wrapAndSignFor({
            projectId: input.verified.projectId,
            environmentId: input.environmentId,
            epoch: input.epoch,
            dek: input.dek,
            recipient,
            signerUserId: input.signerUserId,
            signingKeyPair: input.signingKeyPair,
          }),
        catch: () => cliError(`DEK-wrap generation for ${label} failed (crypto error)`),
      });
      if (built.kind === "failed") {
        return yield* Effect.fail(
          cliError(`Failed to generate the DEK wrap for ${label} (${built.reason})`),
        );
      }
      wraps.push(built.wrap);
    }
    return wraps;
  });
}

/**
 * 対象環境のラップ受信者集合(メンバー + スコープ内 grant)の同一性。
 * CAS リトライでのラップ集合の再利用可否の判定(§12-4)。
 */
export function sameWrapRecipientSet(
  a: VerifiedProject,
  b: VerifiedProject,
  environmentId: string,
): boolean {
  const left = wrapRecipientsFor(a, environmentId);
  const right = wrapRecipientsFor(b, environmentId);
  if (left.length !== right.length) {
    return false;
  }
  return left.every((recipient, index) => {
    const other = right[index];
    return (
      other !== undefined &&
      recipient.kind === other.kind &&
      recipientId(recipient) === recipientId(other) &&
      recipientEncPubHex(recipient) === recipientEncPubHex(other)
    );
  });
}

/**
 * role の順序(CRYPTO_SPEC §6.2)。**否定形(`=== "reader"`)で書かない**:
 * Role に member 未満の値が増えたとき、否定形の判定は無言で素通りしてしまう。
 * `satisfies Record<Role, number>` なら、値が増えた時点でここが型エラーになる。
 */
export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } satisfies Record<
  Role,
  number
>;

/** The signing member with the device that signs and its effective permission (§3 / §6.2). */
export interface WritingMember {
  readonly member: ChainMember;
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
}

/**
 * 複合操作(環境作成・ローテーション)の共通ガード: 自分がチェーン導出の
 * 現メンバーであること・署名する端末(手元の鍵)がその人の有効な端末であること・
 * **端末の実効 role** が member 以上であること・**対象環境が端末の実効 scope に
 * 含まれる**こと(§6.2 / §6.3 — 2026-09-15 ES K4、端末の実効権限は 2026-09-19 DK
 * K4-17: create は `listed` に未存在の id が含まれえないので実効 scope = all の端末
 * だけが通る = サーバーと同じ 1 述語)。いずれも DEK 生成・HPKE ラップ・pull(=
 * `var.read` の記録)より**前**に落とすためのもので、サーバーの 403 を待たない。
 * grant_server 有効時の拒否ガードは持たない — 完全集合がサーバー鍵宛を含む
 * (buildWrapCompleteSet / §12-4)。
 *
 * 環境の存在検査(rotate)や ID の重複検査(create)は操作固有なので呼び出し側に残す。
 */
export function requireWritingMember(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly signerUserId: string;
  /** 署名する端末の鍵(実効権限の計算点 — 人の (role, scope) を検査へ直接渡さない)。 */
  readonly signingKeyPair: SigningKeyPair;
  /** メッセージに埋める操作名(例: 「ローテーション」)。 */
  readonly operation: string;
  /** 権限不足時の文言(操作ごとに具体的に書く)。 */
  readonly forbidden: string;
  /**
   * scope 外の文言(省略 = 既定の「拡大を依頼」の案内)。create は「作成は
   * scope = all のみ」と案内する(拡大の依頼は当てはまらない)。
   */
  readonly outOfScope?: string;
}): Effect.Effect<WritingMember, CliError> {
  return Effect.gen(function* () {
    const member = input.verified.state.members.get(input.signerUserId);
    if (member === undefined) {
      return yield* Effect.fail(
        cliError(`You are not a chain-derived member of this project (cannot ${input.operation})`),
      );
    }
    const device = yield* ownDeviceBySigningKey(member, input.signingKeyPair);
    const permission = effectivePermissionOf(member, device);
    if (ROLE_RANK[permission.role] < ROLE_RANK.member) {
      return yield* Effect.fail(
        cliError(
          ROLE_RANK[member.role] < ROLE_RANK.member
            ? input.forbidden
            : `${input.forbidden}. Your role is ${member.role}, but this device's key is capped at ${device.roleCap} (\`maruhi device list\`) — use a device without that cap`,
        ),
      );
    }
    if (!scopeIncludesEnvironment(permission.scope, input.environmentId)) {
      return yield* Effect.fail(
        cliError(
          input.outOfScope ??
            outOfScopeMessage({
              member,
              device,
              environmentId: input.environmentId,
              operation: input.operation,
            }),
        ),
      );
    }
    return { member, device, permission };
  });
}
