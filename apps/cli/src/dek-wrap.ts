// エポック DEK のラップ完全集合の生成(CRYPTO_SPEC §5 / §5.1 / §6.3、
// AUTH_SPEC §12-4 / §12-6)。
//
// 複合リクエスト(環境作成 = エポック 1、ローテーション = 新エポック)が同梱する
// 「ラップ完全集合」を、検証済み ChainState の現メンバー集合と厳密一致させて
// 生成する共有実装。ラップ先一致検査(§6.3 のゴーストメンバー対策)のクライアント
// 側が本線であり、サーバーの §12-6 検証は補助線(session-07 §5)。
//
// ラップ生成 → signDekWrap → 登録は一続きで行う(署名者 = 呼び出し主体 —
// §5.1 / session-10 §5)。CAS リトライでの作り直しは、再同期で現メンバー集合が
// 変わった場合のみ(§12-4 — HPKE Seal はランダムなので不要な再ラップを避ける)。

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainMember, Role, SigningKeyPair } from "@maruhi/crypto";
import {
  decodeHex,
  encodeHex,
  importEncryptionPublicKey,
  signDekWrap,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { VerifiedProject } from "./sync.ts";

/** 1 ラップの生成結果(実理由コード付きのタグ付き Result — 複数原因を 1 汎用文言に潰さない)。 */
type WrapBuildResult =
  | { readonly kind: "ok"; readonly wrap: WrappedDek }
  | { readonly kind: "failed"; readonly reason: string };

async function wrapAndSignFor(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly member: ChainMember;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}): Promise<WrapBuildResult> {
  const { verified, environmentId, epoch, dek, member } = input;
  const recipientKeyBytes = decodeHex(member.encPubHex);
  if (recipientKeyBytes === null) {
    return { kind: "failed", reason: "受信者の enc 公開鍵 hex を復号できません" };
  }
  const recipientKey = await importEncryptionPublicKey(recipientKeyBytes);
  if (!recipientKey.ok) {
    return { kind: "failed", reason: "受信者の enc 公開鍵を読み込めません" };
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
    return { kind: "failed", reason: "HPKE ラップに失敗しました" };
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
    return { kind: "failed", reason: "登録署名の作成に失敗しました" };
  }
  return {
    kind: "ok",
    wrap: {
      suite: SUITE_ID,
      epoch,
      recipientUserId: member.userId,
      recipientEncPubHex: member.encPubHex,
      encHex,
      ciphertextHex,
      signatureHex: signature.value,
    },
  };
}

/**
 * Builds the wrap set for one epoch: exactly the verified current member set
 * (§6.3), each wrap signed by the caller (§5.1). Deterministic recipient
 * order (userId ascending) for reproducible requests.
 */
export function buildWrapSetForMembers(input: {
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
      // user_id はチェーン由来の自由文字列 — 端末へ出す前に必ず中和する
      const built = yield* Effect.tryPromise({
        try: () => wrapAndSignFor({ ...input, member }),
        catch: () =>
          cliError(
            `メンバー ${displayText(member.userId)} 宛の DEK ラップ生成が失敗しました(暗号処理エラー)`,
          ),
      });
      if (built.kind === "failed") {
        return yield* Effect.fail(
          cliError(
            `メンバー ${displayText(member.userId)} 宛の DEK ラップ生成に失敗しました(${built.reason})`,
          ),
        );
      }
      wraps.push(built.wrap);
    }
    return wraps;
  });
}

/** 現メンバー集合(user_id → enc 公開鍵)の同一性。ラップ集合の再利用可否の判定。 */
export function sameMemberSet(a: VerifiedProject, b: VerifiedProject): boolean {
  if (a.state.members.size !== b.state.members.size) {
    return false;
  }
  for (const [userId, member] of a.state.members) {
    if (b.state.members.get(userId)?.encPubHex !== member.encPubHex) {
      return false;
    }
  }
  return true;
}

/**
 * role の順序(CRYPTO_SPEC §6.2)。**否定形(`=== "reader"`)で書かない**:
 * Role に member 未満の値が増えたとき、否定形の判定は無言で素通りしてしまう。
 * `satisfies Record<Role, number>` なら、値が増えた時点でここが型エラーになる。
 */
const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } satisfies Record<Role, number>;

/**
 * 複合操作(環境作成・ローテーション)の共通ガード: grant_server の開示スコープ・
 * 自分がチェーン導出の現メンバーであること・role が **member 以上**であること
 * (§6.2)。いずれも DEK 生成・HPKE ラップ・pull(= `var.read` の記録)より
 * **前**に落とすためのもので、サーバーの汎用 403 を待たない。
 *
 * 環境の存在検査(rotate)や ID の重複検査(create)は操作固有なので呼び出し側に残す。
 */
export function requireWritingMember(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly signerUserId: string;
  /** メッセージに埋める操作名(例: 「ローテーション」)。 */
  readonly operation: string;
  /** 権限不足時の文言(操作ごとに具体的に書く)。 */
  readonly forbidden: string;
}): Effect.Effect<ChainMember, CliError> {
  return Effect.gen(function* () {
    yield* ensureNoServerGrant(input.verified, input.environmentId, input.operation);
    const member = input.verified.state.members.get(input.signerUserId);
    if (member === undefined) {
      return yield* Effect.fail(
        cliError(
          `このプロジェクトのチェーン導出メンバーではありません(${input.operation}を行えません)`,
        ),
      );
    }
    if (ROLE_RANK[member.role] < ROLE_RANK.member) {
      return yield* Effect.fail(cliError(input.forbidden));
    }
    return member;
  });
}

/**
 * **対象環境が** grant_server のスコープに入っている場合に複合操作を拒否する。
 * サーバー宛ラップのデータプレーンは Phase 2 未実装で、メンバー宛のみの完全集合は
 * §7 / §12-4 の開示契約(サーバー鍵への再ラップ義務)を黙って破ることになるため。
 *
 * 判定は grant ごとのスコープ(§6.2 の「対象環境の部分集合」)で行う: エポックは
 * 環境ごとに独立に進む(§3)ので、dev だけを開示した grant が prod の失効
 * ローテーション(§7)を止めてよい理由はない — 止めれば、退職者の削除に必要な
 * 唯一の手段が別環境の設定によって塞がれる。
 *
 * スコープが空の grant は「対象なし」とも「全環境」とも読めるが §6.2 は意味を
 * 定めていないため、保守的に全環境扱い(= 拒否)とする。
 */
function ensureNoServerGrant(
  verified: VerifiedProject,
  environmentId: string,
  operation: string,
): Effect.Effect<void, CliError> {
  const covering = [...verified.state.serverGrants.values()].some(
    (grant) =>
      grant.scopeEnvironmentIds.length === 0 || grant.scopeEnvironmentIds.includes(environmentId),
  );
  if (covering) {
    return Effect.fail(
      cliError(
        `環境 ${displayText(environmentId)} は grant_server の開示スコープに含まれています。サーバー宛 DEK ラップは Phase 2 未実装のため、CLI からの${operation}は行えません — 失効(§7)のために今すぐローテーションが必要な場合は、先に revoke_server でサーバーへの開示を取り消してください`,
      ),
    );
  }
  return Effect.void;
}
