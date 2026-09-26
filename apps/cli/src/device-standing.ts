// 端末鍵のチェーン上の立場(DK K13-1 — 設計録 dk-design.md §18)。
//
// 「この鍵はこのプロジェクトで何か」という問いを 1 か所で答える: 有効・失効(自分宛の適用済み `revoke_device` の
// 対象)・無い・同期できず。`device add`(既存の鍵の分岐・完了の確認・期限切れ・`--replace`
// の表示)と `device list` と `ownDeviceOrFail`(失効の分岐)が同じ述語を使う。
//
// 純関数 `keyStandingIn` は既に検証したチェーンに当てるだけ(`device list` と `key recover`
// の登録は同期を二重にしない)。`keyStandingsOf` はプロジェクト一覧(サーバー申告 — 発見用)の各プロジェクトを
// 鍵なしの前段で同期して純関数を呼び、一覧・同期の失敗はコマンドを落とさず事実に畳む
// (改ざんの兆候は `evidence` で運ぶ)。文言は作らない(報告側が作る — K12-10)。
//
// 台帳の鍵が予備鍵かは、台帳の中身の予備鍵の印で決まる(CRYPTO_SPEC §8 — DK K16)。チェーンが
// 台帳の鍵について言うのは「失効しているか」だけ(`ledgerKeyVerdictOf`)。

import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Effect, Result } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type CliServices, openMetadataProject, type ProjectContextBase } from "./context.ts";
import { revokedFingerprintsOf } from "./device-key.ts";
import type { CliError } from "./errors.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { compareCodePoints } from "./scope.ts";
import type { CliSession } from "./session.ts";
import type { VerifiedProject } from "./sync.ts";

/** 検証済みチェーンの上での鍵の立場(同期の成否を含まない)。 */
export type ChainKeyStanding =
  | {
      readonly kind: "active";
      readonly member: ChainMember;
      readonly device: ChainDevice;
    }
  | { readonly kind: "revoked" }
  | { readonly kind: "absent" };

/**
 * The standing of `fingerprintHex` for `userId` on one verified chain. A key that
 * is active wins over an earlier revocation (it can only be active again as a
 * new registration, which the chain would show).
 */
export function keyStandingIn(
  verified: VerifiedProject,
  userId: string,
  fingerprintHex: string,
): ChainKeyStanding {
  const member = verified.state.members.get(userId);
  const device = member?.devices.get(fingerprintHex);
  if (member !== undefined && device !== undefined) {
    return { kind: "active", member, device };
  }
  return revokedFingerprintsOf(verified, userId).has(fingerprintHex)
    ? { kind: "revoked" }
    : { kind: "absent" };
}

/** 1 プロジェクトの立場(同期できなければその事実 — 「無い」と混同しない)。 */
export type KeyStanding =
  | (Extract<ChainKeyStanding, { readonly kind: "active" }> & {
      readonly context: ProjectContextBase;
    })
  | Exclude<ChainKeyStanding, { readonly kind: "active" }>
  | {
      readonly kind: "unsynced";
      readonly message: string;
      /** 署名済みデータの矛盾(チェーンの検証失敗など — 改ざんの兆候)。 */
      readonly evidence: boolean;
    };

/** Syncs one project (the keyless front half) and derives the key's standing on it. */
export function keyStandingOnProject(input: {
  readonly session: CliSession;
  readonly projectId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<KeyStanding, never, CliServices> {
  return Effect.map(
    Effect.result(openMetadataProject({ server: input.session.origin, project: input.projectId })),
    (synced) => standingFrom(synced, input.session, input.fingerprintHex),
  );
}

/** 一覧の全プロジェクトでの立場(一覧が取れなければ `listFailure`)。 */
export interface KeyStandings {
  readonly projects: readonly { readonly projectId: string; readonly standing: KeyStanding }[];
  /** プロジェクト一覧の取得の失敗(null = 取れた)。取れなければ `projects` は空。 */
  readonly listFailure: string | null;
}

/**
 * The key's standing on every project the server lists for the caller (server-
 * reported — discovery only). Never fails: a list failure and each sync failure
 * are carried as facts.
 */
export function keyStandingsOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<KeyStandings, never, CliServices> {
  return Effect.gen(function* () {
    const listed = yield* Effect.result(fetchProjectMemberships(input.client));
    if (Result.isFailure(listed)) {
      return { projects: [], listFailure: listed.failure.message };
    }
    const projectIds = listed.success.map((row) => row.projectId).toSorted(compareCodePoints);
    const projects: KeyStandings["projects"][number][] = [];
    for (const projectId of projectIds) {
      const synced = yield* Effect.result(
        openMetadataProject({ server: input.session.origin, project: projectId }),
      );
      projects.push({
        projectId,
        standing: standingFrom(synced, input.session, input.fingerprintHex),
      });
    }
    return { projects, listFailure: null };
  });
}

/** 1 回の同期の結果(成功 / 失敗)から、1 つの鍵の立場を出す(同期できなければその事実)。 */
function standingFrom(
  synced: Result.Result<ProjectContextBase, CliError>,
  session: CliSession,
  fingerprintHex: string,
): KeyStanding {
  if (Result.isFailure(synced)) {
    return {
      kind: "unsynced",
      message: synced.failure.message,
      evidence: synced.failure.evidence === true,
    };
  }
  const context = synced.success;
  const standing = keyStandingIn(context.verified, session.userId, fingerprintHex);
  return standing.kind === "active" ? { ...standing, context } : standing;
}

/** 立場ごとのプロジェクト(報告・分岐の材料)。 */
export interface StandingGroups {
  readonly active: readonly {
    readonly projectId: string;
    readonly standing: Extract<KeyStanding, { readonly kind: "active" }>;
  }[];
  readonly revoked: readonly string[];
  readonly absent: readonly string[];
  readonly unsynced: readonly {
    readonly projectId: string;
    readonly message: string;
    readonly evidence: boolean;
  }[];
}

export function groupStandings(standings: KeyStandings): StandingGroups {
  const groups = {
    active: [] as StandingGroups["active"][number][],
    revoked: [] as string[],
    absent: [] as string[],
    unsynced: [] as StandingGroups["unsynced"][number][],
  };
  for (const { projectId, standing } of standings.projects) {
    if (standing.kind === "active") {
      groups.active.push({ projectId, standing });
    } else if (standing.kind === "unsynced") {
      groups.unsynced.push({ projectId, message: standing.message, evidence: standing.evidence });
    } else {
      groups[standing.kind].push(projectId);
    }
  }
  return groups;
}

/**
 * 台帳から開いた鍵の、チェーンが言う事実(DK K16): 予備鍵かどうかは台帳の中身の印で決まり
 * (CRYPTO_SPEC §8)、チェーンが言うのは「どこかで失効しているか」だけ。失効した予備鍵は台帳の鍵と
 * して働かない(利用者が `device revoke` で予備鍵を失効させた場合)。文言は作らない(K12-10)。
 */
export type ReserveVerdict =
  | {
      readonly kind: "revoked";
      readonly projectIds: readonly string[];
      /** 失効していないプロジェクト(まだ有効に載っている所)。 */
      readonly activeProjectIds: readonly string[];
    }
  | { readonly kind: "usable" };

export function reserveVerdictOf(groups: StandingGroups): ReserveVerdict {
  return groups.revoked.length > 0
    ? {
        kind: "revoked",
        projectIds: groups.revoked,
        activeProjectIds: groups.active.map((entry) => entry.projectId),
      }
    : { kind: "usable" };
}

/**
 * 台帳の鍵がどこかで失効しているかを、サーバーが一覧に出す全プロジェクトを同期して確かめる
 * (`key recovery`・台帳の変更の前段)。`key recover` は登録のために開いたチェーンに
 * `reserveVerdictOf` を直接当てる(同期を二重にしない)。
 */
export function ledgerKeyVerdictOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<ReserveVerdict, never, CliServices> {
  return Effect.map(keyStandingsOf(input), (standings) =>
    reserveVerdictOf(groupStandings(standings)),
  );
}
