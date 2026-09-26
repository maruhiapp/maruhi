// 端末鍵のチェーン上の立場(DK K13-1 — 設計録 dk-design.md §18)。
//
// 「この鍵はこのプロジェクトで何か」という問いを 1 か所で答える: 有効(出所つき —
// `add_device` で足された / その人の最初の鍵)・失効(自分宛の適用済み `revoke_device` の
// 対象)・無い・同期できず。`device add`(既存の鍵の分岐・完了の確認・期限切れ・`--replace`
// の表示)と `device list` と `ownDeviceOrFail`(失効の分岐)が同じ述語を使う。
//
// 純関数 `keyStandingIn` は既に検証したチェーンに当てるだけ(`device list` と `key recover`
// の登録は同期を二重にしない)。`keyStandingsOf` はプロジェクト一覧(サーバー申告 — 発見用)の各プロジェクトを
// 鍵なしの前段で同期して純関数を呼び、一覧・同期の失敗はコマンドを落とさず事実に畳む
// (改ざんの兆候は `evidence` で運ぶ)。文言は作らない(報告側が作る — K12-10)。

import type { ChainDevice, ChainMember } from "@maruhi/crypto";
import { Effect, Result } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type CliServices, openMetadataProject, type ProjectContextBase } from "./context.ts";
import { deviceProvenanceOf, revokedFingerprintsOf } from "./device-key.ts";
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
      /**
       * このチェーンでその人の最初の鍵(genesis / add_member)だったことがある — 今の出所が
       * 最初の鍵か、以前の在籍の最初の鍵(`remove_member` の後の再招待で `add_device` として
       * 戻った鍵を含む — DK K14-1 1-f)。
       */
      readonly firstKey: boolean;
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
    const provenance = deviceProvenanceOf(verified, userId, device);
    const firstKey =
      provenance.addedByFingerprintHex === null || wasFirstKeyOf(verified, userId, device);
    return { kind: "active", member, device, firstKey };
  }
  return revokedFingerprintsOf(verified, userId).has(fingerprintHex)
    ? { kind: "revoked" }
    : { kind: "absent" };
}

/**
 * The device's keys were the first key of `userId` in some tenure on this chain
 * (an applied genesis or `add_member` carrying them). Applied operations outlive
 * the tenure, so a key re-added with `add_device` after a re-invite still counts.
 */
function wasFirstKeyOf(verified: VerifiedProject, userId: string, device: ChainDevice): boolean {
  const carries = (keys: { readonly encPubHex: string; readonly sigPubHex: string }) =>
    keys.encPubHex === device.encPubHex && keys.sigPubHex === device.sigPubHex;
  return verified.applied.some(({ operation, actorUserId }) => {
    if (operation.op === "genesis") {
      return actorUserId === userId && carries(operation.payload);
    }
    return (
      operation.op === "add_member" &&
      operation.payload.targetUserId === userId &&
      carries(operation.payload)
    );
  });
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
  return openMetadataProject({ server: input.session.origin, project: input.projectId }).pipe(
    Effect.map((context): KeyStanding => {
      const standing = keyStandingIn(context.verified, input.session.userId, input.fingerprintHex);
      return standing.kind === "active" ? { ...standing, context } : standing;
    }),
    Effect.catch((error) =>
      Effect.succeed<KeyStanding>({
        kind: "unsynced",
        message: error.message,
        evidence: error.evidence === true,
      }),
    ),
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
      projects.push({
        projectId,
        standing: yield* keyStandingOnProject({
          session: input.session,
          projectId,
          fingerprintHex: input.fingerprintHex,
        }),
      });
    }
    return { projects, listFailure: null };
  });
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
 * 台帳から開いた鍵が予備鍵として働くかの判定(DK K14-2 — 設計録 §19)。予備鍵は必ず
 * `add_device` で載り(K4-30)、DK 以前の端末鍵の複製はその人の最初の鍵(genesis /
 * `add_member`)になる。上から順に最初に当たるもの: どこか 1 つでも最初の鍵 → `first-key`
 * (同期できないプロジェクトがあっても — 正の事実 1 つで足りる)/ どこかで失効 → `revoked` /
 * 同期できないプロジェクトがある・一覧が取れない → `unchecked` / どこにも有効でない →
 * `nowhere` / 有効な所がすべて `add_device` 出所 → `added`(予備鍵と記録してよいのは
 * これだけ)。文言は作らない(報告側 — K12-10)。
 */
export type ReserveVerdict =
  | { readonly kind: "first-key"; readonly projectIds: readonly string[] }
  | {
      readonly kind: "revoked";
      readonly projectIds: readonly string[];
      /** 失効していないプロジェクト(まだ有効に載っている所)。 */
      readonly activeProjectIds: readonly string[];
    }
  | {
      readonly kind: "unchecked";
      readonly projectIds: readonly string[];
      /** プロジェクト一覧の取得の失敗(null = 取れた)。 */
      readonly listFailure: string | null;
    }
  | { readonly kind: "nowhere" }
  | { readonly kind: "added"; readonly projectIds: readonly string[] };

export function reserveVerdictOf(
  groups: StandingGroups,
  listFailure: string | null,
): ReserveVerdict {
  const firstKey = groups.active.filter((entry) => entry.standing.firstKey);
  if (firstKey.length > 0) {
    return { kind: "first-key", projectIds: firstKey.map((entry) => entry.projectId) };
  }
  const activeProjectIds = groups.active.map((entry) => entry.projectId);
  if (groups.revoked.length > 0) {
    return { kind: "revoked", projectIds: groups.revoked, activeProjectIds };
  }
  if (groups.unsynced.length > 0 || listFailure !== null) {
    return {
      kind: "unchecked",
      projectIds: groups.unsynced.map((entry) => entry.projectId),
      listFailure,
    };
  }
  if (activeProjectIds.length === 0) {
    return { kind: "nowhere" };
  }
  return { kind: "added", projectIds: activeProjectIds };
}

/**
 * 台帳から開いた鍵の判定を、サーバーが一覧に出す全プロジェクトを同期して行う(DK K14-4 4-f —
 * `key recovery` と台帳の変更の前段〔`openLedgerReserveForChange`〕が共有する入口)。
 * `key recover` は登録のために開いたチェーンに `reserveVerdictOf` を直接当てる(同期を二重に
 * しない)。群は誤った記録を直す材料(`retractReserveRecord`)として返す。
 */
export function ledgerKeyVerdictOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<
  { readonly verdict: ReserveVerdict; readonly groups: StandingGroups },
  never,
  CliServices
> {
  return Effect.map(keyStandingsOf(input), (standings) => {
    const groups = groupStandings(standings);
    return { verdict: reserveVerdictOf(groups, standings.listFailure), groups };
  });
}
