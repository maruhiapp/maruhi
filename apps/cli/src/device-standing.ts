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
      /**
       * このチェーンでその人の最初の鍵(genesis / add_member)だったことがある — 今の出所が
       * 最初の鍵か、以前の在籍の最初の鍵(`remove_member` の後の再招待で `add_device` として
       * 戻った鍵を含む — DK K14-1 1-f)。
       */
      readonly firstKey: boolean;
    }
  | {
      readonly kind: "revoked";
      /** 失効の前に、このチェーンでその人の最初の鍵だったことがある(DK K14-18)。 */
      readonly firstKey: boolean;
    }
  | {
      readonly kind: "absent";
      /** 以前の在籍で、このチェーンでその人の最初の鍵だったことがある(DK K14-18)。 */
      readonly firstKey: boolean;
    };

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
  // 失効した鍵・以前の在籍の鍵も、公開鍵は束縛の履歴(keyHistory)に残る(DK K14-18)
  const bound = (verified.keyHistory.get(userId) ?? []).find(
    (binding) => binding.keyFingerprintHex === fingerprintHex,
  );
  const firstKey = bound !== undefined && wasFirstKeyOf(verified, userId, bound);
  return revokedFingerprintsOf(verified, userId).has(fingerprintHex)
    ? { kind: "revoked", firstKey }
    : { kind: "absent", firstKey };
}

/**
 * The device's keys were the first key of `userId` in some tenure on this chain
 * (an applied genesis or `add_member` carrying them). Applied operations outlive
 * the tenure, so a key re-added with `add_device` after a re-invite still counts.
 */
function wasFirstKeyOf(
  verified: VerifiedProject,
  userId: string,
  device: { readonly encPubHex: string; readonly sigPubHex: string },
): boolean {
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
  return Effect.map(
    keyStandingsForKeys({ ...input, fingerprintsHex: [input.fingerprintHex] }),
    (byKey) => byKey.get(input.fingerprintHex) ?? { projects: [], listFailure: null },
  );
}

/**
 * The standings of several keys over one pass: each listed project is synced
 * once and the pure `keyStandingIn` is applied per key (DK K14-16 — the same
 * shape as `device list`, which lists every device over one sync).
 */
function keyStandingsForKeys(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintsHex: readonly string[];
}): Effect.Effect<ReadonlyMap<string, KeyStandings>, never, CliServices> {
  return Effect.gen(function* () {
    const fingerprints = [...new Set(input.fingerprintsHex)];
    const listed = yield* Effect.result(fetchProjectMemberships(input.client));
    if (Result.isFailure(listed)) {
      const failed: KeyStandings = { projects: [], listFailure: listed.failure.message };
      return new Map(fingerprints.map((fp) => [fp, failed]));
    }
    const projectIds = listed.success.map((row) => row.projectId).toSorted(compareCodePoints);
    const byKey = new Map(fingerprints.map((fp) => [fp, [] as KeyStandings["projects"][number][]]));
    for (const projectId of projectIds) {
      const synced = yield* Effect.result(
        openMetadataProject({ server: input.session.origin, project: projectId }),
      );
      for (const fp of fingerprints) {
        byKey.get(fp)?.push({ projectId, standing: standingFrom(synced, input.session, fp) });
      }
    }
    return new Map(
      [...byKey].map(([fp, projects]) => [fp, { projects, listFailure: null } as KeyStandings]),
    );
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
  /**
   * どの立場であれ(有効・失効・無い)、この鍵がその人の最初の鍵だった(ことがある)プロジェクト
   * (DK K14-18 — 台帳の鍵の判定が読む。`device add` の 2 択は有効な立場の `firstKey` だけを読む)。
   */
  readonly firstKeyProjects: readonly string[];
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
    firstKeyProjects: [] as string[],
    unsynced: [] as StandingGroups["unsynced"][number][],
  };
  for (const { projectId, standing } of standings.projects) {
    if (standing.kind !== "unsynced" && standing.firstKey) {
      groups.firstKeyProjects.push(projectId);
    }
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
 * `add_member`)になる。上から順に最初に当たるもの: どこか 1 つでも最初の鍵(失効・無いの立場の
 * 以前の最初の鍵を含む — K14-18)→ `first-key`
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
  if (groups.firstKeyProjects.length > 0) {
    return { kind: "first-key", projectIds: groups.firstKeyProjects };
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

/** 台帳の鍵の判定と、その材料(群・確かめられなかった範囲)。 */
export interface LedgerKeyCheck {
  readonly verdict: ReserveVerdict;
  readonly groups: StandingGroups;
  /** 判定の値に依らない「確かめられなかった範囲」(null = 全部確かめた — 失効の門が読む。K14-14)。 */
  readonly unchecked: Extract<ReserveVerdict, { readonly kind: "unchecked" }> | null;
}

/** 1 つの鍵の立場から、台帳の鍵の判定を作る(純関数)。 */
function ledgerKeyCheckFrom(standings: KeyStandings): LedgerKeyCheck {
  const groups = groupStandings(standings);
  const unchecked =
    groups.unsynced.length > 0 || standings.listFailure !== null
      ? {
          kind: "unchecked" as const,
          projectIds: groups.unsynced.map((entry) => entry.projectId),
          listFailure: standings.listFailure,
        }
      : null;
  return { verdict: reserveVerdictOf(groups, standings.listFailure), groups, unchecked };
}

/**
 * 台帳の鍵(と失効させる旧予備鍵)の判定を、サーバーが一覧に出す全プロジェクトを 1 回ずつ
 * 同期して行う(DK K14-4 4-f / K14-16 — `key recovery`・台帳の変更の前段・失効の門が共有する
 * 入口)。`key recover` は登録のために開いたチェーンに `reserveVerdictOf` を直接当てる。
 */
export function ledgerKeyChecksOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintsHex: readonly string[];
}): Effect.Effect<ReadonlyMap<string, LedgerKeyCheck>, never, CliServices> {
  return Effect.map(
    keyStandingsForKeys(input),
    (byKey) => new Map([...byKey].map(([fp, standings]) => [fp, ledgerKeyCheckFrom(standings)])),
  );
}

/** 1 つの鍵の `ledgerKeyChecksOf`。 */
export function ledgerKeyVerdictOf(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  readonly fingerprintHex: string;
}): Effect.Effect<LedgerKeyCheck, never, CliServices> {
  return Effect.map(
    ledgerKeyChecksOf({ ...input, fingerprintsHex: [input.fingerprintHex] }),
    (checks) =>
      checks.get(input.fingerprintHex) ?? ledgerKeyCheckFrom({ projects: [], listFailure: null }),
  );
}
