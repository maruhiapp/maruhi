// メタ操作(宣言作成・activation・削除)を受理して状態を進める、テスト用の
// 「正直なインメモリ環境」ハンドラ群。schema import(複数変数の直列登録 —
// O(N) 往復の固定)と var rm(tombstone への遷移と 1-E′ 確認)のテストが、
// 受理のたびに echo の base を手で組み替えずに済むようにする。
//
// 受理はクライアントが署名したステートメント・マニフェストをそのまま保存して
// author / issuer 情報(所有者)を付けて配布する — 検証(§6.3)はクライアント
// 側の実装が行う(このモックは wire 形の整合だけを保つ)。

import {
  type BuiltChain,
  headOf,
  manifestFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
} from "./crypto.ts";
import type { MockHandler, MockRequest } from "./server.ts";

/** モックが進める環境状態(検査用に公開)。 */
export interface MetaEnvironmentState {
  variables: WireDistributedVariableStatement[];
  tombstones: WireDistributedVariableStatement[];
  /** 受理済みの最新マニフェスト(null = まだ初期形を配る)。 */
  manifest: WireDistributedManifest | null;
  /** 受理したメタ操作リクエスト(検査用 — 種別つき)。 */
  mutations: { kind: "create" | "activate" | "remove"; request: MockRequest }[];
}

export interface MetaEnvironmentServerInput {
  readonly chain: BuiltChain;
  readonly owner: TestUser;
  readonly environmentId: string;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly initialVariables?: readonly WireDistributedVariableStatement[];
  readonly initialTombstones?: readonly WireDistributedVariableStatement[];
  /** 自分宛 DEK ラップ(activation の値 push に要る。省略 = deks 未配線)。 */
  readonly wrap?: WireRecipientDek;
  readonly schemaPolicy?: "disabled" | "enabled" | "locked";
  /** 削除(DELETE)を受理しても状態を進めない(1-E′ の失敗経路の再現用)。 */
  readonly ignoreRemovals?: boolean;
}

interface MutationBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value?: unknown;
  readonly manifest: WireDistributedManifest;
}

/** author / issuer 情報を付けた配布形へ写す(受理時のサーバー挙動の再現)。 */
function distributed<T>(record: T, owner: TestUser, kind: "author" | "issuer"): T {
  return {
    ...record,
    [`${kind}UserId`]: owner.userId,
    [`${kind}KeyFingerprintHex`]: owner.fingerprintHex,
  };
}

/**
 * Builds a stateful mock environment: metadata pulls reflect every accepted
 * create / activate / remove composite, so multi-variable serial flows
 * (schema import) and deletion confirmation (var rm) verify end to end.
 */
export function makeMetaEnvironmentServer(input: MetaEnvironmentServerInput): {
  readonly state: MetaEnvironmentState;
  readonly handlers: readonly MockHandler[];
} {
  const state: MetaEnvironmentState = {
    variables: [...(input.initialVariables ?? [])],
    tombstones: [...(input.initialTombstones ?? [])],
    manifest: null,
    mutations: [],
  };
  const base = `/projects/${input.chain.projectId}/environments/${input.environmentId}`;
  const activatePattern = new RegExp(`^${base}/variables/([^/]+)/activate$`);
  const removePattern = new RegExp(`^${base}/variables/([^/]+)$`);

  const acceptStatement = (body: MutationBody): void => {
    const accepted = distributed(body.statement, input.owner, "author");
    state.variables = [
      ...state.variables.filter((entry) => entry.variableId !== accepted.variableId),
      accepted,
    ];
    state.manifest = distributed(body.manifest, input.owner, "issuer");
  };

  const handlers: MockHandler[] = [
    // チェーン配布(全長)
    (request) =>
      request.method === "GET" && request.path === `/projects/${input.chain.projectId}/chain`
        ? {
            status: 200,
            json: {
              projectId: input.chain.projectId,
              entries: input.chain.entries,
              headSeq: input.chain.entries.length,
              headHashHex: input.chain.hashes[input.chain.hashes.length - 1],
            },
          }
        : null,
    // 自分宛 DEK(activation の値 push)
    (request) =>
      input.wrap !== undefined && request.method === "GET" && request.path === `${base}/deks`
        ? { status: 200, json: { deks: [input.wrap] } }
        : null,
    // メタデータのみ pull(§12-7 — declared は variables に混在)
    async (request) => {
      if (request.method !== "GET" || request.path !== `${base}/pull/metadata`) {
        return null;
      }
      const manifest =
        state.manifest ??
        (await manifestFor({
          projectId: input.chain.projectId,
          environmentId: input.environmentId,
          epoch: 1,
          issuer: input.owner,
          head: headOf(input.chain, input.chain.entries.length),
          envStatement: input.envStatement,
          statements: [...state.variables, ...state.tombstones],
        }));
      return {
        status: 200,
        json: {
          environmentId: input.environmentId,
          currentEpoch: 1,
          statement: input.envStatement,
          variables: state.variables,
          deletedVariables: state.tombstones,
          manifest,
          ...(input.schemaPolicy === undefined ? {} : { schemaPolicy: input.schemaPolicy }),
        },
      };
    },
    // 変数作成(値同梱 / declared — §12-5)
    (request) => {
      if (request.method !== "POST" || request.path !== `${base}/variables`) {
        return null;
      }
      state.mutations.push({ kind: "create", request });
      const body = request.body as MutationBody;
      acceptStatement(body);
      return {
        status: 200,
        json: {
          variableId: body.statement.variableId,
          version: body.value === undefined ? 0 : 1,
          epoch: 1,
        },
      };
    },
    // activation(declared → active — §12-5)
    (request) => {
      const match = request.path.match(activatePattern);
      if (request.method !== "POST" || match === null) {
        return null;
      }
      state.mutations.push({ kind: "activate", request });
      const body = request.body as MutationBody;
      acceptStatement(body);
      return { status: 200, json: { variableId: match[1], version: 1, epoch: 1 } };
    },
    // 削除(tombstone への遷移 — §12-5)
    (request) => {
      const match = request.path.match(removePattern);
      if (request.method !== "DELETE" || match === null) {
        return null;
      }
      state.mutations.push({ kind: "remove", request });
      if (input.ignoreRemovals !== true) {
        const body = request.body as MutationBody;
        const accepted = distributed(body.statement, input.owner, "author");
        state.variables = state.variables.filter(
          (entry) => entry.variableId !== accepted.variableId,
        );
        state.tombstones = [
          ...state.tombstones.filter((entry) => entry.variableId !== accepted.variableId),
          accepted,
        ];
        state.manifest = distributed(body.manifest, input.owner, "issuer");
      }
      return { status: 204, bodyText: "" };
    },
  ];
  return { state, handlers };
}
