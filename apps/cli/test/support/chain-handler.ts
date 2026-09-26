// チェーン配布(全長)と自分宛 DEK のモックハンドラ。meta-server.ts / value-env.ts
// が共有する。追記できるプロジェクト(`appendableProjectHandlers`)は device.test.ts と
// 復元の経路のテスト(passkey / handoff — DK K14)が共有する。

import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";

import type { BuiltChain, WireRecipientDek } from "./crypto.ts";
import { type MockHandler, onRequest } from "./server.ts";

/** `GET /projects/:id/environments/:env/deks` に自分宛ラップを返す。 */
export function deksHandlerOf(
  projectId: string,
  environmentId: string,
  deks: readonly WireRecipientDek[],
): MockHandler {
  const path = `/projects/${projectId}/environments/${environmentId}/deks`;
  return (request) =>
    request.method === "GET" && request.path === path ? { status: 200, json: { deks } } : null;
}

/** `GET /projects/:id/chain` に組み立て済みチェーンをそのまま返す。 */
export function chainHandlerOf(chain: BuiltChain): MockHandler {
  return (request) =>
    request.method === "GET" && request.path === `/projects/${chain.projectId}/chain`
      ? {
          status: 200,
          json: {
            projectId: chain.projectId,
            entries: chain.entries,
            headSeq: chain.entries.length,
            headHashHex: chain.hashes[chain.hashes.length - 1],
          },
        }
      : null;
}

/** 追記を反映したチェーンの `GET /projects/:id/chain` の応答。 */
export function servedChainResponse(
  projectId: string,
  entries: readonly ChainEntry[],
  hashes: readonly string[],
): { readonly status: 200; readonly json: unknown } {
  return {
    status: 200,
    json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
  };
}

/** 追記を受理して列とハッシュを伸ばし、新しいヘッドの応答を返す。 */
export async function acceptAppendedEntry(
  projectId: string,
  entries: ChainEntry[],
  hashes: string[],
  entry: ChainEntry,
): Promise<{ readonly status: 200; readonly json: unknown }> {
  entries.push(entry);
  hashes.push(await computeChainEntryHash(entry));
  return {
    status: 200,
    json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
  };
}

/**
 * 追記できるプロジェクト: チェーンの GET(追記を反映)・追記の POST・空の環境一覧。
 * `onAppend` は受理したエントリを呼び出し順に受け取る。
 */
export function appendableProjectHandlers(
  built: BuiltChain,
  onAppend: (entry: ChainEntry) => void = () => undefined,
): MockHandler[] {
  const { projectId } = built;
  const entries: ChainEntry[] = [...built.entries];
  const hashes: string[] = [...built.hashes];
  return [
    onRequest("GET", `/projects/${projectId}/chain`, () =>
      servedChainResponse(projectId, entries, hashes),
    ),
    (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as { readonly entry: ChainEntry };
      onAppend(body.entry);
      return acceptAppendedEntry(projectId, entries, hashes, body.entry);
    },
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: { environments: [] },
    })),
  ];
}

/** `GET /projects`(AUTH_SPEC §11-5)— 組み立て済みチェーンのプロジェクトを owner として列挙する。 */
export function projectListHandlerOf(projects: readonly BuiltChain[]): MockHandler {
  return onRequest("GET", "/projects", () => ({
    status: 200,
    json: { projects: projects.map((built) => ({ projectId: built.projectId, role: "owner" })) },
  }));
}
