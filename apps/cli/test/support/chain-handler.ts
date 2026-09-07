// チェーン配布(全長)と自分宛 DEK のモックハンドラ。meta-server.ts / value-env.ts
// が共有する。

import type { BuiltChain, WireRecipientDek } from "./crypto.ts";
import type { MockHandler } from "./server.ts";

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
