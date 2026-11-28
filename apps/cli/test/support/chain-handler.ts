import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";
import type { BuiltChain, WireRecipientDek } from "@maruhi/test-kit";
import type { ApiReply, ApiSuccess } from "@maruhi/test-kit/api";

import { type EndpointAnswer, type MockHandler, onEndpoint } from "./server.ts";

export function deksHandlerOf(
  projectId: string,
  environmentId: string,
  deks: readonly WireRecipientDek[],
): MockHandler {
  return onEndpoint("deks.listMine", { projectId, environmentId }, () => ({
    status: 200,
    json: { deks },
  }));
}

export function chainHandlerOf(chain: BuiltChain): MockHandler {
  return onEndpoint("membership.get", { projectId: chain.projectId }, () =>
    servedChainResponse(chain.projectId, chain.entries, chain.hashes),
  );
}

export function lastHashOf(hashes: readonly string[]): string {
  const hashHex = hashes[hashes.length - 1];
  if (hashHex === undefined) {
    throw new Error("lastHashOf: the chain has no entries");
  }
  return hashHex;
}

export function servedChain(
  projectId: string,
  entries: readonly ChainEntry[],
  hashes: readonly string[],
): ApiSuccess<"membership.get"> {
  return {
    projectId,
    entries,
    headSeq: entries.length,
    headHashHex: lastHashOf(hashes),
    attestations: [],
  };
}

export function servedChainResponse(
  projectId: string,
  entries: readonly ChainEntry[],
  hashes: readonly string[],
): ApiReply<"membership.get"> {
  return { status: 200, json: servedChain(projectId, entries, hashes) };
}

export async function acceptAppendedEntry(
  projectId: string,
  entries: ChainEntry[],
  hashes: string[],
  entry: ChainEntry,
): Promise<ApiReply<"membership.append">> {
  entries.push(entry);
  hashes.push(await computeChainEntryHash(entry));
  return {
    status: 200,
    json: { projectId, headSeq: entries.length, headHashHex: lastHashOf(hashes) },
  };
}

export type AppendAnswer = EndpointAnswer<"membership.append">;

export interface AppendInjection<Answer = AppendAnswer> {
  readonly onAppend?: (call: number) => Answer | undefined;
  readonly chainAfterConflict?: BuiltChain;
}

export function injectedAppendResponse<Answer>(
  injection: AppendInjection<Answer>,
  call: number,
  entries: ChainEntry[],
  hashes: string[],
): Answer | undefined {
  const injected = injection.onAppend?.(call);
  if (injected !== undefined && injection.chainAfterConflict !== undefined) {
    entries.splice(0, entries.length, ...injection.chainAfterConflict.entries);
    hashes.splice(0, hashes.length, ...injection.chainAfterConflict.hashes);
  }
  return injected;
}

export function appendableProjectHandlers(
  built: BuiltChain,
  onAppend: (entry: ChainEntry) => void = () => undefined,
): MockHandler[] {
  const { projectId } = built;
  const entries: ChainEntry[] = [...built.entries];
  const hashes: string[] = [...built.hashes];
  return [
    onEndpoint("membership.get", { projectId }, () =>
      servedChainResponse(projectId, entries, hashes),
    ),
    onEndpoint("membership.append", { projectId }, (request) => {
      const entry = request.body.entry as ChainEntry;
      onAppend(entry);
      return acceptAppendedEntry(projectId, entries, hashes, entry);
    }),
    onEndpoint("environments.list", { projectId }, () => ({
      status: 200,
      json: { environments: [], schemaPolicy: "enabled" },
    })),
  ];
}

export function projectListHandlerOf(projects: readonly BuiltChain[]): MockHandler {
  return onEndpoint("membership.list", () => ({
    status: 200,
    json: { projects: projects.map((built) => ({ projectId: built.projectId, role: "owner" })) },
  }));
}
