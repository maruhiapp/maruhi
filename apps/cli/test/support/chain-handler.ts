import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";
import type { BuiltChain, WireRecipientDek } from "@maruhi/test-kit";

import { type MockHandler, type MockResponse, onRequest } from "./server.ts";

export function deksHandlerOf(
  projectId: string,
  environmentId: string,
  deks: readonly WireRecipientDek[],
): MockHandler {
  const path = `/projects/${projectId}/environments/${environmentId}/deks`;
  return (request) =>
    request.method === "GET" && request.path === path ? { status: 200, json: { deks } } : null;
}

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
            attestations: [],
          },
        }
      : null;
}

export function servedChainResponse(
  projectId: string,
  entries: readonly ChainEntry[],
  hashes: readonly string[],
): { readonly status: 200; readonly json: unknown } {
  return {
    status: 200,
    json: {
      projectId,
      entries,
      headSeq: entries.length,
      headHashHex: hashes[hashes.length - 1],
      attestations: [],
    },
  };
}

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

interface AppendInjection {
  readonly onAppend?: (call: number) => MockResponse | undefined;
  readonly chainAfterConflict?: BuiltChain;
}

export function injectedAppendResponse(
  injection: AppendInjection,
  call: number,
  entries: ChainEntry[],
  hashes: string[],
): MockResponse | undefined {
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
      json: { environments: [], schemaPolicy: "enabled" },
    })),
  ];
}

export function projectListHandlerOf(projects: readonly BuiltChain[]): MockHandler {
  return onRequest("GET", "/projects", () => ({
    status: 200,
    json: { projects: projects.map((built) => ({ projectId: built.projectId, role: "owner" })) },
  }));
}
