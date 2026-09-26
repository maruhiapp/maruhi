// Mock handlers for chain distribution (full length) and self-addressed DEKs.
// Shared by meta-server.ts / value-env.ts. The appendable project
// (`appendableProjectHandlers`) is shared by device.test.ts and the restore
// path tests (passkey / handoff — DK K14).

import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";

import type { BuiltChain, WireRecipientDek } from "./crypto.ts";
import { type MockHandler, onRequest } from "./server.ts";

/** Returns self-addressed wraps for `GET /projects/:id/environments/:env/deks`. */
export function deksHandlerOf(
  projectId: string,
  environmentId: string,
  deks: readonly WireRecipientDek[],
): MockHandler {
  const path = `/projects/${projectId}/environments/${environmentId}/deks`;
  return (request) =>
    request.method === "GET" && request.path === path ? { status: 200, json: { deks } } : null;
}

/** Returns the assembled chain verbatim for `GET /projects/:id/chain`. */
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

/** The `GET /projects/:id/chain` response of a chain reflecting appends. */
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

/** Accepts an append, extends the entries and hashes, and returns the new head. */
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
 * An appendable project: chain GET (reflecting appends), append POST, and an
 * empty environment list. `onAppend` receives accepted entries in call order.
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

/** `GET /projects` (AUTH_SPEC §11-5) — lists the assembled chains' projects with the caller as owner. */
export function projectListHandlerOf(projects: readonly BuiltChain[]): MockHandler {
  return onRequest("GET", "/projects", () => ({
    status: 200,
    json: { projects: projects.map((built) => ({ projectId: built.projectId, role: "owner" })) },
  }));
}
