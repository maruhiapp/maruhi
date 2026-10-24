// Mock handlers for chain distribution (full length) and self-addressed DEKs.
// The appendable project (`appendableProjectHandlers`) is shared by
// support/device.ts and the restore path tests (passkey / handoff — DK K14).
// The append injection (`injectedAppendResponse`) and the accepted append
// (`acceptAppendedEntry`) are used together by support/device.ts,
// four-eyes-server.ts and the member add / member remove / server revoke
// tests' servers; meta-server.ts and mirror-server-grant.test.ts accept
// appends through `acceptAppendedEntry` alone.

import { type ChainEntry, computeChainEntryHash } from "@maruhi/crypto";

import type { BuiltChain, WireRecipientDek } from "./crypto.ts";
import { type MockHandler, type MockResponse, onRequest } from "./server.ts";

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
            attestations: [],
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
    json: {
      projectId,
      entries,
      headSeq: entries.length,
      headHashHex: hashes[hashes.length - 1],
      attestations: [],
    },
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

/** A test's injection into a mock's chain appends (e.g. a 409 head conflict). */
interface AppendInjection {
  /** The injected response for an append, by call (from 0). undefined = accept. */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** When onAppend injects, the served chain is replaced with this one first (a concurrent append). */
  readonly chainAfterConflict?: BuiltChain;
}

/** The response `injection` makes for an append's call (undefined = accept), replacing the entries and hashes first when it says to. */
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
      json: { environments: [], schemaPolicy: "enabled" },
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
