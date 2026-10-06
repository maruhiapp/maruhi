import { afterEach, beforeAll } from "vitest";

import { chainHandlerOf } from "./chain-handler.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./crypto.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./server.ts";
import { type StoredVariable } from "./value-env.ts";

export const ENV_ID = "prod";
export const ALPHA_VALUE = "alpha-value";

export let owner: TestUser;
export let built: BuiltChain;
let dek: Uint8Array;
export let wrap: WireRecipientDek;
export let envStatement: WireDistributedEnvironmentStatement;
export let alpha: StoredVariable;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  wrap = await wrapDekFor({ ...common, epoch: 1, dek, recipient: owner, signer: owner });
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({
    ...common,
    name: ENV_ID,
    author: owner,
    head,
  });
  alpha = {
    variableId: "va",
    statement: await statementFor({
      ...common,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head,
    }),
    value: await encryptValueFor({
      dek,
      ...common,
      epoch: 1,
      variableId: "va",
      version: 1,
      plaintext: ALPHA_VALUE,
      writer: owner,
      head: headOf(built, 2),
    }),
  };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

export async function start(handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

/** An origin nothing listens on (the connection is refused at once). */
export async function deadOrigin(): Promise<string> {
  const server = await MockServer.start([]);
  const origin = server.origin;
  await server.close();
  return origin;
}

export const headOfChain = () => ({
  chainHeadSeq: built.entries.length,
  chainHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
  auditMaxSeq: 4,
});

/** The source's mutation counter the export's head reports (every page carries it to the mirror). */
export const SOURCE_MUTATION_SEQ = 5;

/** An export page's head: the chain head plus the source's mutation counter. */
export const exportHeadOfChain = () => ({ ...headOfChain(), mutationSeq: SOURCE_MUTATION_SEQ });

export interface MirrorState {
  readonly pages: {
    readonly sequence: number;
    readonly lines: readonly string[];
    readonly sourceMutationSeq: number;
  }[];
  readonly bearers: string[];
  status: Record<string, unknown>;
  /** An injected answer for the page carrying the trailer. */
  lastPage: { readonly status: number; readonly json: unknown } | null;
}

/** The mirror: the status, the pages (committing when the trailer arrives), the mark and the promotion. */
export function mirrorHandlers(state: MirrorState): MockHandler[] {
  const path = `/projects/${built.projectId}/mirror`;
  return [
    (request: MockRequest) => {
      state.bearers.push(String(request.headers["authorization"] ?? ""));
      return null;
    },
    // The mirror serves the chain like any server (the mark's check reads it)
    chainHandlerOf(built),
    onRequest("GET", path, () => ({ status: 200, json: state.status })),
    onRequest("PUT", path, (request) => {
      const body = request.body as { readonly sourceOrigin: string };
      state.status = {
        ...state.status,
        mirror: true,
        sourceOrigin: body.sourceOrigin,
        markedAtMs: 1,
      };
      return { status: 200, json: state.status };
    }),
    onRequest("DELETE", path, () => {
      state.status = { mirror: false, head: state.status["head"] };
      return { status: 200, json: state.status };
    }),
    onRequest("PUT", `${path}/pages`, (request) => {
      const body = request.body as MirrorState["pages"][number];
      state.pages.push(body);
      const trailer = body.lines.some((line) => line.includes('"kind":"trailer"'));
      if (trailer && state.lastPage !== null) {
        return state.lastPage;
      }
      return trailer
        ? {
            status: 200,
            json: {
              nextSequence: 0,
              committed: {
                atMs: 5,
                ...headOfChain(),
                attestationMark: 0,
                mutationSeq: body.sourceMutationSeq,
              },
            },
          }
        : { status: 200, json: { nextSequence: body.sequence + 1 } };
    }),
    onRequest("GET", "/auth/me", () => ({
      status: 200,
      json: { userId: owner.userId, orgs: [] },
    })),
  ];
}

export function mirrorState(marked = true, sourceOrigin = "https://my.maruhi.app"): MirrorState {
  return {
    pages: [],
    bearers: [],
    status: marked
      ? {
          mirror: true,
          sourceOrigin,
          markedAtMs: 1,
          head: { ...headOfChain(), chainHeadSeq: 1, chainHeadHashHex: built.projectId },
        }
      : { mirror: false, head: headOfChain() },
    lastPage: null,
  };
}
