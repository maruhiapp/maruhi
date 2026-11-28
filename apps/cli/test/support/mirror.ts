import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  distributedEnvironmentStatement,
  distributedValue,
  distributedVariableStatement,
  distributedWrap,
  type GeneratedIdentity,
  generateIdentity,
  genesisOp,
  headOf,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
} from "@maruhi/test-kit";
import type { ApiPayload, ApiSuccess } from "@maruhi/test-kit/api";
import { afterEach, beforeAll } from "vite-plus/test";

import { chainHandlerOf } from "./chain-handler.ts";
import {
  type EndpointAnswer,
  type MockHandler,
  type MockRequest,
  MockServer,
  onEndpoint,
} from "./server.ts";
import { type StoredVariable } from "./value-env.ts";

export const ENV_ID = "prod";
export const ALPHA_VALUE = "alpha-value";

export let owner: GeneratedIdentity;
export let built: BuiltChain;
let dek: Uint8Array;
export let wrap: WireRecipientDek;
export let envStatement: WireDistributedEnvironmentStatement;
export let alpha: StoredVariable;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await generateIdentity("user-owner-1111");
  dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  wrap = await distributedWrap({ ...common, epoch: 1, dek, recipient: owner, signer: owner });
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await distributedEnvironmentStatement({
    ...common,
    name: ENV_ID,
    author: owner,
    head,
  });
  alpha = {
    variableId: "va",
    statement: await distributedVariableStatement({
      ...common,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head,
    }),
    value: await distributedValue({
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

export const SOURCE_MUTATION_SEQ = 5;

export const exportHeadOfChain = () => ({ ...headOfChain(), mutationSeq: SOURCE_MUTATION_SEQ });

export interface MirrorState {
  readonly pages: ApiPayload<"mirror.pages">[];
  readonly bearers: string[];
  status: ApiSuccess<"mirror.status">;
  lastPage: EndpointAnswer<"mirror.pages"> | null;
}

export function mirrorHandlers(state: MirrorState): MockHandler[] {
  const projectId = built.projectId;
  return [
    (request: MockRequest) => {
      state.bearers.push(String(request.headers["authorization"] ?? ""));
      return null;
    },
    chainHandlerOf(built),
    onEndpoint("mirror.status", { projectId }, () => ({ status: 200, json: state.status })),
    onEndpoint("mirror.mark", { projectId }, (request) => {
      state.status = {
        ...state.status,
        mirror: true,
        sourceOrigin: request.body.sourceOrigin,
        markedAtMs: 1,
      };
      return { status: 200, json: state.status };
    }),
    onEndpoint("mirror.unmark", { projectId }, () => {
      state.status = { mirror: false, head: state.status.head };
      return { status: 200, json: state.status };
    }),
    onEndpoint("mirror.pages", { projectId }, (request) => {
      const body = request.body;
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
    onEndpoint("auth.me", () => ({
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
