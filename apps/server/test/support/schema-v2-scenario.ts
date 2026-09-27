// Shared helpers for layout v2 (valueless schema — S2) integration tests.
// Assumes the fixture of data-scenario.ts (registerDataScenario).

import { encryptValue } from "./data-crypto.ts";
import { MEMBER, projectId, requestJson } from "./data-fixture.ts";
import {
  ENV,
  fixture,
  manifestForStatement,
  token,
  variableStatementV2For,
  varStatements,
} from "./data-scenario.ts";

/** v2 value-bundled creation (§12-5 — active + schema field). Advances the
 * record on 200. */
export async function createVariableV2Request(input: {
  readonly variableId: string;
  readonly name: string;
  readonly plaintext: string;
  readonly dek: Uint8Array;
  readonly actorUserId?: string;
  readonly schema?: Parameters<typeof variableStatementV2For>[0]["schema"];
}): Promise<Response> {
  const actorUserId = input.actorUserId ?? MEMBER;
  const statement = await variableStatementV2For({
    authorUserId: actorUserId,
    variableId: input.variableId,
    name: input.name,
    status: "active",
    ...(input.schema === undefined ? {} : { schema: input.schema }),
  });
  const value = await encryptValue(
    input.dek,
    { projectId, environmentId: ENV, epoch: 1, variableId: input.variableId, version: 1 },
    input.plaintext,
    { writerUserId: actorUserId, head: fixture.head },
  );
  const { manifest, record } = await manifestForStatement(statement, actorUserId);
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(actorUserId), {
    statement,
    value,
    manifest,
  });
  if (response.status === 200) {
    varStatements.set(input.variableId, { statement, authorUserId: actorUserId });
    record();
  }
  return response;
}
