// Shared helpers for layout v3 (valueless schema) integration tests.
// Assumes the fixture of data-scenario.ts (registerDataScenario).

import { encryptValue } from "./data-crypto.ts";
import { testEnvironmentId, testProjectId, testVariableId } from "./data-crypto.ts";
import { MEMBER, projectId, requestJson } from "./data-fixture.ts";
import {
  ENV,
  fixture,
  manifestForStatement,
  token,
  variableStatementV3For,
  varStatements,
} from "./data-scenario.ts";

/** v3 value-bundled creation (§12-5 — active + schema field). Advances the
 * record on 200. */
export async function createVariableV3Request(input: {
  readonly variableId: string;
  readonly name: string;
  readonly plaintext: string;
  readonly dek: Uint8Array;
  readonly actorUserId?: string;
  readonly schema?: Parameters<typeof variableStatementV3For>[0]["schema"];
}): Promise<Response> {
  const actorUserId = input.actorUserId ?? MEMBER;
  const statement = await variableStatementV3For({
    authorUserId: actorUserId,
    variableId: input.variableId,
    name: input.name,
    status: "active",
    ...(input.schema === undefined ? {} : { schema: input.schema }),
  });
  const value = await encryptValue(
    input.dek,
    {
      projectId: testProjectId(projectId),
      environmentId: testEnvironmentId(ENV),
      epoch: 1,
      variableId: testVariableId(input.variableId),
      version: 1,
    },
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
