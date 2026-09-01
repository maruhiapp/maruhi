// レイアウト v2(値なしスキーマ — S2)統合テストの共有ヘルパ(旧
// data-schema-v2.test.ts の冒頭ヘルパの分割先 — 分割の動機は
// membership-scenario.ts 冒頭を参照)。data-scenario.ts の fixture
// (registerDataScenario)を前提とする。

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

/** v2 の値同梱作成(§12-5 — active + スキーマ欄)。200 なら記録を進める。 */
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
