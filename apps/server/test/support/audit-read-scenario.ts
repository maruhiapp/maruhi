// 監査読み取り API(AUDIT_SPEC §6 / §7)統合テストの共有ヘルパ(旧
// audit-read.test.ts の冒頭ヘルパの分割先 — 分割の動機は
// membership-scenario.ts 冒頭を参照)。data-scenario.ts の fixture
// (registerDataScenario)を前提とする。

import type { TokenScope } from "@maruhi/core";
import { expect } from "vitest";

import { cliToken } from "./auth.ts";
import { createEnvironmentOk, MEMBER, READER, requestJson } from "./data-fixture.ts";
import { createVariableOk, ENV, fixture, token, VAR } from "./data-scenario.ts";

export interface WireAuditEvent {
  readonly id: string;
  readonly seq?: number;
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly event: string;
  readonly actor: {
    readonly type: "user" | "server" | "system";
    readonly userId?: string;
    readonly keyFingerprintHex?: string;
    readonly apiTokenId?: string;
  };
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
  readonly projectId?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

export async function fetchEvents(
  bearerToken: string,
  query: Record<string, string> = {},
): Promise<{ status: number; events: readonly WireAuditEvent[] }> {
  const search = new URLSearchParams(query).toString();
  const response = await requestJson(
    "GET",
    `/audit/events${search === "" ? "" : `?${search}`}`,
    bearerToken,
  );
  if (response.status !== 200) {
    return { status: response.status, events: [] };
  }
  const body = (await response.json()) as { events: readonly WireAuditEvent[] };
  return { status: 200, events: body.events };
}

/** 環境 + 変数 + 読み取り(READER / MEMBER の pull)まで進めた標準シナリオ。 */
export async function seedProjectActivity(): Promise<void> {
  const dek = await createEnvironmentOk(fixture, ENV, "App");
  await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
  const readerPull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
  expect(readerPull.status).toBe(200);
  const memberPull = await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER));
  expect(memberPull.status).toBe(200);
}

export const eventNames = (events: readonly WireAuditEvent[]): readonly string[] =>
  events.map((event) => event.event);

export function scopedToken(
  githubId: number,
  name: string,
  scopes: readonly TokenScope[],
): Promise<string> {
  return cliToken(githubId, scopes, name);
}
