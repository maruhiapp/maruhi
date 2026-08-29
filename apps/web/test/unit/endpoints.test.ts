// ダッシュボード消費面のスイープ(裁定 BW — docs/notes/session-43.md §11)。
//
// 目録(src/dashboard/endpoints.ts)を登録済み HttpApi(api-schema — 値 import は
// テストプロセスのみ)と突合し、「パス整合」と「セッション許可」を fail-loud に
// する。serving-topology.test.ts(サーバー側の run_worker_first 被覆)の
// クライアント側対応物。
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { isSessionAllowedEndpoint, maruhiApi, UNAUTHENTICATED_ENDPOINTS } from "@maruhi/api-schema";
import { describe, expect, it } from "vitest";

import {
  DASHBOARD_ENDPOINTS,
  SAMPLE_ENVIRONMENT_ID,
  SAMPLE_PROJECT_ID,
} from "../../src/dashboard/endpoints.ts";

/** 検査対象の構造スライス(session-capability.ts の SweepableApi と同じ理由の構造型)。 */
interface PathedApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: { readonly path: string };
      };
    };
  };
}

const api = maruhiApi as unknown as PathedApi;

/**
 * パステンプレートの `:param` を目録と同じサンプル値で具体化する。未知の
 * パラメータ名はそのまま残り、等値比較が落ちて目録の改訂を強制する(fail-loud)。
 */
function substituteTemplate(template: string): string {
  return template
    .replace(/:projectId/g, SAMPLE_PROJECT_ID)
    .replace(/:environmentId/g, SAMPLE_ENVIRONMENT_ID);
}

describe("dashboard endpoint sweep (裁定 BW)", () => {
  it("binds every consumed path builder to a real api-schema endpoint", () => {
    for (const { group, endpoint, sample } of DASHBOARD_ENDPOINTS) {
      const registered = api.groups[group]?.endpoints[endpoint];
      expect(registered, `${group}.${endpoint} is not a registered endpoint`).toBeDefined();
      expect(substituteTemplate(registered?.path ?? ""), `${group}.${endpoint}`).toBe(sample);
    }
  });

  it("classifies every consumed endpoint's auth surface correctly (AUTH_SPEC §5)", () => {
    // access: "session" はセッション許可列挙内(列挙外 API を呼ぶ画面は実行時
    // 403 でなくここで割れる)。access: "unauthenticated" は未認証面の列挙内
    // (認証必須の面をナビゲーション導線として消費する形もここで割れる)
    const unauthenticated = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
    for (const { group, endpoint, access } of DASHBOARD_ENDPOINTS) {
      if (access === "session") {
        expect(
          isSessionAllowedEndpoint(group, endpoint),
          `${group}.${endpoint} is not session-allowed — a browser session cannot call it`,
        ).toBe(true);
      } else {
        expect(
          unauthenticated.has(`${group}.${endpoint}`),
          `${group}.${endpoint} is marked unauthenticated in the manifest but not in AUTH_SPEC §5`,
        ).toBe(true);
      }
    }
  });

  it("has no duplicate entries (each consumed endpoint is listed once)", () => {
    const keys = DASHBOARD_ENDPOINTS.map(({ group, endpoint }) => `${group}.${endpoint}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("keeps API path literals out of screen code (builders are the only source)", () => {
    // ソーストリップワイヤ(裁定 BY): 目録の網羅性は「画面が fetch するパスは
    // すべて endpoints.ts のビルダー経由」という規律に依存する。ここでは
    // src/ 配下(endpoints.ts 自身を除く)に API 前置のパスリテラルが現れない
    // ことを機械検査し、ビルダーを迂回する消費面の混入をドリフトとして落とす
    expect(
      findApiLiteralOffenders(join(import.meta.dirname, "../../src")),
      "API path literal outside src/dashboard/endpoints.ts — use the apiPaths builders (裁定 BW/BY)",
    ).toEqual([]);
  });
});

/** トリップワイヤの走査対象: TS/TSX ソース(唯一のビルダー置き場を除く)。 */
function isSweepTarget(entry: { isFile(): boolean; name: string }): boolean {
  return entry.isFile() && /\.(ts|tsx)$/.test(entry.name) && entry.name !== "endpoints.ts";
}

/**
 * API 前置(/auth・/projects・/invites)のパスリテラルを持つファイルを列挙する。
 * 対象はダブル/シングルクォートの文字列のみ — バッククォートはコメント内の
 * パス例(`/auth/me` 等)と衝突するため対象外で、迂回可能性は許容する
 * (word-hash トリップワイヤと同じ「善意のドリフト検出」の位置づけ — session-41 BG)。
 */
function findApiLiteralOffenders(srcRoot: string): string[] {
  const offenders: string[] = [];
  for (const entry of readdirSync(srcRoot, { recursive: true, withFileTypes: true })) {
    if (!isSweepTarget(entry)) continue;
    const filePath = join(entry.parentPath, entry.name);
    if (/["']\/(auth|projects|invites)\b/.test(readFileSync(filePath, "utf8"))) {
      offenders.push(filePath.slice(srcRoot.length + 1));
    }
  }
  return offenders;
}
