// ダッシュボード消費面のスイープ(裁定 BW — docs/notes/session-43.md §11)。
//
// 目録(src/dashboard/endpoints.ts)を登録済み HttpApi(api-schema — 値 import は
// テストプロセスのみ)と突合し、「パス整合」と「セッション許可」を fail-loud に
// する。serving-topology.test.ts(サーバー側の run_worker_first 被覆)の
// クライアント側対応物。
import { isSessionAllowedEndpoint, maruhiApi } from "@maruhi/api-schema";
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

  it("keeps every consumed endpoint inside the session allow-list (AUTH_SPEC §5)", () => {
    // セッション主体の Web が列挙外 API を呼ぶ画面は実行時 403
    // (session-not-allowed)でなく、このテストで割れる
    for (const { group, endpoint } of DASHBOARD_ENDPOINTS) {
      expect(
        isSessionAllowedEndpoint(group, endpoint),
        `${group}.${endpoint} is not session-allowed — a browser session cannot call it`,
      ).toBe(true);
    }
  });

  it("has no duplicate entries (each consumed endpoint is listed once)", () => {
    const keys = DASHBOARD_ENDPOINTS.map(({ group, endpoint }) => `${group}.${endpoint}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
