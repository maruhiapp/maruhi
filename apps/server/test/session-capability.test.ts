// セッション主体の能力制限の固定テスト(AUTH_SPEC §5 — W2b)。
//
// 全エンドポイント × セッション主体の許可 / 拒否マトリクスを、api-schema の
// エンドポイント列挙(maruhiApi.groups — メソッド・パス・AuthMiddleware 有無)
// から**機械的に導出**して workerd 実経路で検証する — 手書きのエンドポイント
// 列挙を持たない(宣言漏れ・許可判定の焼き込み失効・新設面のゲート素通りを
// 構造的に検出する。§12-10 (1) の strict 固定テストと同じ「注釈・宣言の存在で
// なく拒否の挙動をテストする」規律)。
//
// - 許可列挙(SESSION_ALLOWED_ENDPOINTS)外の認証必須面: セッション +
//   CSRF ヘッダー込みでも一様に 403 `session-not-allowed`
// - 許可列挙内の面: session-not-allowed が返らない(エンドポイント固有の
//   意味論 — 404 / 400 等 — は各既存スイートが担う)
// - トークン主体: どの面でも session-not-allowed が返らない(CLI 無影響の回帰)
// - 未認証面(UNAUTHENTICATED_ENDPOINTS)との分類整合は api-schema のロード時
//   スイープが import 時点で検査済み(本ファイルの import 自体がその実行)

import {
  AuthMiddleware,
  maruhiApi,
  SESSION_ALLOWED_ENDPOINTS,
  UNAUTHENTICATED_ENDPOINTS,
} from "@maruhi/api-schema";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import { OWNER, projectId } from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token, VAR } from "./support/data-scenario.ts";

registerDataScenario();

interface EndpointInfo {
  readonly group: string;
  readonly name: string;
  readonly method: string;
  readonly path: string;
  readonly authenticated: boolean;
}

/** api-schema の登録済み全エンドポイントの機械列挙(構造型で groups を歩く)。 */
function listEndpoints(): EndpointInfo[] {
  const api = maruhiApi as unknown as {
    readonly groups: {
      readonly [group: string]: {
        readonly endpoints: {
          readonly [endpoint: string]: {
            readonly method: string;
            readonly path: string;
            readonly middlewares: ReadonlySet<unknown>;
          };
        };
      };
    };
  };
  const endpoints: EndpointInfo[] = [];
  for (const [group, groupValue] of Object.entries(api.groups)) {
    for (const [name, endpoint] of Object.entries(groupValue.endpoints)) {
      endpoints.push({
        group,
        name,
        method: endpoint.method,
        path: endpoint.path,
        authenticated: endpoint.middlewares.has(AuthMiddleware),
      });
    }
  }
  return endpoints;
}

/**
 * パスパラメータの具現化。実在プロジェクト(fixture — OWNER はチェーン owner)を
 * 使い、許可面の検証がスコープ検査(404)でなくエンドポイント本体まで届くように
 * する。未知のパラメータ名は fail-loud(新設面はここへの追記を強制される)。
 */
function concreteUrl(path: string): string {
  const substituted = path.replace(/:(\w+)/g, (_m, param: string) => {
    switch (param) {
      case "projectId":
        return projectId;
      case "environmentId":
        return ENV;
      case "variableId":
        return VAR;
      case "id":
        return "01ARZ3NDEKTSV4RRFFQ69G5FAV";
      default:
        throw new Error(`session-capability matrix: no substitution for path param :${param}`);
    }
  });
  return `${BASE}${substituted}`;
}

function requestInit(method: string, headers: Record<string, string>): RequestInit {
  if (method === "GET" || method === "HEAD") {
    return { method, headers };
  }
  // body はダミーで足りる: 能力判定(ミドルウェア)は payload decode より前に
  // 走るため、拒否面は body の中身に依存しない。許可面・トークン面は 400 等の
  // 非 session-not-allowed 応答で十分(正常系は既存スイートが担う)
  return { method, headers: { ...JSON_HEADERS, ...headers }, body: "{}" };
}

const isRevokeToken = (endpoint: EndpointInfo): boolean =>
  `${endpoint.group}.${endpoint.name}` === "auth.revokeToken";

async function isSessionDenied(response: Response): Promise<boolean> {
  if (response.status !== 403) {
    return false;
  }
  const body = (await response.json()) as { reason?: string };
  return body.reason === "session-not-allowed";
}

const allowedKeys = new Set(SESSION_ALLOWED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
const unauthenticatedKeys = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));

/**
 * §5 が明示拒否として列挙する実装済み面(仕様本文との突合ピン)。導出マトリクス
 * とは独立に、これらが許可列挙へ紛れ込む退行をテキストレベルで固定する。
 */
const SPEC_EXPLICIT_DENIALS: ReadonlyArray<readonly [string, string]> = [
  ["variables", "pull"], // 値付き一括 pull(§12-7)
  ["deks", "register"], // DEK の登録(§12-6)
  ["deks", "listMine"], // DEK の取得(§12-6)
  ["deks", "remove"], // DEK の削除(§12-6 — 署名を伴わない唯一の破壊系)
  ["membership", "init"], // チェーン init(§11)
  ["membership", "append"], // チェーン追記(§11)
  ["environments", "create"],
  ["environments", "rotate"],
  ["environments", "rename"],
  ["environments", "remove"],
  ["variables", "create"],
  ["variables", "push"],
  ["variables", "rename"],
  ["variables", "remove"],
  ["invites", "issue"], // 招待の発行(§15-2)
  ["invites", "accept"], // 招待の受諾(§15-2)
  ["rotation", "dismiss"], // rotation dismiss(AUDIT_SPEC §7)
  ["auth", "recoveryPut"], // リカバリーブロブの登録(§13-2)
  ["auth", "recoveryGet"], // リカバリーブロブの取得(§13-2)
];

describe("セッション主体の能力制限マトリクス(AUTH_SPEC §5 — 機械導出)", () => {
  it("§5 の明示拒否面は許可列挙に含まれない(仕様本文との突合ピン)", () => {
    for (const [group, name] of SPEC_EXPLICIT_DENIALS) {
      expect(allowedKeys.has(`${group}.${name}`), `${group}.${name} must not be allowed`).toBe(
        false,
      );
    }
  });

  it("認証必須面と未認証面の分割が全エンドポイントを覆う(導出の完全性)", () => {
    const endpoints = listEndpoints();
    expect(endpoints.length).toBeGreaterThan(0);
    for (const endpoint of endpoints) {
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(endpoint.authenticated, `${key} classification`).toBe(!unauthenticatedKeys.has(key));
      if (allowedKeys.has(key)) {
        expect(endpoint.authenticated, `${key} must carry AuthMiddleware`).toBe(true);
      }
    }
  });

  it("許可列挙外の全認証必須面はセッション主体に一様 403 session-not-allowed(CSRF ヘッダー込みでも)", async () => {
    const denied = listEndpoints().filter(
      (endpoint) =>
        endpoint.authenticated && !allowedKeys.has(`${endpoint.group}.${endpoint.name}`),
    );
    // fail-closed の対象が空でないこと(導出が壊れて全許可に倒れた形の検出)
    expect(denied.length).toBeGreaterThanOrEqual(SPEC_EXPLICIT_DENIALS.length);
    // 拒否面はセッションを失効させられない(全面が拒否される)ため 1 セッションを
    // 使い回す
    const session = await loginSession(9001);
    const headers = sessionHeaders(session);
    for (const endpoint of denied) {
      const response = await SELF.fetch(
        concreteUrl(endpoint.path),
        requestInit(endpoint.method, headers),
      );
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(response.status, `${key} must be 403 for a session principal`).toBe(403);
      const body = (await response.json()) as { reason?: string };
      expect(body.reason, `${key} must be denied by the §5 capability gate`).toBe(
        "session-not-allowed",
      );
    }
  });

  it("許可列挙の全面はセッション主体に session-not-allowed を返さない", async () => {
    const allowed = listEndpoints().filter((endpoint) =>
      allowedKeys.has(`${endpoint.group}.${endpoint.name}`),
    );
    // 許可列挙の宣言(api-schema)と登録面の突合はロード時スイープ済み。ここでは
    // 実挙動側: ゲートが誤って許可面まで拒否していないこと。logout はセッションを
    // 失効させるため、面ごとに新しいセッションを張る
    expect(allowed.length).toBe(SESSION_ALLOWED_ENDPOINTS.length);
    for (const endpoint of allowed) {
      const session = await loginSession(9001);
      const response = await SELF.fetch(
        concreteUrl(endpoint.path),
        requestInit(endpoint.method, sessionHeaders(session)),
      );
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(
        await isSessionDenied(response),
        `${key} must not be rejected by the §5 capability gate`,
      ).toBe(false);
      // 許可面がゲート以外の理由で全滅していないことの粗い健全性(401 は
      // セッション解決の退行を示す)
      expect(response.status, `${key} must authenticate the session`).not.toBe(401);
    }
  });

  it("トークン主体はどの面でも session-not-allowed を受けない(CLI 無影響の回帰)", async () => {
    const authenticated = listEndpoints().filter((endpoint) => endpoint.authenticated);
    // auth.revokeToken は提示トークン自身を失効させるため最後に回し、他の面の
    // 検証を生きたトークンで行う
    const endpoints = [
      ...authenticated.filter((endpoint) => !isRevokeToken(endpoint)),
      ...authenticated.filter(isRevokeToken),
    ];
    const pat = token(OWNER);
    for (const endpoint of endpoints) {
      const response = await SELF.fetch(
        concreteUrl(endpoint.path),
        requestInit(endpoint.method, bearer(pat)),
      );
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(
        await isSessionDenied(response),
        `${key} must not apply the session gate to a token principal`,
      ).toBe(false);
    }
  });

  it("能力判定は CSRF 検査に先行する(拒否面はヘッダー欠落でも session-not-allowed)", async () => {
    const session = await loginSession(9001);
    const cookieOnly = { cookie: sessionHeaders(session)["cookie"] ?? "" };
    // 拒否面(書き込み): CSRF ヘッダーなしでも一様に session-not-allowed
    const deniedWrite = await SELF.fetch(
      concreteUrl("/projects/:projectId/rotation/dismissals"),
      requestInit("POST", cookieOnly),
    );
    expect(deniedWrite.status).toBe(403);
    expect(((await deniedWrite.json()) as { reason?: string }).reason).toBe("session-not-allowed");
    // 許可面(書き込み = logout)では CSRF 検査が生きている(撤去していない)
    const allowedWrite = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: cookieOnly,
    });
    expect(allowedWrite.status).toBe(403);
    expect(((await allowedWrite.json()) as { reason?: string }).reason).toBe(
      "csrf-header-required",
    );
  });

  it("許可面の代表(読み取り)はセッションで実際に成功する(positive control)", async () => {
    const session = await loginSession(9001);
    const headers = sessionHeaders(session);
    // チェーン取得(§11)— fixture の OWNER はチェーン導出メンバー
    const chain = await SELF.fetch(concreteUrl("/projects/:projectId/chain"), { headers });
    expect(chain.status).toBe(200);
    // プロジェクト一覧(§11-5 — W2a。S4 の消費経路)
    const projectList = await SELF.fetch(`${BASE}/projects`, { headers });
    expect(projectList.status).toBe(200);
    // 環境一覧(§12-4)
    const environments = await SELF.fetch(concreteUrl("/projects/:projectId/environments"), {
      headers,
    });
    expect(environments.status).toBe(200);
    // 要ローテーションフラグ(AUDIT_SPEC §4.1)
    const flags = await SELF.fetch(concreteUrl("/projects/:projectId/rotation/flags"), {
      headers,
    });
    expect(flags.status).toBe(200);
    // fixture.head が読めていること(セッションでの読み取りがトークンと同じ形)
    const body = (await chain.json()) as { headSeq: number };
    expect(body.headSeq).toBe(fixture.head.seq);
  });
});
