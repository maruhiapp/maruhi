// strict 受理の実効性の固定テスト(AUTH_SPEC §12-10 (1) — PR-F1)。
//
// 対象は §12-10 (1) の列挙面のうち実装済みの全エンドポイント payload ルート
// (packages/api-schema/src/strict.ts の SECURITY_CRITICAL_PAYLOAD_ENDPOINTS)。
// 各面で「未知フィールドを含むリクエストが実際に 400 で拒否される」ことを
// workerd 実環境の受理経路で検証する — 注釈の**存在**をテストしない
// (docs/notes/session-32.md §2-3: 適用順バグと upstream の parseOptions
// 読み取り位置変更の両方を、挙動の側から検出するため)。
//
// 各テストは同一 body の 2 送信で構成する:
// 1. probe = clean body + 未知フィールド → 400
// 2. control = clean body そのもの → 400 以外(decode 通過の証明)
//
// 2 送信の差分は未知フィールドのみなので、probe の 400 は未知フィールド起因で
// あることが確定する(他フィールド起因の 400 なら control も 400 になる)。
// Schema 400 の応答本文は空(upstream の HttpApiSchemaError は「empty 400」で
// レンダリングされる仕様)のため、本文の検査は行わない。正常系の完走は既存
// スイートが担う。
//
// 署名検証に到達しない body には data-scenario の unsigned ダミー(形式のみ
// 有効なゼロ署名)を使う — 400 が Schema 段で確定することの証明には十分。

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS } from "./support/auth.ts";
import { dataUrl, OWNER, projectId } from "./support/data-fixture.ts";
import {
  aadFor,
  ENV,
  fixture,
  registerDataScenario,
  token,
  unsignedManifest,
  unsignedPayload,
  unsignedVariableStatement,
  VAR,
} from "./support/data-scenario.ts";

registerDataScenario();

const PROBE_KEY = "__maruhiStrictProbe";

/**
 * probe(clean + 未知フィールド)= 400、control(clean)= 非 400 を固定する。
 * control の実ステータスを返す(呼び出し側でハンドラ段の典型結果を併記できる)。
 */
async function expectStrictReject(
  send: (body: Record<string, unknown>) => Promise<Response>,
  clean: Record<string, unknown>,
): Promise<number> {
  const probe = await send({ ...clean, [PROBE_KEY]: true });
  expect(probe.status).toBe(400);
  const control = await send(clean);
  expect(control.status).not.toBe(400);
  return control.status;
}

/**
 * ネストへの伝播: control(非 400)を通過済みの clean body に対し、ネスト位置に
 * だけ未知フィールドを埋めた形が 400 で落ちること(expectStrictReject の後に呼ぶ)。
 */
async function expectNestedReject(
  send: (body: Record<string, unknown>) => Promise<Response>,
  nested: Record<string, unknown>,
): Promise<void> {
  const probe = await send(nested);
  expect(probe.status).toBe(400);
}

const sendJson =
  (method: string, url: string, headers: Record<string, string>) =>
  (body: Record<string, unknown>): Promise<Response> =>
    SELF.fetch(url, {
      method,
      headers: { ...JSON_HEADERS, ...headers },
      body: JSON.stringify(body),
    });

// 形式のみ有効なゼロ署名エントリ(署名検証 = 422 に到達する前提の control 用)
const unsignedEntry = (op: string, payload: Record<string, unknown>): Record<string, unknown> => ({
  suite: "maruhi/v1",
  seq: fixture.head.seq + 1,
  prevHashHex: fixture.head.hashHex,
  op,
  actor: { userId: OWNER, keyFingerprintHex: "ab".repeat(16) },
  payload,
  timestampMs: 1754006400000,
  signatureHex: "00".repeat(64),
});

const unsignedEnvStatement = (
  lifecycle:
    | { status: "active"; metaVersion: 1; prevMetaSigHashHex: "" }
    | { status: "active" | "deleted"; metaVersion: number; prevMetaSigHashHex: string },
): Record<string, unknown> => ({
  suite: "maruhi/v1",
  environmentId: ENV,
  name: "App",
  ...lifecycle,
  chainHeadHashHex: fixture.head.hashHex,
  chainHeadSeq: fixture.head.seq,
  signatureHex: "00".repeat(64),
});

describe("チェーン追記(§11-4)", () => {
  it("init rejects an unknown field with 400", async () => {
    const send = sendJson("POST", `${BASE}/projects`, bearer(token(OWNER)));
    await expectStrictReject(send, {
      orgId: "org-strict-0001",
      entry: unsignedEntry("genesis", { encPubHex: "cd".repeat(32), sigPubHex: "ef".repeat(32) }),
    });
  });

  it("append rejects an unknown field with 400 (root and nested entry payload)", async () => {
    const send = sendJson(
      "POST",
      `${BASE}/projects/${projectId}/chain/entries`,
      bearer(token(OWNER)),
    );
    const entry = unsignedEntry("remove_member", { targetUserId: "user-member-0002" });
    const clean = { parentHeadHashHex: fixture.head.hashHex, entry };
    await expectStrictReject(send, clean);
    // ネスト(entry.payload)への伝播
    await expectNestedReject(send, {
      ...clean,
      entry: {
        ...entry,
        payload: { targetUserId: "user-member-0002", [PROBE_KEY]: true },
      },
    });
  });
});

describe("環境作成・ローテーション複合(§12-4)", () => {
  it("create rejects an unknown field with 400 (root and nested entry payload)", async () => {
    const send = sendJson("POST", dataUrl("/environments"), bearer(token(OWNER)));
    const entryPayload = { environmentId: ENV, dekCommitmentHex: "12".repeat(32) };
    const clean = {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("create_environment", entryPayload),
      statement: unsignedEnvStatement({ status: "active", metaVersion: 1, prevMetaSigHashHex: "" }),
      deks: [],
      manifest: {
        ...unsignedManifest(),
        variablesDigestHex: "ab".repeat(32),
      },
    };
    await expectStrictReject(send, clean);
    await expectNestedReject(send, {
      ...clean,
      entry: unsignedEntry("create_environment", { ...entryPayload, [PROBE_KEY]: true }),
    });
  });

  it("rotate rejects an unknown field with 400 (root and nested manifest)", async () => {
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/rotate`), bearer(token(OWNER)));
    const clean = {
      parentHeadHashHex: fixture.head.hashHex,
      entry: unsignedEntry("rotate_epoch", {
        environmentId: ENV,
        newEpoch: 2,
        reason: "test",
        dekCommitmentHex: "12".repeat(32),
      }),
      deks: [],
      manifest: {
        ...unsignedManifest(),
        epoch: 2,
        manifestVersion: 2,
        prevManifestSigHashHex: "cd".repeat(32),
      },
    };
    await expectStrictReject(send, clean);
    await expectNestedReject(send, {
      ...clean,
      manifest: { ...(clean.manifest as Record<string, unknown>), [PROBE_KEY]: true },
    });
  });
});

describe("メタ操作(§12-5 — 環境)", () => {
  it("environment rename rejects an unknown field with 400", async () => {
    const send = sendJson("PATCH", dataUrl(`/environments/${ENV}`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      statement: unsignedEnvStatement({
        status: "active",
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      }),
      manifest: unsignedManifest(),
    });
  });

  it("environment delete rejects an unknown field with 400", async () => {
    const send = sendJson("DELETE", dataUrl(`/environments/${ENV}`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      statement: unsignedEnvStatement({
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      }),
    });
  });
});

describe("値 push・メタ操作(§12-5 — 変数)", () => {
  it("variable create rejects an unknown field with 400", async () => {
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/variables`), bearer(token(OWNER)));
    await expectStrictReject(send, {
      statement: unsignedVariableStatement(VAR, "DATABASE_URL"),
      value: unsignedPayload(aadFor(1, 1)),
      manifest: unsignedManifest(),
    });
  });

  it("push rejects an unknown field with 400 (root and nested value AAD)", async () => {
    const send = sendJson(
      "POST",
      dataUrl(`/environments/${ENV}/variables/${VAR}/versions`),
      bearer(token(OWNER)),
    );
    const value = unsignedPayload(aadFor(1, 2));
    await expectStrictReject(send, { value });
    await expectNestedReject(send, {
      value: { ...value, aad: { ...value.aad, [PROBE_KEY]: true } },
    });
  });

  it("variable rename rejects an unknown field with 400", async () => {
    const send = sendJson(
      "PATCH",
      dataUrl(`/environments/${ENV}/variables/${VAR}`),
      bearer(token(OWNER)),
    );
    await expectStrictReject(send, {
      statement: {
        ...unsignedVariableStatement(VAR, "DATABASE_URL_2"),
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      },
      manifest: unsignedManifest(),
    });
  });

  it("variable delete rejects an unknown field with 400", async () => {
    const send = sendJson(
      "DELETE",
      dataUrl(`/environments/${ENV}/variables/${VAR}`),
      bearer(token(OWNER)),
    );
    await expectStrictReject(send, {
      statement: {
        ...unsignedVariableStatement(VAR, "DATABASE_URL"),
        status: "deleted",
        metaVersion: 2,
        prevMetaSigHashHex: "ab".repeat(32),
      },
      manifest: unsignedManifest(),
    });
  });
});

describe("DEK ラップ登録(§12-6)", () => {
  it("register rejects an unknown field with 400 (root and nested wrap)", async () => {
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/deks`), bearer(token(OWNER)));
    const wrap = {
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: OWNER,
      recipientEncPubHex: "ab".repeat(32),
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
      signatureHex: "00".repeat(64),
    };
    await expectStrictReject(send, { deks: [wrap] });
    await expectNestedReject(send, { deks: [{ ...wrap, [PROBE_KEY]: true }] });
  });
});

describe("リカバリーブロブ登録(§13-2)", () => {
  it("recovery put rejects an unknown field with 400 (clean body still succeeds)", async () => {
    const send = sendJson("PUT", `${BASE}/auth/recovery`, bearer(token(OWNER)));
    const status = await expectStrictReject(send, {
      suite: "maruhi/v1",
      nonceHex: "00".repeat(12),
      ciphertextHex: "ab".repeat(16),
    });
    // control は実受理まで通る(probe が状態を変えないことの裏取り込み)
    expect(status).toBe(204);
  });
});

describe("リース請求(§14)", () => {
  it("lease issue rejects an unknown field with 400", async () => {
    // 唯一の未認証面(資格情報 = OIDC トークン自体 — §14-1)
    const send = sendJson("POST", dataUrl(`/environments/${ENV}/lease`), {});
    await expectStrictReject(send, {
      oidcToken: "aa.bb.cc",
      ephemeralPubHex: "ab".repeat(32),
    });
  });
});

describe("招待の作成・受諾(§15-2)", () => {
  it("invite issue rejects an unknown field with 400", async () => {
    const send = sendJson("POST", `${BASE}/projects/${projectId}/invites`, bearer(token(OWNER)));
    await expectStrictReject(send, { role: "member" });
  });

  it("invite accept rejects an unknown field with 400", async () => {
    const send = sendJson("POST", `${BASE}/invites/accept`, bearer(token(OWNER)));
    await expectStrictReject(send, {
      token: `maruhi_inv_${"a".repeat(43)}`,
      encPubHex: "ab".repeat(32),
      sigPubHex: "cd".repeat(32),
      signatureHex: "00".repeat(64),
    });
  });
});
