// メンバーシップログのサーバー保存(CRYPTO_SPEC §6.4)+ 認可(AUTH_SPEC §11)の
// 統合テスト — genesis 受理・正常系ベクター再生・差分ロードキャッシュ。
// @cloudflare/vitest-plugin(workerd 実環境)で SELF 経由の HttpApi と DO SQLite / D1 を検証する。
//
// 共有 fixture・ベクター再生ヘルパは support/membership-scenario.ts(認可・
// negative・受理ポリシーは membership-authz / membership-negatives-* /
// membership-policy の各ファイル — 分割の動機はシナリオモジュール冒頭を参照)。

import type { ChainEntry } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { bearer } from "./support/auth.ts";
import {
  firstFourEyesSeq,
  toWireEntry,
  vectorEntries,
  vectorExtendedChains,
  vectorProjectId,
} from "./support/chain-vectors.ts";
import { signEntryAt } from "./support/data-crypto.ts";
import {
  appendEntry,
  getChain,
  initChain,
  registerMembershipScenario,
  replayNegativePrefix,
  replayVectorChain,
  tokenFor,
  VECTOR_ORG,
} from "./support/membership-scenario.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerMembershipScenario();

describe("environment", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });
});

describe("POST /projects (genesis 受理 + org 連携 §11-3)", () => {
  it("accepts the vector genesis, derives project id = genesis entry hash, records the org row", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    // D1 の projects 行(org 帰属メタデータ)が追従する
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects a duplicate genesis submission with 409", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    const second = await initChain(toWireEntry(genesis));
    expect(second.status).toBe(409);
    const body = (await second.json()) as { projectId: string };
    expect(body.projectId).toBe(vectorProjectId);
  });

  it("repairs a missing projects row idempotently for the genesis actor (§11-3)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    await initChain(toWireEntry(genesis));
    // DO 受理後・D1 行挿入前のクラッシュを模擬: 行だけを消す
    await env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(vectorProjectId).run();
    const retried = await initChain(toWireEntry(genesis));
    expect(retried.status).toBe(200);
    await expect(retried.json()).resolves.toEqual({
      projectId: vectorProjectId,
      headSeq: 1,
      headHashHex: genesis.entry_hash_hex,
    });
    const row = await env.DB.prepare("SELECT org_id FROM projects WHERE id = ?")
      .bind(vectorProjectId)
      .first<{ org_id: string }>();
    expect(row?.org_id).toBe(VECTOR_ORG);
  });

  it("rejects init into an org the caller is not a member of (403 org-membership-required)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), { orgId: "org-not-mine" });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("org-membership-required");
  });

  it("rejects init whose genesis actor is not the authenticated user (403 actor-mismatch §11-1)", async () => {
    const genesis = vectorEntries[0];
    if (genesis === undefined) throw new Error("missing genesis vector");
    const response = await initChain(toWireEntry(genesis), {
      headers: bearer(tokenFor("user-member-0002")),
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { reason: string };
    expect(body.reason).toBe("actor-mismatch");
  });

  it("rejects a non-genesis entry with 422 (bad-seq)", async () => {
    const entry2 = vectorEntries[1];
    if (entry2 === undefined) throw new Error("missing vector entry 2");
    const response = await initChain(toWireEntry(entry2));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("bad-seq");
  });
});

describe("チェーン再生(正常系ベクター。create/rotate は複合経由)", () => {
  // 正規チェーン全 24 エントリ(2026-09-14 ES + PF1 — seq 20〜24 の四眼 4 op を含む。
  // K5 で受理ガードを外し全再生に戻した)
  const lastSeq = vectorEntries[vectorEntries.length - 1]?.seq ?? 0;

  it("accepts the whole vector chain with interleaved boundary checkpoints, append-only", async () => {
    // 複合(vector seq 3 / 4 / 8 / 10 / 11)ごとに境界 checkpoint(H+2)が
    // 挿入される(§12-4)。ベクターの seq 1〜24 はこの順序で全受理される
    expect(lastSeq).toBeGreaterThan(firstFourEyesSeq);
    const { head } = await replayVectorChain(lastSeq);

    const response = await getChain(vectorProjectId);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      projectId: string;
      entries: ChainEntry[];
      headSeq: number;
      headHashHex: string;
    };
    // 期待 op 列 = ベクター本編の op 列に、create / rotate の直後の境界 checkpoint を挿入したもの
    const expectedOps = vectorEntries.flatMap((v) =>
      v.op === "create_environment" || v.op === "rotate_epoch" ? [v.op, "checkpoint"] : [v.op],
    );
    expect(body.projectId).toBe(vectorProjectId);
    expect(body.headSeq).toBe(expectedOps.length);
    expect(body.headHashHex).toBe(head.hashHex);
    expect(body.entries.map((entry) => entry.seq)).toEqual(expectedOps.map((_, i) => i + 1));
    expect(body.entries.map((entry) => entry.op)).toEqual(expectedOps);
    // checkpoint を除いた op 列はベクター本編と一致する(同じ操作列の受理)
    expect(
      body.entries.filter((entry) => entry.op !== "checkpoint").map((entry) => entry.op),
    ).toEqual(vectorEntries.map((v) => v.op));

    // DO SQLite の実データを直接確認する(append-only 保存とハッシュ列)。最初の
    // 複合の checkpoint 挿入まで(seq 1〜3)はベクターの固定バイトのまま受理される
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec("SELECT seq, entry_hash_hex FROM chain_entries ORDER BY seq")
        .toArray();
      expect(rows.length).toBe(expectedOps.length);
      expect(rows.slice(0, 3).map((row) => row["entry_hash_hex"])).toEqual(
        vectorEntries.slice(0, 3).map((v) => v.entry_hash_hex),
      );
    });
  });
});

type AuditRow = Record<string, unknown>;

/** 監査行の payload(JSON 文字列)を読む。 */
const payloadOf = (row: AuditRow): Record<string, unknown> =>
  JSON.parse(String(row["payload"])) as Record<string, unknown>;

/** chain_seq の行(監査 seq 順)。 */
const rowsAt = (rows: readonly AuditRow[], chainSeq: number): AuditRow[] =>
  rows.filter((row) => row["chain_seq"] === chainSeq);

/** chain_seq の nth 行(無ければ失敗)。 */
function rowAt(rows: readonly AuditRow[], chainSeq: number, nth = 0): AuditRow {
  const row = rowsAt(rows, chainSeq)[nth];
  if (row === undefined) throw new Error(`no audit row #${nth} for chain_seq=${chainSeq}`);
  return row;
}

/** 再生済みチェーンから op の nth エントリの seq を引く。 */
function seqOf(entries: readonly ChainEntry[], op: ChainEntry["op"], nth = 0): number {
  const found = entries.filter((entry) => entry.op === op)[nth];
  if (found === undefined) throw new Error(`replayed chain has no ${op} #${nth}`);
  return found.seq;
}

async function projectionRowsFor(userId: string): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM project_members WHERE project_id = ? AND user_id = ?",
  )
    .bind(vectorProjectId, userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

describe("四眼の 4 op の受理とミラー(PF1 — K5。AUDIT_SPEC §3.4)", () => {
  // 正規チェーンの seq 20〜24 = set_approval_policy / propose(change_role: devmember →
  // reader listed{dev} — 提案者 owner-0001 の 1 票)/ approve(owner-0014 — 定足数 2 に
  // 到達 = 完成)/ propose(remove_member — 提案者 devadmin-0011 は admin で票なし)/
  // withdraw(owner-0015)。再生後の実 seq は境界 checkpoint の挿入分だけずれるので、
  // 取得したチェーンから op で引く
  it("mirrors the four-eyes entries with proposalChainSeq / completed and writes the applied inner-op row", async () => {
    await replayVectorChain(vectorEntries[vectorEntries.length - 1]?.seq ?? 0);
    const chain = await readChain();
    const policySeq = seqOf(chain.entries, "set_approval_policy");
    const firstProposeSeq = seqOf(chain.entries, "propose", 0);
    const approveSeq = seqOf(chain.entries, "approve");
    const secondProposeSeq = seqOf(chain.entries, "propose", 1);
    const withdrawSeq = seqOf(chain.entries, "withdraw");
    const rows = await readAuditEvents(vectorProjectId);

    // 1 エントリ 1 行(全単射)— 完成した approve だけが 2 行目(適用行)を持つ
    for (const entry of chain.entries) {
      expect(rowsAt(rows, entry.seq).length, `chain_seq=${entry.seq} (${entry.op})`).toBe(
        entry.seq === approveSeq ? 2 : 1,
      );
    }

    const policy = rowAt(rows, policySeq);
    expect(policy["event"]).toBe("chain.approval_policy_changed");
    expect(payloadOf(policy)).toEqual({
      ops: ["change_role", "grant_server", "remove_member", "set_approval_policy"],
      requiredApprovals: 2,
    });

    const proposed = rowAt(rows, firstProposeSeq);
    expect(proposed["event"]).toBe("chain.proposed");
    expect(payloadOf(proposed)).toMatchObject({ innerOp: "change_role" });
    // 内側 payload は写さない(正はチェーン)
    expect(payloadOf(proposed)["inner"]).toBeUndefined();

    // 完成した approve: chain.approved(completed = true)+ 内側 op の適用行(同 chain_seq。
    // actor = 提案者 owner-0001・target = devmember・viaProposalSeq = 提案の seq)
    const approved = rowAt(rows, approveSeq, 0);
    const applied = rowAt(rows, approveSeq, 1);
    expect(approved["event"]).toBe("chain.approved");
    expect(approved["actor_user_id"]).toBe("user-owner-0014");
    expect(payloadOf(approved)).toEqual({ proposalChainSeq: firstProposeSeq, completed: true });
    expect(applied["event"]).toBe("chain.role_changed");
    expect(applied["actor_user_id"]).toBe("user-owner-0001");
    expect(applied["target_user_id"]).toBe("user-devmember-0010");
    expect(payloadOf(applied)).toEqual({
      newRole: "reader",
      scopeKind: "listed",
      scopeEnvironmentIds: ["env-dev-0002"],
      viaProposalSeq: firstProposeSeq,
    });
    // 監査 seq はミラー行 → 適用行の順(検出はミラーの後に読む)
    expect(Number(approved["seq"])).toBeLessThan(Number(applied["seq"]));

    const withdrawn = rowAt(rows, withdrawSeq);
    expect(withdrawn["event"]).toBe("chain.proposal_withdrawn");
    expect(payloadOf(withdrawn)).toEqual({ proposalChainSeq: secondProposeSeq });

    // devmember は seq 13 の add_member 受理で投影行を持ち(§11-5 (2))、降格(適用済み
    // change_role)では消えない
    expect(await projectionRowsFor("user-devmember-0010")).toBe(1);
  });

  it("writes the applied member_removed row only for the approve that reaches the quorum and drops the projection row", async () => {
    // 派生チェーン proposal-completed(base 23): approve@24(owner-0014 — 1 票・未完成)
    // → approve@25(owner-0015 — 定足数 2 で完成 = remove_member devmember の適用)
    const extended = vectorExtendedChains["proposal-completed"];
    const last = extended?.entries[extended.entries.length - 1];
    if (last === undefined) throw new Error("missing extended chain proposal-completed");
    // replayNegativePrefix は chain 指定で派生チェーンの全エントリを再生する
    const { head } = await replayNegativePrefix({
      entry: { seq: last.seq + 1 },
      chain: "proposal-completed",
    });

    const chain = await readChain();
    // 正規チェーンの完成 approve(seq 22 相当)に派生チェーンの 2 本が続く
    const firstApproveSeq = seqOf(chain.entries, "approve", 1);
    const completingSeq = seqOf(chain.entries, "approve", 2);
    expect(completingSeq).toBe(head.seq);
    const rows = await readAuditEvents(vectorProjectId);

    expect(rowsAt(rows, firstApproveSeq).map((row) => row["event"])).toEqual(["chain.approved"]);
    expect(payloadOf(rowAt(rows, firstApproveSeq))).toMatchObject({ completed: false });

    const approved = rowAt(rows, completingSeq, 0);
    const applied = rowAt(rows, completingSeq, 1);
    expect(approved["event"]).toBe("chain.approved");
    expect(payloadOf(approved)).toMatchObject({ completed: true });
    expect(applied["event"]).toBe("chain.member_removed");
    expect(applied["target_user_id"]).toBe("user-devmember-0010");
    // 提案者(devadmin-0011 — admin。票にはならないが適用行の actor)
    expect(applied["actor_user_id"]).toBe("user-devadmin-0011");
    expect(payloadOf(applied)).toEqual({ viaProposalSeq: seqOf(chain.entries, "propose", 1) });

    // §11-5 (3): 適用された remove_member は投影行を消す(worker の D1 後処理 — K5-H)
    expect(await projectionRowsFor("user-devmember-0010")).toBe(0);
    // 削除されたメンバーはもう読めない(§11-2)
    const denied = await getChain(vectorProjectId, bearer(tokenFor("user-devmember-0010")));
    expect(denied.status).toBe(404);
    // チェーン行の数 = ミラー行の chain_seq の集合(適用行は既存 seq の 2 行目)
    const distinct = new Set(rows.map((row) => row["chain_seq"]).filter((seq) => seq !== null));
    expect(distinct.size).toBe(chain.headSeq);
    expect(
      await queryProjectDo(vectorProjectId, "SELECT COUNT(*) AS n FROM chain_entries"),
    ).toEqual([{ n: chain.headSeq }]);
  });
});

const readChain = async () => {
  const response = await getChain(vectorProjectId);
  expect(response.status).toBe(200);
  return (await response.json()) as {
    projectId: string;
    entries: ChainEntry[];
    headSeq: number;
    headHashHex: string;
  };
};

describe("チェーンの差分ロードキャッシュ(chain-store.ts StateCache.chain)", () => {
  it("追記→読み取り→追記の往復がフルロードと同一結果を返す(複合追記の増分反映込み)", async () => {
    // seq 1〜12 の再生は「追記(増分反映)→ 読み取り(差分ロード)」を毎手で
    // 往復し、複合受理(create/rotate + 境界 checkpoint の 2 エントリ insertSync
    // 経路)もキャッシュに反映する
    const { members } = await replayVectorChain(12);
    const warm = await readChain();

    // DO 退去 = インスタンスメモリのキャッシュ破棄。次の読み取りはフルロードに
    // フォールバックし、ウォームキャッシュの結果と完全一致しなければならない
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(vectorProjectId));
    await evictDurableObject(stub);
    const cold = await readChain();
    expect(cold).toEqual(warm);

    // フォールバック後も追記を受理でき、以降の読み取りへ増分反映される
    const target = members.find((userId) => userId !== "user-owner-0001");
    if (target === undefined) throw new Error("vector chain has no removable member");
    const { entry } = await signEntryAt({
      seq: warm.headSeq + 1,
      prevHashHex: warm.headHashHex,
      actorUserId: "user-owner-0001",
      operation: { op: "remove_member", payload: { targetUserId: target } },
    });
    const appended = await appendEntry(vectorProjectId, warm.headHashHex, entry);
    expect(appended.status).toBe(200);
    const after = await readChain();
    expect(after.headSeq).toBe(warm.headSeq + 1);
    expect(after.entries.slice(0, warm.headSeq)).toEqual(warm.entries);
    expect(after.entries[warm.headSeq]).toEqual(entry);

    // もう一度キャッシュを破棄してもフルロードが同一結果に到達する
    await evictDurableObject(stub);
    const coldAfter = await readChain();
    expect(coldAfter).toEqual(after);
  });
});
