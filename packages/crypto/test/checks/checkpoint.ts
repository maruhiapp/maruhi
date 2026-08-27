// CRYPTO_SPEC §6.2 checkpoint op(PR-F3a — 2026-08-27 セッション 33)のチェック:
// - values_digest 正規形(chain-entries.json の values_digests セクション)を
//   computeEnvValuesDigest が再現する(入力順非依存・重複拒否・境界)
// - 検証済みチェーンからの導出(ChainState.checkpoints)と履歴索引の照会
//   (checkpointTupleFor / latestCheckpointFor — §4.3 (2) の照合材料)
// - 同一 (environment, manifest_version) タプルの equivocation 格下げ
//   (session-33 裁定 B: (epoch, manifest_sig_hash) の相違 = conflicting。
//   values_digest の相違は正当な再公証であり conflict ではない)
//
// 合意規則の拒否側(理由コード・検査順序)は chain-negative.ts の
// authorization スイープが chain-entries.json の checkpoint negative で固定する。

import type { ChainEntry, ChainHistoryIndex, UnsignedChainEntry } from "../../src/index.ts";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  type EnvValuesDigestEntry,
  importSigningKeyPair,
  signChainEntry,
  verifyChainWithHistory,
} from "../../src/index.ts";
import {
  toTypedEntry,
  typedEntries,
  vectorExtendedChains,
  vectorKeys,
  vectorValuesDigests,
} from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex } from "./support.ts";

function typedDigestEntries(
  entries: (typeof vectorValuesDigests)[number]["entries"],
): EnvValuesDigestEntry[] {
  return entries.map((entry) => ({
    variableId: entry.variable_id,
    version: Number(entry.version),
    valueSigHashHex: entry.value_sig_hash_hex,
  }));
}

/** values_digests セクション: env values digest の LP 正規形の固定(§6.2)。 */
async function valuesDigestVectorChecks(c: Checks): Promise<void> {
  for (const digestCase of vectorValuesDigests) {
    const computed = await computeEnvValuesDigest(
      "maruhi/v1",
      typedDigestEntries(digestCase.entries),
    );
    c.push(
      `checkpoint values-digest ${digestCase.name}`,
      computed.ok && computed.value === digestCase.values_digest_hex,
      computed.ok ? undefined : JSON.stringify(computed.error),
    );
    // 入力順に依らず正規形へ正規化される(バイト昇順は関数の内部規約)
    const reversed = await computeEnvValuesDigest(
      "maruhi/v1",
      typedDigestEntries(digestCase.entries.toReversed()),
    );
    c.push(
      `checkpoint values-digest ${digestCase.name}: order-independent input`,
      reversed.ok && reversed.value === digestCase.values_digest_hex,
    );
  }
  // 重複 variable_id は「active 変数ごとに最新 version 1 本」の不変条件違反
  const single = vectorValuesDigests.find((digestCase) => digestCase.name === "single-entry");
  if (single !== undefined && single.entries.length === 1) {
    const duplicated = await computeEnvValuesDigest(
      "maruhi/v1",
      typedDigestEntries([...single.entries, ...single.entries]),
    );
    c.push(
      "checkpoint values-digest: duplicate variable id rejected",
      !duplicated.ok && duplicated.error.kind === "InvalidInput",
    );
  }
}

/** 構造不正(version 0 / 非整数 / 大文字 hex / 空 id / 空 suite)は InvalidInput。 */
async function valuesDigestInvalidInputChecks(c: Checks): Promise<void> {
  const validEntry: EnvValuesDigestEntry = {
    variableId: "var-a-0001",
    version: 1,
    valueSigHashHex: "ab".repeat(32),
  };
  const badEntries: readonly { readonly name: string; readonly entry: EnvValuesDigestEntry }[] = [
    { name: "version zero", entry: { ...validEntry, version: 0 } },
    { name: "fractional version", entry: { ...validEntry, version: 1.5 } },
    {
      name: "uppercase value sig hash",
      entry: { ...validEntry, valueSigHashHex: "AB".repeat(32) },
    },
    { name: "empty variable id", entry: { ...validEntry, variableId: "" } },
  ];
  for (const bad of badEntries) {
    const result = await computeEnvValuesDigest("maruhi/v1", [bad.entry]);
    c.push(
      `checkpoint values-digest invalid input: ${bad.name}`,
      !result.ok && result.error.kind === "InvalidInput",
    );
  }
  const emptySuite = await computeEnvValuesDigest("", []);
  c.push(
    "checkpoint values-digest invalid input: empty suite",
    !emptySuite.ok && emptySuite.error.kind === "InvalidInput",
  );
}

/** checkpoint-baseline 派生チェーン(正規 12 + seq 13/14)の検証済みビュー。 */
async function baselineView() {
  const extended = vectorExtendedChains["checkpoint-baseline"];
  if (extended === undefined) {
    throw new Error("checkpoint-baseline extended chain missing");
  }
  const entries = [
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
  ];
  const result = await verifyChainWithHistory(entries);
  if (!result.ok) {
    throw new Error("checkpoint-baseline chain failed verification");
  }
  return { extended, entries, ...result.value };
}

function tupleChecks(c: Checks, history: ChainHistoryIndex): void {
  // (env-dev, 3) は seq 13 のみが運ぶ
  const dev = history.checkpointTupleFor("env-dev-0002", 3);
  c.push("checkpoint history: unique tuple for env-dev", dev?.kind === "unique" && dev.seq === 13);
  // (env-prod, 2) は seq 13 / 14 の両方が同一 (epoch, manifest_sig_hash) で運ぶ
  // (values_digest だけが異なる正当な再公証)— unique のまま、seq は初出
  const prod = history.checkpointTupleFor("env-prod-0001", 2);
  c.push(
    "checkpoint history: re-attested tuple stays unique",
    prod?.kind === "unique" && prod.seq === 13 && prod.epoch === 2,
  );
  // 運ばれていない座標・未知環境・不正 manifestVersion は undefined
  c.push(
    "checkpoint history: uncovered manifest version is undefined",
    history.checkpointTupleFor("env-prod-0001", 1) === undefined,
  );
  c.push(
    "checkpoint history: unknown environment is undefined",
    history.checkpointTupleFor("env-ghost-9999", 1) === undefined,
  );
  c.push(
    "checkpoint history: non-integer manifest version is undefined",
    history.checkpointTupleFor("env-prod-0001", 2.5) === undefined &&
      history.checkpointTupleFor("env-prod-0001", 0) === undefined,
  );
}

async function signAs(userId: string, entry: UnsignedChainEntry): Promise<ChainEntry> {
  const keys = vectorKeys[userId];
  if (keys === undefined) {
    throw new Error(`chain vector keys for ${userId} missing`);
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    throw new Error("signing key import failed");
  }
  const signed = await signChainEntry({ entry, signingKey: pair.value.privateKey });
  if (!signed.ok) {
    throw new Error("chain entry signing failed");
  }
  return signed.value;
}

/**
 * equivocation 格下げ(session-33 裁定 B): checkpoint-baseline の先へ、同一
 * (env-prod, manifestVersion 2) を**異なる manifest_sig_hash** で公証する
 * checkpoint を追記する。この追記自体は合意規則で有効(非後退は等号を許し、
 * 内容はチェーン検証で検証不能)だが、履歴索引の照会は conflicting へ落ち、
 * マニフェスト検証(§4.3 (2) — PR-F3b)が硬い証拠として拒否する材料になる。
 */
async function equivocationChecks(c: Checks): Promise<void> {
  const view = await baselineView();
  const admin = vectorKeys["user-admin-0003"];
  const head14 = view.entries[view.entries.length - 1];
  if (admin === undefined || head14 === undefined) {
    c.push("checkpoint history: setup", false, "fixture missing");
    return;
  }
  const baseTuple = view.state.checkpoints.get("env-prod-0001");
  if (baseTuple === undefined) {
    c.push("checkpoint history: setup", false, "baseline tuple missing");
    return;
  }
  const forged = await signAs("user-admin-0003", {
    suite: "maruhi/v1",
    seq: 15,
    prevHashHex: await computeChainEntryHash(head14),
    actor: { userId: "user-admin-0003", keyFingerprintHex: admin.key_fingerprint_hex },
    timestampMs: head14.timestampMs + 1000,
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: "env-prod-0001",
          epoch: 2,
          manifestVersion: 2,
          // 同座標へ別内容のマニフェストハッシュ(equivocation の形)
          manifestSigHashHex: "ef".repeat(32),
          valuesDigestHex: baseTuple.valuesDigestHex,
        },
      ],
      auditHeadHashHex: "",
    },
  });
  const result = await verifyChainWithHistory([...view.entries, forged]);
  if (!result.ok) {
    c.push("checkpoint history: equivocating append verifies", false, JSON.stringify(result.error));
    return;
  }
  // 追記自体は有効(合意規則は内容を検証しない)…
  c.push("checkpoint history: equivocating append verifies", true);
  // …が、(env, manifestVersion) の照会は conflicting へ落ちる
  c.push(
    "checkpoint history: conflicting tuple lookup",
    result.value.history.checkpointTupleFor("env-prod-0001", 2)?.kind === "conflicting",
  );
  // 別座標(env-dev, 3)の照会は影響を受けない
  c.push(
    "checkpoint history: unrelated tuple stays unique",
    result.value.history.checkpointTupleFor("env-dev-0002", 3)?.kind === "unique",
  );
}

/** 派生状態と履歴索引の一貫性: latestCheckpointFor = ChainState.checkpoints。 */
async function derivedStateChecks(c: Checks): Promise<void> {
  const view = await baselineView();
  const fromState = view.state.checkpoints.get("env-prod-0001");
  const fromHistory = view.history.latestCheckpointFor("env-prod-0001");
  c.push(
    "checkpoint history: latest checkpoint mirrors chain state",
    fromState !== undefined &&
      fromHistory !== undefined &&
      fromState.seq === fromHistory.seq &&
      fromState.valuesDigestHex === fromHistory.valuesDigestHex &&
      fromHistory.seq === 14,
  );
  c.push(
    "checkpoint history: latest checkpoint absent for uncovered environment",
    view.history.latestCheckpointFor("env-stage-0003") === undefined &&
      view.state.checkpoints.get("env-stage-0003") === undefined,
  );
  // 正規 12 エントリチェーン(checkpoint なし)では全照会が undefined
  const canonical = await verifyChainWithHistory(typedEntries);
  c.push(
    "checkpoint history: canonical chain has no tuples",
    canonical.ok &&
      canonical.value.state.checkpoints.size === 0 &&
      canonical.value.history.checkpointTupleFor("env-prod-0001", 2) === undefined &&
      canonical.value.history.latestCheckpointFor("env-prod-0001") === undefined,
  );
}

export async function checkpointChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await valuesDigestVectorChecks(c);
  await valuesDigestInvalidInputChecks(c);
  const view = await baselineView();
  tupleChecks(c, view.history);
  await derivedStateChecks(c);
  await equivocationChecks(c);
  return c.results;
}
