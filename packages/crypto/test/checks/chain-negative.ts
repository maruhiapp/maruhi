// CRYPTO_SPEC §6 のチェック(negative + 境界の positive): 改竄・移植・順序入替
// (must_fail)、認可系ベクター(署名は有効だが §6.2 の規則で拒否)、フレーミング・
// 意味検証の失敗系、および合意規則の許容側の境界(valid_appends)。

import {
  canonicalChainSignedBytes,
  type ChainEntry,
  type ChainState,
  computeChainEntryHash,
  type CryptoResult,
  type EnvironmentChainState,
  importSigningKeyPair,
  signChainEntry,
  type UnsignedChainEntry,
  verifyChain,
} from "../../src/index.ts";
import {
  toTypedEntry,
  typedEntries,
  serverGrantsMatchVector,
  vectorEntries,
  vectorEnvironmentDeks,
  vectorExtendedChains,
  vectorKeys,
  vectorNegatives,
  vectorValidAppends,
} from "./chain-vector.ts";
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

function failsWith(result: CryptoResult<ChainState>, seq: number, reason: string): boolean {
  return (
    !result.ok &&
    result.error.kind === "ChainInvalid" &&
    result.error.seq === seq &&
    result.error.reason === reason
  );
}

function entryAt(seq: number): ChainEntry {
  const entry = typedEntries[seq - 1];
  if (entry === undefined) {
    throw new Error(`chain vector entry seq ${seq} missing`);
  }
  return entry;
}

function negativeByName(name: string) {
  return vectorNegatives.find((n) => n.name === name);
}

/** ベクター固定鍵(欠落はフィクスチャ破損 = throw。entryAt と同じ流儀)。 */
function keysOf(userId: string) {
  const keys = vectorKeys[userId];
  if (keys === undefined) {
    throw new Error(`chain vector keys for ${userId} missing`);
  }
  return keys;
}

interface TamperVariant {
  readonly name: string;
  readonly entry: ChainEntry;
  readonly expect: string;
}

/** 期待した op のベクターエントリ(不一致はフィクスチャ破損 = throw)。 */
function entryOfOp<K extends ChainEntry["op"]>(seq: number, op: K): ChainEntry & { op: K } {
  const entry = entryAt(seq);
  if (entry.op !== op) {
    throw new Error(`chain vector seq ${seq}: expected ${op}, got ${entry.op}`);
  }
  return entry as ChainEntry & { op: K };
}

/** ベクターの (environment, epoch) のコミットメント(欠落はフィクスチャ破損 = throw)。 */
function vectorCommitmentOf(environmentId: string, epoch: number): string {
  const commitment = vectorEnvironmentDeks[environmentId]?.[String(epoch)]?.dek_commitment_hex;
  if (commitment === undefined) {
    throw new Error(`chain vector environment_deks missing ${environmentId}#${epoch}`);
  }
  return commitment;
}

/** 改竄済み payload の typed 変種。canonical bytes がベクターの negative と一致するはず */
function payloadTamperVariants(): readonly TamperVariant[] {
  const e2 = entryOfOp(2, "add_member");
  const eChange = entryOfOp(7, "change_role");
  const eGrant = entryOfOp(9, "grant_server");
  const eRotate = entryOfOp(10, "rotate_epoch");
  const eCreate = entryOfOp(11, "create_environment");
  const eRevoke = entryOfOp(12, "revoke_server");
  const flipped = fromHex(eRevoke.payload.serverKeyFingerprintHex);
  flipped[0] = (flipped[0] ?? 0) ^ 0x01;
  const freshCommitment = vectorCommitmentOf("env-fresh-0004", 1);
  const prodCommitment = vectorCommitmentOf("env-prod-0001", 2);
  return [
    {
      name: "tampered-payload-role",
      entry: { ...e2, payload: { ...e2.payload, role: "admin" } },
      expect: "bad-signature",
    },
    {
      name: "grant-server-scope-reorder",
      entry: {
        ...eGrant,
        payload: {
          ...eGrant.payload,
          scopeEnvironmentIds: eGrant.payload.scopeEnvironmentIds.toReversed(),
        },
      },
      expect: "bad-signature",
    },
    // lease_policy の順序(要素・制約とも)も署名対象(§6.2。2026-08-12)
    {
      name: "grant-server-lease-policy-reorder",
      entry: {
        ...eGrant,
        payload: { ...eGrant.payload, leasePolicy: eGrant.payload.leasePolicy.toReversed() },
      },
      expect: "bad-signature",
    },
    {
      name: "grant-server-lease-claims-reorder",
      entry: {
        ...eGrant,
        payload: {
          ...eGrant.payload,
          leasePolicy: eGrant.payload.leasePolicy.map((element, index) =>
            index === 0
              ? { ...element, claimConstraints: element.claimConstraints.toReversed() }
              : element,
          ),
        },
      },
      expect: "bad-signature",
    },
    {
      name: "change-role-tampered-new-role",
      entry: { ...eChange, payload: { ...eChange.payload, newRole: "owner" } },
      expect: "bad-signature",
    },
    {
      name: "revoke-server-tampered-fp",
      entry: { ...eRevoke, payload: { serverKeyFingerprintHex: toHex(flipped) } },
      expect: "bad-signature",
    },
    // dek_commitment_hex も署名対象(§5.2): 差し替えは検証失敗
    {
      name: "create-env-tampered-commitment",
      entry: { ...eCreate, payload: { ...eCreate.payload, dekCommitmentHex: freshCommitment } },
      expect: "bad-signature",
    },
    {
      name: "rotate-tampered-commitment",
      entry: { ...eRotate, payload: { ...eRotate.payload, dekCommitmentHex: prodCommitment } },
      expect: "bad-signature",
    },
  ];
}

/** 署名・prev_hash を差し替えた変種(payload は元のまま) */
function headerTamperVariants(): readonly TamperVariant[] {
  const e3 = entryAt(3);
  return [
    {
      name: "wrong-signer",
      entry: { ...e3, signatureHex: negativeByName("wrong-signer")?.signature_hex ?? "" },
      expect: "bad-signature",
    },
    {
      name: "prev-hash-mismatch",
      entry: {
        ...e3,
        prevHashHex: negativeByName("prev-hash-mismatch")?.claimed_prev_hash_hex ?? "",
      },
      expect: "bad-prev-hash",
    },
  ];
}

/**
 * kind なし(暗号検証系)negative の網羅ガード: ベクター再生成で negative が
 * 増えたとき、名前ハードコードの検査(payloadTamperVariants 等)が黙って
 * 新規分を落とさないよう、全 name が検査済み集合に含まれることを固定する。
 */
function tamperCoverageCheck(c: Checks, covered: ReadonlySet<string>): void {
  // kind の語彙は undefined(暗号検証系 — 本関数の網羅対象)と "authorization"
  // (crypto / server の authorization スイープが全件を舐める)の 2 つのみ。
  // 第三の kind が導入されると両方のふるいから静かに漏れるため、語彙自体を固定する
  const unknownKinds = vectorNegatives
    .filter((negative) => negative.kind !== undefined && negative.kind !== "authorization")
    .map((negative) => negative.name);
  c.push(
    "chain negative: kind vocabulary is fixed",
    unknownKinds.length === 0,
    unknownKinds.length === 0 ? undefined : `unknown kind: ${unknownKinds.join(", ")}`,
  );
  const uncovered = vectorNegatives
    .filter((negative) => negative.kind === undefined)
    .map((negative) => negative.name)
    .filter((name) => !covered.has(name));
  c.push(
    "chain negative: every non-authorization vector is covered",
    uncovered.length === 0,
    uncovered.length === 0 ? undefined : `uncovered: ${uncovered.join(", ")}`,
  );
}

async function tamperedChecks(c: Checks): Promise<void> {
  const payloadVariants = payloadTamperVariants();
  const headerVariants = headerTamperVariants();
  tamperCoverageCheck(
    c,
    new Set([
      ...payloadVariants.map((variant) => variant.name),
      ...headerVariants.map((variant) => variant.name),
      // bytesLevelChecks が担う 4 件(この実装からは生成されないバイト列)
      "field-order-swap",
      "grant-server-scope-flat-concat",
      "grant-server-lease-policy-flat-concat",
      "grant-server-lease-policy-dropped",
    ]),
  );
  for (const variant of [...payloadVariants, ...headerVariants]) {
    const vector = negativeByName(variant.name);
    if (vector === undefined) {
      c.push(`chain negative: ${variant.name}`, false, "vector missing");
      continue;
    }
    // payload 改竄系は「改竄後の正規化バイト列」がベクターと一致することも確認する
    const canonicalMatches =
      vector.signed_bytes_hex === undefined ||
      variant.name === "wrong-signer" ||
      toHex(canonicalChainSignedBytes(variant.entry)) === vector.signed_bytes_hex;
    const prefix = typedEntries.slice(0, variant.entry.seq - 1);
    const result = await verifyChain([...prefix, variant.entry]);
    c.push(
      `chain negative: ${variant.name}`,
      canonicalMatches && failsWith(result, variant.entry.seq, variant.expect),
    );
  }
}

async function bytesLevelChecks(c: Checks): Promise<void> {
  // 正規化の順序・入れ子 LP を崩したバイト列は、この実装からは生成されず
  // (canonical bytes と不一致)、元の署名も通らないことを確認する。
  // lease-policy-flat-concat は 3 段入れ子の平坦化、lease-policy-dropped は
  // 旧 3 フィールド形式(4 フィールドが正規形であることの固定 — §6.2)
  for (const name of [
    "field-order-swap",
    "grant-server-scope-flat-concat",
    "grant-server-lease-policy-flat-concat",
    "grant-server-lease-policy-dropped",
  ]) {
    const vector = negativeByName(name);
    if (
      vector?.signed_bytes_hex === undefined ||
      vector.signature_hex === undefined ||
      vector.verify_key_hex === undefined ||
      vector.base_seq === undefined
    ) {
      c.push(`chain negative: ${name}`, false, "vector missing");
      continue;
    }
    const base = entryAt(vector.base_seq);
    const canonicalDiffers = toHex(canonicalChainSignedBytes(base)) !== vector.signed_bytes_hex;
    const key = await crypto.subtle.importKey(
      "raw",
      fromHex(vector.verify_key_hex) as BufferSource,
      "Ed25519",
      false,
      ["verify"],
    );
    const signatureRejected = !(await crypto.subtle.verify(
      "Ed25519",
      key,
      fromHex(vector.signature_hex) as BufferSource,
      fromHex(vector.signed_bytes_hex) as BufferSource,
    ));
    c.push(`chain negative: ${name}`, canonicalDiffers && signatureRejected);
  }
}

/** 認可 negative の前提チェーン: 正規プレフィックス、または extended_chains の派生。 */
function authzPrefix(chainName: string | undefined, seq: number): readonly ChainEntry[] {
  if (chainName === undefined) {
    return typedEntries.slice(0, seq - 1);
  }
  const extended = vectorExtendedChains[chainName];
  if (extended === undefined) {
    throw new Error(`chain vector extended chain ${chainName} missing`);
  }
  return [
    ...typedEntries.slice(0, extended.base_seq),
    ...extended.entries.map((entry) => toTypedEntry(entry)),
  ];
}

async function authorizationChecks(c: Checks): Promise<void> {
  // kind = "authorization": 署名・連鎖は有効で、§6.2 の権限規則のみで拒否すべき
  for (const vector of vectorNegatives) {
    if (vector.kind !== "authorization" || vector.entry === undefined) {
      continue;
    }
    const entry = toTypedEntry(vector.entry);
    const prefix = authzPrefix(vector.chain, entry.seq);
    const result = await verifyChain([...prefix, entry]);
    c.push(
      `chain authz: ${vector.name}`,
      failsWith(result, entry.seq, vector.expected_reason ?? ""),
    );
  }
}

async function extendedChainChecks(c: Checks): Promise<void> {
  // extended_chains: 派生チェーン自体が受理されること(許容側の境界)。
  // server-key-member-sock は「add_member の鍵一意性の索引は現メンバーの鍵のみで、
  // 有効 grant のサーバー鍵は対象外」という §6.2 の線引きを固定する
  for (const [name, extended] of Object.entries(vectorExtendedChains)) {
    const chain = [
      ...typedEntries.slice(0, extended.base_seq),
      ...extended.entries.map((entry) => toTypedEntry(entry)),
    ];
    const result = await verifyChain(chain);
    c.push(
      `chain extended: ${name} verifies`,
      result.ok && membersMatch(result.value, extended.expected_members),
    );
  }
}

async function framingChecks(c: Checks): Promise<void> {
  const e1 = entryAt(1);
  c.push("chain framing: empty chain", failsWith(await verifyChain([]), 0, "empty-chain"));
  c.push(
    "chain framing: bad suite",
    failsWith(await verifyChain([{ ...e1, suite: "maruhi/v0" }]), 1, "bad-suite"),
  );
  c.push("chain framing: seq gap", failsWith(await verifyChain([e1, entryAt(3)]), 2, "bad-seq"));
  const secondGenesis: ChainEntry = { ...e1, seq: 2, prevHashHex: "0".repeat(64) };
  c.push(
    "chain framing: genesis only at seq 1",
    failsWith(await verifyChain([e1, secondGenesis]), 2, "bad-genesis"),
  );
  c.push(
    "chain framing: non-genesis head",
    failsWith(await verifyChain([{ ...entryAt(2), seq: 1 }]), 1, "bad-genesis"),
  );
}

async function signAs(userId: string, entry: UnsignedChainEntry): Promise<ChainEntry | undefined> {
  const keys = vectorKeys[userId];
  if (keys === undefined) {
    return undefined;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) {
    return undefined;
  }
  const signed = await signChainEntry({ entry, signingKey: pair.value.privateKey });
  return signed.ok ? signed.value : undefined;
}

/** 正規チェーン末尾(seq 12)に続く追記エントリの seq。 */
const NEXT_SEQ = typedEntries.length + 1;

function nextEntryBase(): Omit<UnsignedChainEntry, "op" | "payload"> {
  const head = entryAt(typedEntries.length);
  const owner = vectorKeys["user-owner-0001"];
  if (owner === undefined) {
    throw new Error("owner keys missing");
  }
  return {
    suite: "maruhi/v1",
    seq: NEXT_SEQ,
    // prev はベクター最終エントリのハッシュ(chain.ts の positive で固定済み)
    prevHashHex: "",
    actor: { userId: "user-owner-0001", keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: head.timestampMs + 1000,
  };
}

/** テスト内で追記するエントリ用の形式的に有効なコミットメント(内容は §5.2 の照合対象で、チェーン検証は形式のみ検査する)。 */
const DUMMY_COMMITMENT_HEX = "ab".repeat(32);

type SemanticBase = Omit<UnsignedChainEntry, "op" | "payload">;

function semanticCases(
  base: SemanticBase,
): readonly { name: string; entry: UnsignedChainEntry; expect: string }[] {
  const memberKeys = keysOf("user-member-0002");
  const ownerKeys = keysOf("user-owner-0001");
  return [
    {
      name: "grant_server with mismatched fingerprint",
      entry: {
        ...base,
        op: "grant_server",
        payload: {
          serverEncPubHex: memberKeys.enc_pub_hex,
          serverKeyFingerprintHex: memberKeys.key_fingerprint_hex,
          scopeEnvironmentIds: ["env-prod-0001"],
          leasePolicy: [],
        },
      },
      expect: "invalid-payload",
    },
    {
      name: "add_member duplicate",
      entry: {
        ...base,
        op: "add_member",
        payload: {
          targetUserId: "user-admin-0003",
          encPubHex: memberKeys.enc_pub_hex,
          sigPubHex: memberKeys.sig_pub_hex,
          role: "reader",
        },
      },
      expect: "duplicate-member",
    },
    {
      // 検査順序の固定(§6.2): 対象 user_id と鍵の両方が重複する場合、
      // user_id 重複(duplicate-member)が鍵重複(duplicate-member-key)より
      // 先に判定される(owner の鍵一式 = 現メンバーの鍵を流用しても理由は
      // duplicate-member)
      name: "add_member duplicate user id wins over duplicate key",
      entry: {
        ...base,
        op: "add_member",
        payload: {
          targetUserId: "user-admin-0003",
          encPubHex: ownerKeys.enc_pub_hex,
          sigPubHex: ownerKeys.sig_pub_hex,
          role: "reader",
        },
      },
      expect: "duplicate-member",
    },
    {
      name: "remove_member unknown target",
      entry: { ...base, op: "remove_member", payload: { targetUserId: "user-ghost-9999" } },
      expect: "unknown-target",
    },
    {
      name: "revoke_server without active grant",
      entry: {
        ...base,
        op: "revoke_server",
        payload: { serverKeyFingerprintHex: "00112233445566778899aabbccddeeff" },
      },
      expect: "unknown-server-grant",
    },
  ];
}

async function appendRotation(
  base: SemanticBase,
  environmentId: string,
  newEpoch: number,
): Promise<ChainState | undefined> {
  const rotate = await signAs("user-admin-0003", {
    ...base,
    actor: {
      userId: "user-admin-0003",
      keyFingerprintHex: vectorKeys["user-admin-0003"]?.key_fingerprint_hex ?? "",
    },
    op: "rotate_epoch",
    payload: {
      environmentId,
      newEpoch,
      reason: "scheduled",
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  if (rotate === undefined) {
    return undefined;
  }
  const result = await verifyChain([...typedEntries, rotate]);
  return result.ok ? result.value : undefined;
}

/** 導出状態のメンバー集合が期待(user_id → role)と一致するか。 */
function membersMatch(state: ChainState, expected: Readonly<Record<string, string>>): boolean {
  return (
    state.members.size === Object.keys(expected).length &&
    Object.entries(expected).every(([userId, role]) => state.members.get(userId)?.role === role)
  );
}

/** 導出状態の環境集合が期待(environment_id → 現エポック)と一致するか。 */
function environmentsMatch(state: ChainState, expected: Readonly<Record<string, string>>): boolean {
  return (
    state.environments.size === Object.keys(expected).length &&
    Object.entries(expected).every(
      ([environmentId, epoch]) =>
        state.environments.get(environmentId)?.currentEpoch === Number(epoch),
    )
  );
}

/** 導出状態の有効 grant 集合が期待(scope + lease_policy 込み)と一致するか。 */
function serverGrantsMatch(
  state: ChainState,
  expected: Parameters<typeof serverGrantsMatchVector>[1],
): boolean {
  return serverGrantsMatchVector(state.serverGrants, expected);
}

async function validAppendVectorChecks(c: Checks, base: SemanticBase): Promise<void> {
  // 合意規則の許容側の境界をベクター(valid_appends)で固定する:
  // (1) メンバー鍵一意性の禁止範囲は「現メンバー集合のみ」(§6.2)—
  //     「履歴全体との重複禁止」を誤って実装した検証器はここで落ちる
  // (2) 環境ライフサイクル(§6.2)— 未使用 ID の create_environment と
  //     create 済み環境(エポック 1)への初回 rotate(new_epoch 2)は受理される
  for (const append of vectorValidAppends) {
    const entry = toTypedEntry(append.entry);
    // 接続点は entry の seq が指す正規エントリの直後(seq 13 = 末尾ヘッド、
    // seq 10 = seq 9 ヘッドへの再 grant 追記 — regrant-lease-policy-revised)
    const result = await verifyChain([...typedEntries.slice(0, entry.seq - 1), entry]);
    c.push(
      `chain valid append: ${append.name}`,
      result.ok &&
        membersMatch(result.value, append.expected_members) &&
        environmentsMatch(result.value, append.expected_environments) &&
        serverGrantsMatch(result.value, append.expected_server_grants),
    );
  }

  // 索引の再形成: 復帰(re-add)で鍵が現メンバー集合に戻った後は、同じ鍵での
  // 別 user_id の追加が再び duplicate-member-key になる(remove での索引削除と
  // add での再登録の両方向を閉じる)
  const readd = vectorValidAppends.find((a) => a.name === "readd-removed-member-same-key");
  if (readd === undefined) {
    c.push("chain semantic: duplicate key rejected again after re-add", false, "vector missing");
    return;
  }
  const readdEntry = toTypedEntry(readd.entry);
  const memberKeys = keysOf("user-member-0002");
  const duplicated = await signAs("user-owner-0001", {
    ...base,
    seq: NEXT_SEQ + 1,
    prevHashHex: await computeChainEntryHash(readdEntry),
    op: "add_member",
    payload: {
      targetUserId: "user-clone-0004",
      encPubHex: memberKeys.enc_pub_hex,
      sigPubHex: memberKeys.sig_pub_hex,
      role: "member",
    },
  });
  const result =
    duplicated === undefined
      ? undefined
      : await verifyChain([...typedEntries, readdEntry, duplicated]);
  c.push(
    "chain semantic: duplicate key rejected again after re-add",
    result !== undefined && failsWith(result, NEXT_SEQ + 1, "duplicate-member-key"),
  );
}

/** 導出された環境状態が期待(現エポック・作成 seq・エポック開始 seq)と一致するか。 */
function environmentStateIs(
  environment: EnvironmentChainState | undefined,
  expected: {
    readonly currentEpoch: number;
    readonly createdAtSeq?: number;
    readonly epochStartSeqs: Readonly<Record<number, number>>;
  },
): boolean {
  if (environment === undefined || environment.currentEpoch !== expected.currentEpoch) {
    return false;
  }
  if (expected.createdAtSeq !== undefined && environment.createdAtSeq !== expected.createdAtSeq) {
    return false;
  }
  return Object.entries(expected.epochStartSeqs).every(
    ([epoch, seq]) => environment.epochStartSeqs.get(Number(epoch)) === seq,
  );
}

async function validAppendCheck(c: Checks, base: SemanticBase): Promise<void> {
  // 正しい追記(admin による rotate_epoch。現エポック 2 → 3)は検証を通り、
  // 状態(現エポック・エポック開始 seq・コミットメント)が更新される
  const extended = await appendRotation(base, "env-prod-0001", 3);
  const prod = extended?.environments.get("env-prod-0001");
  c.push(
    "chain semantic: valid append by admin verifies",
    extended?.headSeq === NEXT_SEQ &&
      environmentStateIs(prod, { currentEpoch: 3, epochStartSeqs: { 3: NEXT_SEQ } }) &&
      prod?.dekCommitments.get(3) === DUMMY_COMMITMENT_HEX,
  );

  // create_environment → rotate_epoch の 2 エントリ連鎖: 作成直後の環境の
  // エポック開始 seq(1 = create の seq、2 = rotate の seq)まで導出される
  const create = await signAs("user-owner-0001", {
    ...base,
    op: "create_environment",
    payload: { environmentId: "env-chained-0006", dekCommitmentHex: DUMMY_COMMITMENT_HEX },
  });
  if (create === undefined) {
    c.push("chain semantic: create then rotate chain", false, "signing failed");
    return;
  }
  const rotate = await signAs("user-admin-0003", {
    ...base,
    seq: NEXT_SEQ + 1,
    prevHashHex: await computeChainEntryHash(create),
    actor: {
      userId: "user-admin-0003",
      keyFingerprintHex: keysOf("user-admin-0003").key_fingerprint_hex,
    },
    op: "rotate_epoch",
    payload: {
      environmentId: "env-chained-0006",
      newEpoch: 2,
      reason: "scheduled",
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const result =
    rotate === undefined ? undefined : await verifyChain([...typedEntries, create, rotate]);
  const chained =
    result?.ok === true ? result.value.environments.get("env-chained-0006") : undefined;
  c.push(
    "chain semantic: create then rotate chain",
    environmentStateIs(chained, {
      currentEpoch: 2,
      createdAtSeq: NEXT_SEQ,
      epochStartSeqs: { 1: NEXT_SEQ, 2: NEXT_SEQ + 1 },
    }),
  );
}

/**
 * 実行時型が TS 型と乖離した悪意ある/破損エントリ(サーバー配布 JSON 想定)は
 * 例外でなく invalid-payload になる(Bugbot セキュリティ指摘 2026-08-02 の再発防止)
 */
async function malformedInputChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain malformed: setup", false, "full chain must verify");
    return;
  }
  const eGrant = entryAt(9);
  if (eGrant.op !== "grant_server") {
    c.push("chain malformed: setup", false, "seq 9 must be grant_server");
    return;
  }
  // signatureHex は形状として妥当な 64 バイトのダミーにする: 短い値だと全ケースが
  // 署名長の shape 検査で短絡し、各ケースが意図したフィールドを検査しなくなる
  const base = {
    ...nextEntryBase(),
    prevHashHex: full.value.headHashHex,
    signatureHex: "00".repeat(64),
  };
  const cases: readonly { name: string; entry: unknown }[] = [
    {
      name: "grant_server scope is not an array",
      entry: {
        ...base,
        op: "grant_server",
        payload: { ...eGrant.payload, scopeEnvironmentIds: "env-prod-0001" },
      },
    },
    {
      name: "grant_server scope contains non-string",
      entry: {
        ...base,
        op: "grant_server",
        payload: { ...eGrant.payload, scopeEnvironmentIds: [42] },
      },
    },
    {
      name: "rotate_epoch reason is not a string",
      entry: {
        ...base,
        op: "rotate_epoch",
        payload: {
          environmentId: "env-prod-0001",
          newEpoch: 3,
          reason: {},
          dekCommitmentHex: DUMMY_COMMITMENT_HEX,
        },
      },
    },
    {
      name: "rotate_epoch commitment is not a string",
      entry: {
        ...base,
        op: "rotate_epoch",
        payload: {
          environmentId: "env-prod-0001",
          newEpoch: 3,
          reason: "scheduled",
          dekCommitmentHex: 42,
        },
      },
    },
    {
      name: "create_environment commitment missing",
      entry: {
        ...base,
        op: "create_environment",
        payload: { environmentId: "env-shapeless-0007" },
      },
    },
    {
      name: "actor missing",
      entry: { ...base, actor: undefined, op: "remove_member", payload: { targetUserId: "x" } },
    },
    {
      name: "payload missing",
      entry: { ...base, op: "remove_member", payload: undefined },
    },
    {
      name: "add_member target is not a string",
      entry: {
        ...base,
        op: "add_member",
        payload: { ...entryAt(2).payload, targetUserId: 123 },
      },
    },
    {
      name: "signature missing",
      entry: {
        ...base,
        signatureHex: undefined,
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    {
      name: "signature is null",
      entry: {
        ...base,
        signatureHex: null,
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    {
      name: "signature hex oversized",
      entry: {
        ...base,
        signatureHex: "ab".repeat(500_000),
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    {
      name: "actor fingerprint hex oversized",
      entry: {
        ...base,
        actor: { userId: "user-owner-0001", keyFingerprintHex: "ab".repeat(500_000) },
        op: "remove_member",
        payload: { targetUserId: "x" },
      },
    },
    { name: "entry slot is null", entry: null },
    { name: "entry slot is a string", entry: "not-an-entry" },
  ];
  for (const item of cases) {
    // 例外を投げず invalid-payload の CryptoResult で返ることを検査する
    try {
      const result = await verifyChain([...typedEntries, item.entry as ChainEntry]);
      c.push(`chain malformed: ${item.name}`, failsWith(result, NEXT_SEQ, "invalid-payload"));
    } catch (error) {
      c.push(`chain malformed: ${item.name}`, false, `threw: ${String(error)}`);
    }
  }
}

async function regrantWideningCheck(c: Checks): Promise<void> {
  // 再 grant のスコープ拡大(旧 ⊆ 新)は受理され、スコープが更新される。
  // 縮小の拒否(grant-scope-narrowed)はベクター authz-grant-scope-narrowed が固定する
  const check = "chain semantic: re-grant widening accepted";
  const eGrant = entryAt(9);
  const owner = vectorKeys["user-owner-0001"];
  if (eGrant.op !== "grant_server" || owner === undefined) {
    c.push(check, false, "setup failed");
    return;
  }
  const widened = await signAs("user-owner-0001", {
    suite: "maruhi/v1",
    seq: 10,
    prevHashHex: vectorEntries[8]?.entry_hash_hex ?? "",
    actor: { userId: "user-owner-0001", keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: eGrant.timestampMs + 500,
    op: "grant_server",
    payload: {
      ...eGrant.payload,
      scopeEnvironmentIds: [...eGrant.payload.scopeEnvironmentIds, "env-stage-0003"],
    },
  });
  if (widened === undefined) {
    c.push(check, false, "signing failed");
    return;
  }
  const result = await verifyChain([...typedEntries.slice(0, 9), widened]);
  if (!result.ok) {
    c.push(check, false, "widened re-grant must verify");
    return;
  }
  const grant = result.value.serverGrants.get(eGrant.payload.serverKeyFingerprintHex);
  c.push(
    check,
    grant !== undefined &&
      grant.scopeEnvironmentIds.length === 3 &&
      // 二層判定の独立: scope だけ触った再 grant でも lease_policy は新 payload の値
      // (ここでは元と同じ 2 要素)に置換される
      grant.leasePolicy.length === eGrant.payload.leasePolicy.length,
  );
}

/** フィールドサイズ上限(§6.1)の境界: 1024 バイトちょうどは受理、バイト数基準で判定 */
async function fieldSizeBoundaryChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain field-size: setup", false, "full chain must verify");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex };
  const adminActor = {
    userId: "user-admin-0003",
    keyFingerprintHex: vectorKeys["user-admin-0003"]?.key_fingerprint_hex ?? "",
  };

  // reason がちょうど 1024 バイト(ASCII)→ 受理される
  const atLimit = await signAs("user-admin-0003", {
    ...base,
    actor: adminActor,
    op: "rotate_epoch",
    payload: {
      environmentId: "env-prod-0001",
      newEpoch: 3,
      reason: "y".repeat(1024),
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const accepted =
    atLimit === undefined ? undefined : await verifyChain([...typedEntries, atLimit]);
  c.push("chain field-size: 1024-byte reason accepted", accepted !== undefined && accepted.ok);

  // ㊙(3 バイト)× 342 = 1026 バイト: コード単位数は 342 ≤ 1024 だが
  // UTF-8 バイト数で超過 → 拒否(上限がバイト基準であることの固定)
  const multibyte = await signAs("user-admin-0003", {
    ...base,
    actor: adminActor,
    op: "rotate_epoch",
    payload: {
      environmentId: "env-prod-0001",
      newEpoch: 3,
      reason: "㊙".repeat(342),
      dekCommitmentHex: DUMMY_COMMITMENT_HEX,
    },
  });
  const rejected =
    multibyte === undefined ? undefined : await verifyChain([...typedEntries, multibyte]);
  c.push(
    "chain field-size: multibyte over-limit reason rejected",
    rejected !== undefined && failsWith(rejected, NEXT_SEQ, "invalid-payload"),
  );
}

/** 署名は正しいが意味的に不正なエントリ(vector 外の失敗系)を owner 鍵で作って検査 */
async function semanticChecks(c: Checks): Promise<void> {
  const full = await verifyChain(typedEntries);
  if (!full.ok) {
    c.push("chain semantic: setup", false, "full chain must verify");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex };
  for (const item of semanticCases(base)) {
    const signed = await signAs("user-owner-0001", item.entry);
    if (signed === undefined) {
      c.push(`chain semantic: ${item.name}`, false, "signing failed");
      continue;
    }
    const result = await verifyChain([...typedEntries, signed]);
    c.push(`chain semantic: ${item.name}`, failsWith(result, NEXT_SEQ, item.expect));
  }
  await validAppendCheck(c, base);
  await validAppendVectorChecks(c, base);
}

export async function chainNegativeChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await tamperedChecks(c);
  await bytesLevelChecks(c);
  await authorizationChecks(c);
  await extendedChainChecks(c);
  await framingChecks(c);
  await semanticChecks(c);
  await regrantWideningCheck(c);
  await malformedInputChecks(c);
  await fieldSizeBoundaryChecks(c);
  return c.results;
}
