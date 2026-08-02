// CRYPTO_SPEC §6 のチェック(negative): 改竄・移植・順序入替(must_fail)、
// 認可系ベクター(署名は有効だが §6.2 の role 規則で拒否)、フレーミング・
// 意味検証の失敗系。

import {
  canonicalChainSignedBytes,
  type ChainEntry,
  type ChainState,
  type CryptoResult,
  importSigningKeyPair,
  signChainEntry,
  type UnsignedChainEntry,
  verifyChain,
} from "../../src/index.ts";
import {
  toTypedEntry,
  typedEntries,
  vectorEntries,
  vectorKeys,
  vectorNegatives,
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

interface TamperVariant {
  readonly name: string;
  readonly entry: ChainEntry;
  readonly expect: string;
}

/** 改竄済み payload の typed 変種。canonical bytes がベクターの negative と一致するはず */
function payloadTamperVariants(): readonly TamperVariant[] {
  const e2 = entryAt(2);
  const e6 = entryAt(6);
  const e7 = entryAt(7);
  const e9 = entryAt(9);
  if (
    e2.op !== "add_member" ||
    e6.op !== "change_role" ||
    e7.op !== "grant_server" ||
    e9.op !== "revoke_server"
  ) {
    throw new Error("chain vector ops unexpected");
  }
  const flipped = fromHex(e9.payload.serverKeyFingerprintHex);
  flipped[0] = (flipped[0] ?? 0) ^ 0x01;
  return [
    {
      name: "tampered-payload-role",
      entry: { ...e2, payload: { ...e2.payload, role: "admin" } },
      expect: "bad-signature",
    },
    {
      name: "grant-server-scope-reorder",
      entry: {
        ...e7,
        payload: {
          ...e7.payload,
          scopeEnvironmentIds: e7.payload.scopeEnvironmentIds.toReversed(),
        },
      },
      expect: "bad-signature",
    },
    {
      name: "change-role-tampered-new-role",
      entry: { ...e6, payload: { ...e6.payload, newRole: "owner" } },
      expect: "bad-signature",
    },
    {
      name: "revoke-server-tampered-fp",
      entry: { ...e9, payload: { serverKeyFingerprintHex: toHex(flipped) } },
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

async function tamperedChecks(c: Checks): Promise<void> {
  for (const variant of [...payloadTamperVariants(), ...headerTamperVariants()]) {
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
  // (canonical bytes と不一致)、元の署名も通らないことを確認する
  for (const name of ["field-order-swap", "grant-server-scope-flat-concat"]) {
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

async function authorizationChecks(c: Checks): Promise<void> {
  // kind = "authorization": 署名・連鎖は有効で、§6.2 の権限規則のみで拒否すべき
  for (const vector of vectorNegatives) {
    if (vector.kind !== "authorization" || vector.entry === undefined) {
      continue;
    }
    const entry = toTypedEntry(vector.entry);
    const prefix = typedEntries.slice(0, entry.seq - 1);
    const result = await verifyChain([...prefix, entry]);
    c.push(
      `chain authz: ${vector.name}`,
      failsWith(result, entry.seq, vector.expected_reason ?? ""),
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

function nextEntryBase(): Omit<UnsignedChainEntry, "op" | "payload"> {
  const head = entryAt(9);
  const owner = vectorKeys["user-owner-0001"];
  if (owner === undefined) {
    throw new Error("owner keys missing");
  }
  return {
    suite: "maruhi/v1",
    seq: 10,
    // prev はベクター最終エントリのハッシュ(chain.ts の positive で固定済み)
    prevHashHex: "",
    actor: { userId: "user-owner-0001", keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: head.timestampMs + 1000,
  };
}

type SemanticBase = Omit<UnsignedChainEntry, "op" | "payload">;

function semanticCases(
  base: SemanticBase,
): readonly { name: string; entry: UnsignedChainEntry; expect: string }[] {
  const memberKeys = vectorKeys["user-member-0002"];
  return [
    {
      name: "grant_server with mismatched fingerprint",
      entry: {
        ...base,
        op: "grant_server",
        payload: {
          serverEncPubHex: memberKeys?.enc_pub_hex ?? "",
          serverKeyFingerprintHex: memberKeys?.key_fingerprint_hex ?? "",
          scopeEnvironmentIds: ["env-prod-0001"],
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
          encPubHex: memberKeys?.enc_pub_hex ?? "",
          sigPubHex: memberKeys?.sig_pub_hex ?? "",
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
    payload: { environmentId, newEpoch, reason: "scheduled" },
  });
  if (rotate === undefined) {
    return undefined;
  }
  const result = await verifyChain([...typedEntries, rotate]);
  return result.ok ? result.value : undefined;
}

async function validAppendCheck(c: Checks, base: SemanticBase): Promise<void> {
  // 正しい追記(admin による rotate_epoch。観測値 2 → 3)は検証を通り、状態が更新される
  const extended = await appendRotation(base, "env-prod-0001", 3);
  c.push(
    "chain semantic: valid append by admin verifies",
    extended !== undefined &&
      extended.headSeq === 10 &&
      extended.environmentEpochs.get("env-prod-0001") === 3,
  );

  // 未観測環境の初回 rotate は 初期値 1 + 1 = 2 のみ受理される(エポック = カウンタ)
  const withFirst = await appendRotation(base, "env-staging-0003", 2);
  c.push(
    "chain semantic: first rotation of unobserved environment to 2 accepted",
    withFirst !== undefined && withFirst.environmentEpochs.get("env-staging-0003") === 2,
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
  const e7 = entryAt(7);
  if (e7.op !== "grant_server") {
    c.push("chain malformed: setup", false, "seq 7 must be grant_server");
    return;
  }
  const base = { ...nextEntryBase(), prevHashHex: full.value.headHashHex, signatureHex: "00" };
  const cases: readonly { name: string; entry: unknown }[] = [
    {
      name: "grant_server scope is not an array",
      entry: {
        ...base,
        op: "grant_server",
        payload: { ...e7.payload, scopeEnvironmentIds: "env-prod-0001" },
      },
    },
    {
      name: "grant_server scope contains non-string",
      entry: {
        ...base,
        op: "grant_server",
        payload: { ...e7.payload, scopeEnvironmentIds: [42] },
      },
    },
    {
      name: "rotate_epoch reason is not a string",
      entry: {
        ...base,
        op: "rotate_epoch",
        payload: { environmentId: "env-prod-0001", newEpoch: 3, reason: {} },
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
      c.push(`chain malformed: ${item.name}`, failsWith(result, 10, "invalid-payload"));
    } catch (error) {
      c.push(`chain malformed: ${item.name}`, false, `threw: ${String(error)}`);
    }
  }
}

async function regrantWideningCheck(c: Checks): Promise<void> {
  // 再 grant のスコープ拡大(旧 ⊆ 新)は受理され、スコープが更新される。
  // 縮小の拒否(grant-scope-narrowed)はベクター authz-grant-scope-narrowed が固定する
  const e7 = entryAt(7);
  const owner = vectorKeys["user-owner-0001"];
  if (e7.op !== "grant_server" || owner === undefined) {
    c.push("chain semantic: re-grant widening accepted", false, "setup failed");
    return;
  }
  const widened = await signAs("user-owner-0001", {
    suite: "maruhi/v1",
    seq: 8,
    prevHashHex: vectorEntries[6]?.entry_hash_hex ?? "",
    actor: { userId: "user-owner-0001", keyFingerprintHex: owner.key_fingerprint_hex },
    timestampMs: e7.timestampMs + 500,
    op: "grant_server",
    payload: {
      ...e7.payload,
      scopeEnvironmentIds: [...e7.payload.scopeEnvironmentIds, "env-staging-0003"],
    },
  });
  const result =
    widened === undefined ? undefined : await verifyChain([...typedEntries.slice(0, 7), widened]);
  const grant =
    result !== undefined && result.ok
      ? result.value.serverGrants.get(e7.payload.serverKeyFingerprintHex)
      : undefined;
  c.push(
    "chain semantic: re-grant widening accepted",
    grant !== undefined && grant.scopeEnvironmentIds.length === 3,
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
    payload: { environmentId: "env-prod-0001", newEpoch: 3, reason: "y".repeat(1024) },
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
    payload: { environmentId: "env-prod-0001", newEpoch: 3, reason: "㊙".repeat(342) },
  });
  const rejected =
    multibyte === undefined ? undefined : await verifyChain([...typedEntries, multibyte]);
  c.push(
    "chain field-size: multibyte over-limit reason rejected",
    rejected !== undefined && failsWith(rejected, 10, "invalid-payload"),
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
    c.push(`chain semantic: ${item.name}`, failsWith(result, 10, item.expect));
  }
  await validAppendCheck(c, base);
}

export async function chainNegativeChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await tamperedChecks(c);
  await bytesLevelChecks(c);
  await authorizationChecks(c);
  await framingChecks(c);
  await semanticChecks(c);
  await regrantWideningCheck(c);
  await malformedInputChecks(c);
  await fieldSizeBoundaryChecks(c);
  return c.results;
}
