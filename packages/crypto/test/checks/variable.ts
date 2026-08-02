// CRYPTO_SPEC §4(変数値の AES-256-GCM + AAD)のチェック。
// ベクター: test-vectors/variable-encryption.json。
// 固定 nonce の暗号化 API は存在しない(nonce 再利用を構造的に不可能にするため)ので、
// 固定ベクターは復号方向で検証する(GCM は決定論的なので暗号化方向の同値性も担保される)。

import {
  buildVariableAad,
  decryptVariable,
  encryptVariable,
  generateDek,
  type VariableContext,
} from "../../src/index.ts";
import variableVectors from "../../test-vectors/variable-encryption.json" with { type: "json" };
import { type CheckResult, Checks, fromHex, toHex } from "./support.ts";

const baseVector = variableVectors.vectors[0];
if (baseVector === undefined) {
  throw new Error("variable-encryption.json: basic vector missing");
}
const base = baseVector;

function baseContext(): VariableContext {
  return {
    projectId: base.project_id,
    environmentId: base.environment_id,
    epoch: base.epoch,
    variableId: base.variable_id,
    version: base.version,
  };
}

async function vectorChecks(c: Checks): Promise<void> {
  // AAD 構築がベクターと一致
  c.push("var-enc: aad construction", toHex(buildVariableAad(baseContext())) === base.aad_hex);

  // 固定ベクターの復号
  const pt = await decryptVariable({
    dek: fromHex(base.key_hex),
    context: baseContext(),
    nonce: fromHex(base.nonce_hex),
    ciphertext: fromHex(base.ciphertext_hex),
  });
  c.push(
    "var-enc: basic vector decrypt",
    pt.ok && new TextDecoder().decode(pt.value) === base.plaintext_utf8,
  );
}

async function aadMismatchChecks(c: Checks): Promise<void> {
  // aad-environment-mismatch / aad-epoch-mismatch は文脈差し替えで再現し、
  // ベクターの decrypt_aad_hex と AAD 構築が一致することも確認する
  const mismatches: readonly { name: string; context: VariableContext }[] = [
    {
      name: "aad-environment-mismatch",
      context: { ...baseContext(), environmentId: "env-dev-0002" },
    },
    { name: "aad-epoch-mismatch", context: { ...baseContext(), epoch: 4 } },
  ];
  for (const m of mismatches) {
    const vector = variableVectors.negative.find((n) => n.name === m.name);
    const aadMatches = vector?.decrypt_aad_hex === toHex(buildVariableAad(m.context));
    const result = await decryptVariable({
      dek: fromHex(base.key_hex),
      context: m.context,
      nonce: fromHex(base.nonce_hex),
      ciphertext: fromHex(base.ciphertext_hex),
    });
    c.push(
      `var-enc negative: ${m.name}`,
      aadMatches && !result.ok && result.error.kind === "DecryptFailed",
    );
  }
}

async function tamperChecks(c: Checks): Promise<void> {
  // ciphertext-bit-flip / nonce-mismatch
  for (const n of variableVectors.negative) {
    if (n.name === "aad-environment-mismatch" || n.name === "aad-epoch-mismatch") {
      continue;
    }
    const result = await decryptVariable({
      dek: fromHex(base.key_hex),
      context: baseContext(),
      nonce: fromHex(n.decrypt_nonce_hex ?? base.nonce_hex),
      ciphertext: fromHex(n.ciphertext_hex ?? base.ciphertext_hex),
    });
    c.push(`var-enc negative: ${n.name}`, !result.ok === n.must_fail);
  }
}

async function roundtripChecks(c: Checks): Promise<void> {
  const dek = generateDek();
  const plaintext = new TextEncoder().encode("dummy-value-not-a-real-secret");
  const encrypted = await encryptVariable({ dek, context: baseContext(), plaintext });
  if (!encrypted.ok) {
    c.push("var-enc: roundtrip", false, "encrypt failed");
    return;
  }
  const decrypted = await decryptVariable({ dek, context: baseContext(), ...encrypted.value });
  c.push(
    "var-enc: roundtrip",
    encrypted.value.nonce.length === 12 &&
      decrypted.ok &&
      toHex(decrypted.value) === toHex(plaintext),
  );

  // 別 DEK では復号できない
  const wrongDek = await decryptVariable({
    dek: generateDek(),
    context: baseContext(),
    ...encrypted.value,
  });
  c.push("var-enc: wrong DEK rejected", !wrongDek.ok);
}

async function nonceUniquenessChecks(c: Checks): Promise<void> {
  // §4 / §11: nonce はランダム生成で再利用禁止。同一入力で繰り返し暗号化しても
  // nonce が重複しないこと(および暗号文も毎回異なること)を検査する
  const dek = generateDek();
  const plaintext = new TextEncoder().encode("same-input-every-time");
  const nonces = new Set<string>();
  const ciphertexts = new Set<string>();
  const iterations = 256;
  for (let i = 0; i < iterations; i++) {
    const encrypted = await encryptVariable({ dek, context: baseContext(), plaintext });
    if (!encrypted.ok) {
      c.push("var-enc: nonce uniqueness", false, "encrypt failed");
      return;
    }
    nonces.add(toHex(encrypted.value.nonce));
    ciphertexts.add(toHex(encrypted.value.ciphertext));
  }
  c.push(
    "var-enc: nonce uniqueness over repeated encryptions",
    nonces.size === iterations && ciphertexts.size === iterations,
  );
}

export async function variableChecks(): Promise<CheckResult[]> {
  const c = new Checks();
  await vectorChecks(c);
  await aadMismatchChecks(c);
  await tamperChecks(c);
  await roundtripChecks(c);
  await nonceUniquenessChecks(c);
  return c.results;
}
