// スパイク C: 環境非依存の検証本体。vitest(node / workerd / browser)と
// Bun 直接実行(src/run-in-bun.ts)の両方から同じチェックを呼ぶ。

import vectors from "../test-vectors/rfc9180-base-x25519-hkdfsha256-aes256gcm.json" with { type: "json" };
import { adapters, hex, hpkeJsAdapter, panvaAdapter } from "./adapters.ts";

export interface CheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: string;
}

const utf8 = new TextEncoder();

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

async function expectThrows(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

/** CRYPTO_SPEC §5 と同形の info(dek-wrap 文脈)を模したダミー値 */
const INFO = utf8.encode("maruhi/v1/dek-wrap|spike-c-project|epoch-1|user-42");
const AAD = utf8.encode("spike-c-aad");
const PT = utf8.encode("dummy-dek-0123456789abcdef-not-a-real-secret");

export async function runChecks(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const push = (name: string, ok: boolean, detail?: string) => {
    results.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  };

  // 1. 各ライブラリの自己ラウンドトリップ + 文脈束縛(info / aad 不一致で復号失敗)
  for (const adapter of adapters) {
    try {
      const kp = await adapter.generateKeyPair();
      const { enc, ct } = await adapter.seal(kp.publicKey, INFO, AAD, PT);
      const pt = await adapter.open(kp.privateKey, enc, INFO, AAD, ct);
      push(`${adapter.name}: self roundtrip`, eq(pt, PT));

      const wrongInfo = await expectThrows(() =>
        adapter.open(kp.privateKey, enc, utf8.encode("maruhi/v1/dek-wrap|OTHER"), AAD, ct),
      );
      push(`${adapter.name}: wrong info rejected`, wrongInfo);

      const wrongAad = await expectThrows(() =>
        adapter.open(kp.privateKey, enc, INFO, utf8.encode("tampered-aad"), ct),
      );
      push(`${adapter.name}: wrong aad rejected`, wrongAad);
    } catch (e) {
      push(`${adapter.name}: self roundtrip`, false, String(e));
    }
  }

  // 2. 相互運用(RFC 9180 準拠の間接証拠): A で Seal → B で Open、その逆
  const pairs = [
    [hpkeJsAdapter, panvaAdapter],
    [panvaAdapter, hpkeJsAdapter],
  ] as const;
  for (const [sender, recipient] of pairs) {
    const name = `interop: seal=${sender.name} → open=${recipient.name}`;
    try {
      const kp = await recipient.generateKeyPair();
      const { enc, ct } = await sender.seal(kp.publicKey, INFO, AAD, PT);
      const pt = await recipient.open(kp.privateKey, enc, INFO, AAD, ct);
      push(name, eq(pt, PT));
    } catch (e) {
      push(name, false, String(e));
    }
  }

  // 3. RFC 9180 公式テストベクター(Base, X25519, HKDF-SHA256, AES-256-GCM)
  const v = vectors[0];
  if (v === undefined) throw new Error("test vector missing");
  const info = hex.decode(v.info);
  const ikmR = hex.decode(v.ikmR);
  const ikmE = hex.decode(v.ikmE);
  const pkRm = hex.decode(v.pkRm);
  const skRm = hex.decode(v.skRm);
  const encV = hex.decode(v.enc);
  const enc0 = v.encryptions[0];
  if (enc0 === undefined) throw new Error("test vector encryptions missing");

  for (const adapter of adapters) {
    // 3a. DeriveKeyPair(ikmR) がベクターの鍵と一致するか
    try {
      const kp = await adapter.deriveKeyPair(ikmR);
      push(
        `${adapter.name}: RFC 9180 DeriveKeyPair(ikmR) == (pkRm, skRm)`,
        eq(kp.publicKey, pkRm) && eq(kp.privateKey, skRm),
        `pk=${hex.encode(kp.publicKey)}`,
      );
    } catch (e) {
      push(`${adapter.name}: RFC 9180 DeriveKeyPair(ikmR) == (pkRm, skRm)`, false, String(e));
    }

    // 3b. Open 方向のベクター一致(受信側は enc が与えられれば決定論的)
    try {
      const pt = await adapter.open(skRm, encV, info, hex.decode(enc0.aad), hex.decode(enc0.ct));
      push(`${adapter.name}: RFC 9180 Open(vector enc/ct) == pt`, eq(pt, hex.decode(enc0.pt)));
    } catch (e) {
      push(`${adapter.name}: RFC 9180 Open(vector enc/ct) == pt`, false, String(e));
    }
  }

  // 3c. Seal 方向のベクター一致(hpke-js のみ。ekm による derandomize が可能)
  try {
    const { enc, ct } = await hpkeJsAdapter.sealWithEkm(
      pkRm,
      info,
      hex.decode(enc0.aad),
      hex.decode(enc0.pt),
      ikmE,
    );
    push(
      "hpke-js: RFC 9180 Seal(ekm=ikmE) == (enc, ct)",
      eq(enc, encV) && eq(ct, hex.decode(enc0.ct)),
      `enc=${hex.encode(enc)}`,
    );
  } catch (e) {
    push("hpke-js: RFC 9180 Seal(ekm=ikmE) == (enc, ct)", false, String(e));
  }
  // panva hpke は単発 API に skE / ikmE を注入する手段がない(意図的な API 設計)。
  // Seal 方向の正しさは相互運用テスト(2)と Open 方向ベクター(3b)で間接的に担保する。

  // 4. 環境差の観察(合否ではなく挙動記録): panva hpke の非抽出(extractable=false)
  //    秘密鍵での Open が動くか。Bun では失敗することを確認済み(adapters.ts 参照)。
  {
    const { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM } =
      await import("hpke");
    const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
    const kp = await suite.GenerateKeyPair(true);
    const skBytes = await suite.SerializePrivateKey(kp.privateKey);
    const sealed = await suite.Seal(kp.publicKey, PT, { info: INFO, aad: AAD });
    let nonExtractableOpen: string;
    try {
      const sk = await suite.DeserializePrivateKey(skBytes, false);
      await suite.Open(sk, sealed.encapsulatedSecret, sealed.ciphertext, { info: INFO, aad: AAD });
      nonExtractableOpen = "works";
    } catch (e) {
      nonExtractableOpen = `fails: ${e instanceof Error && e.cause instanceof Error ? e.cause.message : String(e)}`;
    }
    // 観察項目なので常に ok=true。detail に挙動を記録する
    push("observe: hpke (panva) Open with non-extractable private key", true, nonExtractableOpen);
  }

  return results;
}
