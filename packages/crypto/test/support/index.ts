// @maruhi/crypto/test-support — 外部ワークスペース(apps/*)のテスト支援が使う
// 再エクスポート面。crypto 内部のテストは従来どおり相対 import でよい。
//
// ここに載せるのはテストベクター・共有フィクスチャの読み出し口のみ。src/ の
// 内部実装(internal.package)をこの面から露出させないこと。

export {
  toTypedEntry,
  vectorEntries,
  type VectorEntry,
  vectorEnvironmentDeks,
  vectorKeys,
  vectorNegatives,
} from "../checks/chain-vector.ts";
export {
  BASE_TIME_MS,
  buildChainWith,
  type BuiltChain,
  hexBytes,
  type LazyChainOperation,
  unwrapResult,
  valueContextOf,
  valueSignedBytesHashOf,
  type WireEncryptedPayload,
} from "./fixture.ts";
