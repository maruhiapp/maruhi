// @maruhi/crypto/test-support — the re-export surface used by the test
// support of external workspaces (apps/*). Tests inside crypto keep using
// relative imports as before.
//
// Only the accessors for test vectors and shared fixtures go on this surface.
// Do not expose internal implementations in src/ (internal.package) through it.

export {
  toTypedEntry,
  vectorEntries,
  type VectorEntry,
  vectorEnvironmentDeks,
  vectorExtendedChains,
  vectorKeys,
  vectorNegatives,
} from "../checks/chain-vector.ts";
export {
  BASE_TIME_MS,
  buildChainWith,
  type BuiltChain,
  hexBytes,
  type LazyChainOperation,
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testUserId,
  testVariableId,
  unwrapResult,
  valueContextOf,
  valueSignedBytesHashOf,
  type WireEncryptedPayload,
} from "./fixture.ts";
