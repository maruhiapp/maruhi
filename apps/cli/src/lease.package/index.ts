// lease.package's public surface: only the symbols other src files import.
// There is no command.ts here: ci.package's ci-lease.ts requests and
// verifies the workload lease for `maruhi ci run`, `ci sync` and `ci
// rotate`, and ci-rotate.ts and sync.package's sync-ci.ts take its
// VerifiedLeaseMaterial type, each through this index like any other
// outside file.
export {
  type LeaseResponseWire,
  type VerifiedLeaseMaterial,
  verifyLeaseResponse,
} from "./lease-client.ts";
