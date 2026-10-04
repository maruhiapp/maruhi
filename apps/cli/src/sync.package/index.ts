// sync.package's public surface: only the symbols other src files import.
// The `maruhi sync` command pieces live in command.ts, imported directly by
// commands/index.ts — the package-entry convention (CLAUDE.md "CLI source
// layout"). Schema and proxy need it because re-exporting would close a
// real import cycle; sync's matching edge is a type-only import, so the
// same shape is followed for consistency.
export { ciSyncOp } from "./sync-ci.ts";
export {
  checkConfigProject,
  DEFAULT_SYNC_CONFIG_PATH,
  loadSyncConfig,
  requireSyncTarget,
} from "./sync-config.ts";
export { GH_ENV, scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
export {
  decidePushSync,
  loadPushSyncConfig,
  type PushSyncSetup,
  syncAfterPush,
} from "./sync-push.ts";
export { advanceReceiptsAfterRotation, checkRotateConfigProject } from "./sync-rotate.ts";
