// sync.package's public surface: only the symbols other src files import.
// The `maruhi sync` command pieces live in command.ts, imported directly by
// commands/index.ts — re-exporting them here would close an import cycle
// (index → command → context → rotate-connector → index).
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
