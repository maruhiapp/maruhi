// sync.package's public surface: the `maruhi sync` command pieces consumed by
// commands/index.ts plus the 14 symbols other src files use (measured at
// introduction — see the PR). Everything else stays package-private.
export { makeSyncCommands, syncApplyConfig, syncInitConfig, syncPlanConfig } from "./command.ts";
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
