// checkpoint.package's public surface: only the symbols other src files
// import. It has no command.ts: `maruhi project checkpoint` lives in
// project.package/command.ts, which issues a checkpoint with
// issueCheckpoint, as env.package's rotate does after a rotation.
// commands/shared.ts proposes a checkpoint after a pull or a value write
// (checkpointProposal and ANCHOR_REFRESH_PROPOSAL), and it and env
// rotate's command note a stale anchor after a rotation
// (ANCHOR_STALE_AFTER_ROTATION). audit.package's audit-reconcile.ts reads
// the server's audit head with fetchAuditHead. checkpoint-integrity.ts
// stays at the src root: values.ts imports it, and through this index it
// would also load checkpoint.ts, which imports values.ts.
export {
  ANCHOR_REFRESH_PROPOSAL,
  ANCHOR_STALE_AFTER_ROTATION,
  checkpointProposal,
  fetchAuditHead,
  issueCheckpoint,
} from "./checkpoint.ts";
