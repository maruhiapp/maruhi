// connector.package's public surface: only the symbols other src files
// import. There is no command.ts here: var.package's var-rotate.ts and
// ci.package's ci-rotate.ts run a rule's connector through the frame
// (connector.ts) and report the new values' shapes, which
// rotation-proposals.ts also checks at a proposal's acceptance. The
// rotation config (rotate-config.ts) is read by those two, by both groups'
// command.ts and by rotation.ts. live.ts provides the SqlRunner the SQL
// connectors use (connector-sql.ts), which context.ts and ci-rotate.ts
// name as a type. The proxy's connector is proxy.package's own.
export {
  type ConnectorError,
  type CredentialValues,
  describeShape,
  describeValueShapes,
  type FinalizeOutcome,
  lineCountWarning,
  type RotateInputs,
  type RotationOutcome,
  shapeOf,
  type ValueShape,
} from "./connector-shared.ts";
export { SqlRunner, type SqlRunnerShape } from "./connector-sql.ts";
export {
  companionsOf,
  describeFinalize,
  finalizeCredential,
  planRotation,
  rotateCredential,
} from "./connector.ts";
export {
  configNamesProject,
  DEFAULT_ROTATE_CONFIG_PATH,
  type InputRefs,
  loadRotateConfig,
  loadRotateConfigIfPresent,
  type RotateConfig,
  type RotateRule,
  ruleFor,
} from "./rotate-config.ts";
