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
