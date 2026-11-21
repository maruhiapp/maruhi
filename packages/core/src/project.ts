import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/crypto";
import { Schema } from "effect";

export type { EnvironmentId, ProjectId, VariableId } from "@maruhi/crypto";

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

export function isProjectId(value: string): boolean {
  return PROJECT_ID_PATTERN.test(value);
}

const narrowsProjectId = (value: string): value is ProjectId => PROJECT_ID_PATTERN.test(value);

export const PROJECT_ID_EXPECTED = "project id (lowercase hex SHA-256 of the genesis entry)";
export const ENVIRONMENT_ID_EXPECTED =
  "environment id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)";
export const VARIABLE_ID_EXPECTED =
  "variable id (1-64 chars of [A-Za-z0-9_-], starting alphanumeric)";

export const ProjectIdSchema = Schema.String.pipe(
  Schema.refine(narrowsProjectId, {
    expected: PROJECT_ID_EXPECTED,
  }),
);

export const decodeProjectId: (value: string) => ProjectId = Schema.decodeSync(ProjectIdSchema);

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function isEnvironmentId(value: string): boolean {
  return RESOURCE_ID_PATTERN.test(value);
}

const narrowsEnvironmentId = (value: string): value is EnvironmentId =>
  RESOURCE_ID_PATTERN.test(value);

export const EnvironmentIdSchema = Schema.String.pipe(
  Schema.refine(narrowsEnvironmentId, {
    expected: ENVIRONMENT_ID_EXPECTED,
  }),
);

export const environmentIdSchemaWithMessage = (message: string) =>
  Schema.String.annotate({ message }).pipe(Schema.refine(narrowsEnvironmentId, { message }));

export const decodeEnvironmentId: (value: string) => EnvironmentId =
  Schema.decodeSync(EnvironmentIdSchema);

export function isVariableId(value: string): boolean {
  return RESOURCE_ID_PATTERN.test(value);
}

const narrowsVariableId = (value: string): value is VariableId => RESOURCE_ID_PATTERN.test(value);

export const VariableIdSchema = Schema.String.pipe(
  Schema.refine(narrowsVariableId, {
    expected: VARIABLE_ID_EXPECTED,
  }),
);

export const decodeVariableId: (value: string) => VariableId = Schema.decodeSync(VariableIdSchema);
