// Id-brand narrowing for values that came out of a genuine id slot but whose
// declared type is a bounded string: api-schema wire fields decoded with
// `BoundedUserId` (Schema.String, not a mint), crypto signing-context fields
// left as `string`, and Record keys of verified chain state. The brand
// carries provenance — the check is the slot's bound, not a format — so the
// helpers narrow rather than decode. A bound violation is corrupt verified
// state and throws.

import {
  isEnvironmentId,
  isProjectId,
  isVariableId,
  type EnvironmentId,
  type ProjectId,
  type UserId,
  type VariableId,
} from "@maruhi/core";

function isUserId(value: string): value is UserId {
  return value.length > 0;
}

export function userIdOf(value: string): UserId {
  if (!isUserId(value)) throw new Error("empty user id");
  return value;
}

export function projectIdOf(value: string): ProjectId {
  if (!isProjectId(value)) throw new Error(`invalid project id: ${value}`);
  return value;
}

export function environmentIdOf(value: string): EnvironmentId {
  if (!isEnvironmentId(value)) throw new Error(`invalid environment id: ${value}`);
  return value;
}

export function variableIdOf(value: string): VariableId {
  if (!isVariableId(value)) throw new Error(`invalid variable id: ${value}`);
  return value;
}
