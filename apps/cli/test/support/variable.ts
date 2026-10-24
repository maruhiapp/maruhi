// A decrypted variable (pull.ts's DecryptedVariable) for the tests of what
// is done with values after decryption: showValues (display.test.ts) and
// buildInjectionEnv (run.test.ts).

import { Redacted } from "effect";

import type { DecryptedVariable } from "../../src/pull.ts";
import { testVariableId } from "./crypto.ts";

export function variable(name: string, value: string | Uint8Array): DecryptedVariable {
  return {
    variableId: testVariableId("v1"),
    name,
    version: 1,
    epoch: 1,
    required: false,
    varType: "",
    maxAgeDays: null,
    value: Redacted.make(typeof value === "string" ? new TextEncoder().encode(value) : value, {
      label: "variable-value",
    }),
  };
}
