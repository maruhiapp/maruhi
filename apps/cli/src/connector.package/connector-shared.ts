import { type EnvironmentId } from "@maruhi/core";
import { Context, Data } from "effect";
import type { HttpClientError } from "effect/http";

import { countNoun } from "../display.ts";
import { CLI_VERSION } from "../version.ts";

interface IssuerEndpointsShape {
  readonly awsIamBase?: string | undefined;
  readonly awsStsBase?: string | undefined;
  readonly cloudflareBase?: string | undefined;
}

export class IssuerEndpoints extends Context.Reference<IssuerEndpointsShape>(
  "cli/IssuerEndpoints",
  {
    defaultValue: (): IssuerEndpointsShape => ({}),
  },
) {}

export type CompanionAncestors = Readonly<Record<string, readonly Uint8Array[]>>;

export type RotateInputs = Readonly<Record<string, Uint8Array>>;

export interface RotationSite {
  readonly variable: string;
  readonly environmentId: EnvironmentId;
}

export interface CredentialValues {
  readonly primary: Uint8Array;
  readonly companions: Readonly<Record<string, Uint8Array>>;
}

export interface RotationPlan {
  readonly description: string;
  readonly immediate: boolean;
}

export interface RotationOutcome {
  readonly values: CredentialValues;
  readonly shape: ValueShape;
  readonly companionShapes: Readonly<Record<string, ValueShape>>;
  readonly currentShape: ValueShape;
  readonly facts: readonly string[];
  readonly previous: string;
  readonly recovery: string;
  readonly warnings: readonly string[];
}

export type ConnectorOutcome = Omit<RotationOutcome, "shape" | "companionShapes" | "currentShape">;

export interface FinalizeOutcome {
  readonly kind: "finalized" | "already" | "nothing";
  readonly facts: readonly string[];
}

export class ConnectorError extends Data.TaggedError("ConnectorError")<{
  readonly message: string;
}> {}

export const USER_AGENT = `maruhi-cli/${CLI_VERSION}`;

export function reasonOf(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export function transportReason(error: HttpClientError.HttpClientError): string {
  return reasonOf(error.reason.cause, reasonOf(error, "request failed"));
}

export function shapeOf(value: Uint8Array): ValueShape {
  let lines = 1;
  for (const byte of value) {
    if (byte === 0x0a) {
      lines += 1;
    }
  }
  return { bytes: value.length, lines };
}

export interface ValueShape {
  readonly bytes: number;
  readonly lines: number;
}

export function describeShape(shape: ValueShape): string {
  return `${countNoun(shape.bytes, "byte")}, ${countNoun(shape.lines, "line")}`;
}

export function describeValueShapes(
  outcome: Pick<RotationOutcome, "shape" | "companionShapes">,
): string {
  return [
    describeShape(outcome.shape),
    ...Object.entries(outcome.companionShapes)
      .toSorted(([a], [b]) => a.localeCompare(b))
      .map(([name, shape]) => `${name} ${describeShape(shape)}`),
  ].join("; ");
}

export function lineCountWarning(
  name: string,
  next: ValueShape,
  current: ValueShape,
  connector: string,
): string | null {
  if (next.lines === current.lines) {
    return null;
  }
  const cause =
    connector === "exec"
      ? "check that the rotate script printed only the credential (a process it started may have written to its stdout)"
      : `the ${connector} connector produced it as the issuer answered, so the current value had another layout (pushed by hand?) — nothing to fix unless the issuer's answer changed shape`;
  return `the new value of ${name} has ${countNoun(next.lines, "line")} where the current value has ${countNoun(current.lines, "line")}: ${cause}`;
}
