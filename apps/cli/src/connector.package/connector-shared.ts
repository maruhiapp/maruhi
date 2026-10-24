// What the rotation connectors share (the connector overview lives in
// connector.ts): the issuer origins a run targets (IssuerEndpoints), the
// credential and outcome types, ConnectorError and the wording of a
// transport failure, and the value shapes the rotation reports show, with
// their line-count warning (D-7 / D-8 / D-16 / D-18).

import { type EnvironmentId } from "@maruhi/core";
import { Context, Data } from "effect";
import type { HttpClientError } from "effect/http";

import { countNoun } from "../display.ts";
import { CLI_VERSION } from "../version.ts";

/**
 * The issuer API origins a run targets (production: the reference's
 * default — every origin unset, so each call uses the issuer's fixed host;
 * tests provide the reference to point the calls at a fake issuer).
 */
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

/**
 * The values every earlier version of a companion variable held (newest
 * first), each lineage-verified against the verified latest. A finalize
 * invalidates a credential the issuer lists only when one of these held
 * its id — the server's history metadata never picks the target.
 */
export type CompanionAncestors = Readonly<Record<string, readonly Uint8Array[]>>;

/** The decrypted inputs a connector consumes (input name → bytes). Empty = self-rotation. */
export type RotateInputs = Readonly<Record<string, Uint8Array>>;

/**
 * Where the rotation happens — the rule's variable and the environment
 * (the `exec` connector hands both to its scripts; the other connectors
 * do not need them).
 */
export interface RotationSite {
  readonly variable: string;
  readonly environmentId: EnvironmentId;
}

/** One credential as stored: the rule's variable and its companions (the AWS access key id). */
export interface CredentialValues {
  readonly primary: Uint8Array;
  readonly companions: Readonly<Record<string, Uint8Array>>;
}

/** What a rotation will do, decided before anything is sent (the caller confirms an immediate invalidation). */
export interface RotationPlan {
  /** What changes at the issuer, in one line (no credential). */
  readonly description: string;
  /** true = the old credential stops working as part of the rotation itself (no grace period). */
  readonly immediate: boolean;
}

export interface RotationOutcome {
  /** The new values to push (the primary and every companion the rule names). */
  readonly values: CredentialValues;
  /** The primary's shape ({@link shapeOf}) — for the local report; never a proposal fact. */
  readonly shape: ValueShape;
  /** Each companion's shape by name, for the same report. */
  readonly companionShapes: Readonly<Record<string, ValueShape>>;
  /** The current primary's shape, for the same report: a new value of another line count is worth a look before it is pushed (D-16 — a leftover's line is the common form). */
  readonly currentShape: ValueShape;
  /** Non-secret facts for the report (the new key id, the role now in use, the token id). */
  readonly facts: readonly string[];
  /** What the previous credential's state is now, in one line. */
  readonly previous: string;
  /**
   * How to recover when the issuer accepted the change but storing the new
   * value failed (the new credential is then held only by the process that
   * is about to exit): the issuer-specific step, in one line.
   */
  readonly recovery: string;
  /** Warnings (a connection test that failed after the issuer accepted the change). */
  readonly warnings: readonly string[];
}

/** A connector's own outcome (the frame adds the values' shapes). */
export type ConnectorOutcome = Omit<RotationOutcome, "shape" | "companionShapes" | "currentShape">;

export interface FinalizeOutcome {
  readonly kind: "finalized" | "already" | "nothing";
  readonly facts: readonly string[];
}

/** A connector failure the caller reports as-is (the message never carries a credential). */
export class ConnectorError extends Data.TaggedError("ConnectorError")<{
  readonly message: string;
}> {}

export const USER_AGENT = `maruhi-cli/${CLI_VERSION}`;

/** An unknown thrown value's message (a fetch rejection, a driver error — the reason, never a credential). */
export function reasonOf(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

/**
 * The message an `HttpClientError` carries: the transport's own cause (the
 * fetch rejection — a refused connection, a DNS failure) when it has one,
 * the client's wording ("Transport error", "Decode error"…) otherwise.
 */
export function transportReason(error: HttpClientError.HttpClientError): string {
  return reasonOf(error.reason.cause, reasonOf(error, "request failed"));
}

/* -------------------------------------------------------------------------- */
/* Value shapes (the rotation reports)                                          */
/* -------------------------------------------------------------------------- */

/**
 * The shape of a value (D-7 / D-8): "N bytes, M lines", shown in the local
 * rotation report and, at an acceptance, computed from the opened value on
 * the member's device — never sent to the server (a line count is
 * plaintext-derived information the ciphertext does not give away). A
 * script that printed its own chatter on stdout shows here before the
 * value is pushed.
 */
export function shapeOf(value: Uint8Array): ValueShape {
  let lines = 1;
  for (const byte of value) {
    if (byte === 0x0a) {
      lines += 1;
    }
  }
  return { bytes: value.length, lines };
}

/** The numbers a value's shape is made of; the text is formatted at display time ({@link describeShape}) and never parsed back (D-19). */
export interface ValueShape {
  readonly bytes: number;
  readonly lines: number;
}

/** "N bytes, M lines". */
export function describeShape(shape: ValueShape): string {
  return `${countNoun(shape.bytes, "byte")}, ${countNoun(shape.lines, "line")}`;
}

/** The primary's shape, then each companion's by name (the same parity as the acceptance's per-value shapes). */
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

/**
 * The warning a changed line count earns before the push (D-16 at `var
 * rotate`, D-18 at the acceptance): the one form of a leftover's output no
 * timing can tell apart. A warning, never a refusal (a token becoming a
 * PEM is legitimate). null = the line count is unchanged.
 */
export function lineCountWarning(
  name: string,
  next: ValueShape,
  current: ValueShape,
  connector: string,
): string | null {
  if (next.lines === current.lines) {
    return null;
  }
  // Only a script can have printed more than the credential; an API
  // connector's value is the issuer's answer, so the difference is the
  // current value's layout (round 9)
  const cause =
    connector === "exec"
      ? "check that the rotate script printed only the credential (a process it started may have written to its stdout)"
      : `the ${connector} connector produced it as the issuer answered, so the current value had another layout (pushed by hand?) — nothing to fix unless the issuer's answer changed shape`;
  return `the new value of ${name} has ${countNoun(next.lines, "line")} where the current value has ${countNoun(current.lines, "line")}: ${cause}`;
}
