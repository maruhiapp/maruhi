// The inspected request of the forward proxy (proxy-server.ts): finding
// every placeholder in the request (path, query, headers — a Basic
// credential decoded first — and body), the refusal when a rule does not
// allow the use, the substitution into the upstream request, and the
// scrub patterns for the forms the proxy itself puts on the wire.

import { type BytePattern, replaceBytes, scrubPatterns } from "../byte-replace.ts";
import type { Surface } from "./proxy-config.ts";
import { authorityOf, type BrokeredCredential, hostHeaderOf, type Target } from "./proxy-rules.ts";
import { HOP_BY_HOP } from "./proxy-server-http.ts";

/* -------------------------------------------------------------------------- */
/* Request inspection                                                           */
/* -------------------------------------------------------------------------- */

/** Where a placeholder was found, for the refusal wording. */
export type Found = { readonly credential: BrokeredCredential; readonly surface: Surface };

function findIn(text: string, credentials: readonly BrokeredCredential[]): BrokeredCredential[] {
  return credentials.filter((credential) => text.includes(credential.placeholder));
}

function substituteText(text: string, values: ReadonlyMap<BrokeredCredential, string>): string {
  let out = text;
  for (const [credential, value] of values) {
    out = out.split(credential.placeholder).join(value);
  }
  return out;
}

const BASIC_PREFIX = /^basic\s+/i;

/** `Basic <base64>` → the decoded `user:password` text (null when not Basic or not base64). */
function decodeBasic(value: string): string | null {
  if (!BASIC_PREFIX.test(value)) {
    return null;
  }
  const encoded = value.replace(BASIC_PREFIX, "").trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    return null;
  }
  return Buffer.from(encoded, "base64").toString("utf8");
}

export interface Inspection {
  /** Placeholders found in the request, by surface. */
  readonly found: readonly Found[];
}

/** Placeholders in the headers (a Basic credential is searched decoded as well). */
function findInHeaders(
  headers: Readonly<Record<string, string>>,
  credentials: readonly BrokeredCredential[],
): Found[] {
  const found: Found[] = [];
  for (const [name, value] of Object.entries(headers)) {
    const decoded = name === "authorization" ? decodeBasic(value) : null;
    const text = decoded === null ? value : `${value} ${decoded}`;
    for (const credential of findIn(text, credentials)) {
      found.push({ credential, surface: "header" });
    }
  }
  return found;
}

function findInBody(body: Buffer, credentials: readonly BrokeredCredential[]): Found[] {
  if (body.length === 0) {
    return [];
  }
  return credentials
    .filter((credential) => body.includes(credential.placeholder, 0, "latin1"))
    .map((credential) => ({ credential, surface: "body" as const }));
}

export function inspectRequest(input: {
  readonly path: string;
  readonly query: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  readonly credentials: readonly BrokeredCredential[];
}): Inspection {
  const found: Found[] = [
    ...findIn(input.path, input.credentials).map((credential) => ({
      credential,
      surface: "path" as const,
    })),
    ...findIn(input.query, input.credentials).map((credential) => ({
      credential,
      surface: "query" as const,
    })),
    ...findInHeaders(input.headers, input.credentials),
    ...findInBody(input.body, input.credentials),
  ];
  return { found };
}

/** Current real values of the credentials that may be substituted into a request (only the ones the request uses). */
export async function resolveValues(
  allowed: readonly BrokeredCredential[],
  needed: ReadonlySet<BrokeredCredential>,
): Promise<Map<BrokeredCredential, string>> {
  const values = new Map<BrokeredCredential, string>();
  for (const credential of allowed) {
    if (!needed.has(credential)) {
      continue;
    }
    const bytes = await credential.resolve();
    values.set(credential, Buffer.from(bytes).toString("utf8"));
  }
  return values;
}

/** The refusal for a placeholder used where its rule does not allow it (null = every use is allowed). */
export function refusalFor(
  found: readonly Found[],
  allowed: readonly BrokeredCredential[],
  target: Target,
): string | null {
  for (const { credential, surface } of found) {
    if (!allowed.includes(credential)) {
      return `the placeholder for ${credential.name} is only substituted toward the hosts its rule names (this request is for ${authorityOf(target)}); the request was not sent`;
    }
    if (!credential.surfaces.includes(surface)) {
      return `the placeholder for ${credential.name} appears in the ${surface} of the request, but its rule allows only: ${credential.surfaces.join(", ")} (add "${surface}" to the rule's surfaces to allow it); the request was not sent`;
    }
  }
  return null;
}

const textEncoder = new TextEncoder();

/** The request as it leaves toward the origin: substituted path, headers, and body. */
export function buildUpstreamRequest(input: {
  readonly target: Target;
  readonly path: string;
  readonly query: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  readonly values: ReadonlyMap<BrokeredCredential, string>;
}): {
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly body: Buffer;
  readonly substituted: readonly string[];
} {
  const { values } = input;
  // A value in the request target must be percent-encoded (a space, `&`,
  // `#`, `%`, `+` would change the URL's meaning or be refused by the HTTP
  // client — review finding §19 C-4); a header value must stay a single
  // Latin-1 line (a line break would be refused by the client; a value that
  // cannot be a header is reported, never mangled)
  const encoded = new Map(
    [...values].map(([credential, value]) => [credential, encodeURIComponent(value)]),
  );
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.headers)) {
    if (HOP_BY_HOP.has(name)) {
      continue;
    }
    const substituted =
      name === "authorization"
        ? substituteAuthorization(value, values)
        : substituteText(value, values);
    // Only a value that lands in a header as text must be header-safe (a
    // `Basic` credential is re-encoded as base64; a placeholder found only
    // in the path, query, or body is never a header — review finding §21 R-9)
    if (substituted !== value && !isHeaderSafe(substituted)) {
      throw new UnsendableValueError(unsendableCredentialName(value, values));
    }
    headers[name] = substituted;
  }
  const bodyPatterns: BytePattern[] = [...values].map(([credential, value]) => ({
    from: textEncoder.encode(credential.placeholder),
    to: textEncoder.encode(value),
  }));
  const body = Buffer.from(replaceBytes(input.body, bodyPatterns));
  headers["host"] = hostHeaderOf(input.target);
  // The response must be readable to be scrubbed (and HTTP/1.1 upstream keeps it simple)
  headers["accept-encoding"] = "identity";
  if (body.length > 0 || input.headers["content-length"] !== undefined) {
    headers["content-length"] = String(body.length);
  }
  return {
    path: substituteText(input.path, encoded) + substituteText(input.query, encoded),
    headers,
    body,
    substituted: [...values.keys()].map((credential) => credential.name).toSorted(),
  };
}

/** The variable whose value made a header unsendable (the first placeholder in the header whose value is not header-safe). */
function unsendableCredentialName(
  header: string,
  values: ReadonlyMap<BrokeredCredential, string>,
): string {
  for (const [credential, value] of values) {
    if (header.includes(credential.placeholder) && !isHeaderSafe(value)) {
      return credential.name;
    }
  }
  return [...values.keys()].map((credential) => credential.name).join(", ");
}

/** A single Latin-1 line (what an HTTP header value may carry). */
function isHeaderSafe(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x0d || code === 0x0a || code > 0xff) {
      return false;
    }
  }
  return true;
}

/** A brokered value that cannot travel in a header (a line break or a non-Latin-1 character). */
export class UnsendableValueError extends Error {
  constructor(readonly variable: string) {
    super("unsendable value");
  }
}

/** `Authorization`: a Basic credential is substituted decoded and re-encoded; anything else as text. */
function substituteAuthorization(
  value: string,
  values: ReadonlyMap<BrokeredCredential, string>,
): string {
  const decoded = decodeBasic(value);
  if (decoded === null) {
    return substituteText(value, values);
  }
  const substituted = substituteText(decoded, values);
  return substituted === decoded
    ? value
    : `Basic ${Buffer.from(substituted, "utf8").toString("base64")}`;
}

/**
 * The values plus the forms the proxy itself puts on the wire (review
 * finding §21 R-21): a value substituted into the path or query travels
 * percent-encoded, and an origin that echoes the request URL echoes that
 * form — the scrub must know it too. (The Basic re-encoding is per request
 * — {@link wirePatterns}.)
 */
export function withWireForms(values: readonly Uint8Array[]): readonly Uint8Array[] {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const extra: Uint8Array[] = [];
  for (const value of values) {
    let text: string;
    try {
      text = decoder.decode(value);
    } catch {
      continue;
    }
    const encoded = encodeURIComponent(text);
    if (encoded !== text) {
      extra.push(textEncoder.encode(encoded));
    }
  }
  return [...values, ...extra];
}

/**
 * Patterns for what this one request put on the wire in a form the global
 * scrub cannot know: a `Basic` credential the proxy decoded, substituted,
 * and re-encoded. An origin echoing the header echoes the re-encoded blob;
 * it is scrubbed back to the blob the client sent (which carries the
 * placeholder) — §21 R-21.
 */
export function wirePatterns(
  original: Readonly<Record<string, string>>,
  sent: Readonly<Record<string, string>>,
): readonly BytePattern[] {
  const before = original["authorization"];
  const after = sent["authorization"];
  if (
    before === undefined ||
    after === undefined ||
    before === after ||
    !BASIC_PREFIX.test(after)
  ) {
    return [];
  }
  const sentBlob = after.replace(BASIC_PREFIX, "").trim();
  const clientBlob = before.replace(BASIC_PREFIX, "").trim();
  return scrubPatterns([textEncoder.encode(sentBlob)], clientBlob);
}
