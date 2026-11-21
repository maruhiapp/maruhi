import { Data } from "effect";

import { type BytePattern, replaceBytes, scrubPatterns } from "../byte-replace.ts";
import type { Surface } from "./proxy-config.ts";
import { authorityOf, type BrokeredCredential, hostHeaderOf, type Target } from "./proxy-rules.ts";
import { HOP_BY_HOP } from "./proxy-server-http.ts";

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
  readonly found: readonly Found[];
}

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

function isHeaderSafe(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x0d || code === 0x0a || code > 0xff) {
      return false;
    }
  }
  return true;
}

export class UnsendableValueError extends Data.TaggedError("UnsendableValueError")<{
  readonly variable: string;
  readonly message: string;
}> {
  constructor(variable: string) {
    super({ variable, message: "unsendable value" });
  }
}

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
