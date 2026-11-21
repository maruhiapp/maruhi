const encoder = new TextEncoder();

const HEX = "0123456789abcdef";

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += HEX[byte >> 4]! + HEX[byte & 0x0f]!;
  }
  return out;
}

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));
}

async function hmac(key: Uint8Array, data: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, encoder.encode(data)));
}

export function amzDate(nowMs: number): { readonly dateTime: string; readonly date: string } {
  const iso = new Date(nowMs).toISOString();
  const dateTime = `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}T${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`;
  return { dateTime, date: dateTime.slice(0, 8) };
}

export interface AwsCredentials {
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly sessionToken?: string | undefined;
}

export interface SigV4Input {
  readonly method: "GET" | "POST";
  readonly url: string;
  readonly region: string;
  readonly service: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly credentials: AwsCredentials;
  readonly nowMs: number;
}

export interface SigV4Output {
  readonly headers: Readonly<Record<string, string>>;
  readonly canonicalRequest: string;
  readonly stringToSign: string;
  readonly signature: string;
}

function uriEncode(text: string): string {
  return encodeURIComponent(text).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function canonicalQuery(url: URL): string {
  const pairs: [string, string][] = [];
  for (const [name, value] of url.searchParams) {
    pairs.push([uriEncode(name), uriEncode(value)]);
  }
  pairs.sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0,
  );
  return pairs.map(([name, value]) => `${name}=${value}`).join("&");
}

export async function signingKey(
  secretAccessKey: string,
  date: string,
  region: string,
  service: string,
): Promise<Uint8Array> {
  const kDate = await hmac(encoder.encode(`AWS4${secretAccessKey}`), date);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

export async function signV4(input: SigV4Input): Promise<SigV4Output> {
  const url = new URL(input.url);
  const { dateTime, date } = amzDate(input.nowMs);
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.headers)) {
    headers[name.toLowerCase()] = value.trim().replace(/\s+/g, " ");
  }
  headers["host"] = url.host;
  headers["x-amz-date"] = dateTime;
  if (input.credentials.sessionToken !== undefined) {
    headers["x-amz-security-token"] = input.credentials.sessionToken;
  }
  const signedHeaderNames = Object.keys(headers).toSorted();
  const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headers[name]}\n`).join("");
  const signedHeaders = signedHeaderNames.join(";");
  const payloadHash = await sha256Hex(input.body);
  const canonicalRequest = [
    input.method,
    url.pathname === "" ? "/" : url.pathname,
    canonicalQuery(url),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    dateTime,
    scope,
    await sha256Hex(canonicalRequest),
  ].join("\n");
  const key = await signingKey(
    input.credentials.secretAccessKey,
    date,
    input.region,
    input.service,
  );
  const signature = hex(await hmac(key, stringToSign));
  headers["authorization"] =
    `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers, canonicalRequest, stringToSign, signature };
}
