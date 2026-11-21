import { redactUrls } from "./cf-config.ts";

const DEFAULT_API_BASE_URL = "https://api.cloudflare.com/client/v4";

export interface D1PollResponse {
  readonly success?: boolean;
  readonly status?: string;
  readonly error?: string;
  readonly errors?: ReadonlyArray<{ readonly message?: string } | string>;
  readonly messages?: readonly string[];
  readonly at_bookmark?: string;
  readonly upload_url?: string;
  readonly filename?: string;
  readonly result?: {
    readonly signed_url?: string;
    readonly status?: string;
    readonly at_bookmark?: string;
  };
}

interface ApiEnvelope {
  readonly success?: boolean;
  readonly errors?: ReadonlyArray<{ readonly code?: number; readonly message?: string }>;
  readonly result?: D1PollResponse | null;
}

function requiredEnv(name: string, caller: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    console.error(`${caller}: ${name} is not set (an Account API token with D1: Edit)`);
    process.exit(2);
  }
  return value;
}

export function pollErrorDetail(response: D1PollResponse, raw: string): string {
  return (
    response.error ??
    response.errors?.map((e) => (typeof e === "string" ? e : e.message)).join("; ") ??
    redactUrls(raw)
  );
}

function d1Endpoint(caller: string, databaseId: string, action: string): string {
  const accountId = requiredEnv("CLOUDFLARE_ACCOUNT_ID", caller);
  const base = (process.env["CLOUDFLARE_API_BASE_URL"] ?? DEFAULT_API_BASE_URL).replace(/\/+$/, "");
  return `${base}/accounts/${encodeURIComponent(accountId)}/d1/database/${encodeURIComponent(databaseId)}/${action}`;
}

function parseEnvelope(action: string, status: number, text: string): ApiEnvelope {
  try {
    return JSON.parse(text) as ApiEnvelope;
  } catch {
    throw new Error(`D1 ${action} API returned HTTP ${status} without JSON: ${redactUrls(text)}`);
  }
}

function envelopeErrorDetail(envelope: ApiEnvelope, text: string): string {
  const listed = (envelope.errors ?? [])
    .map((e) => (e.code === undefined ? e.message : `${e.message} [${e.code}]`))
    .join("; ");
  return listed === "" ? redactUrls(text) : listed;
}

export async function d1ApiPost(
  caller: string,
  databaseId: string,
  action: "export" | "import",
  body: Readonly<Record<string, unknown>>,
): Promise<D1PollResponse> {
  const token = requiredEnv("CLOUDFLARE_API_TOKEN", caller);
  const response = await fetch(d1Endpoint(caller, databaseId, action), {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const envelope = parseEnvelope(action, response.status, text);
  if (!response.ok || envelope.success !== true || envelope.result == null) {
    throw new Error(
      `D1 ${action} API failed with HTTP ${response.status}: ${envelopeErrorDetail(envelope, text)}`,
    );
  }
  return envelope.result;
}
