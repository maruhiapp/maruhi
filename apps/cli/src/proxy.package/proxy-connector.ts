// The connector frame of `maruhi proxy run` (PF4 — integration-options.md
// §6 option D3 "shortening at the broker", §7 part ②): a brokered
// credential whose real value is **minted** on the proxy, just in time,
// from variables the child never receives. The agent does not even see
// the short-lived token — the proxy inserts it (pf4-design.md ruling P8).
//
// First connector: `github-app`. Inputs are the App ID (or client ID),
// the App's private key (PEM — PKCS#1 as GitHub issues it, or PKCS#8),
// and the installation ID. The proxy signs a 9-minute RS256 JWT with the
// key (WebCrypto RSASSA-PKCS1-v1_5 — the format GitHub requires), asks
// `POST /app/installations/{id}/access_tokens` for an installation token
// (one hour), caches it, and re-mints five minutes before it expires.
// Nothing from this flow is written anywhere; the key is imported as a
// non-extractable WebCrypto key and the PEM bytes are dropped. The server
// (maruhi's) is not involved — it never sees the App key or the token.
//
// Why this is not a CRYPTO_SPEC operation: it is a client of GitHub's
// authentication protocol, the same class as the vendor-API drivers of
// `maruhi sync` (sync-http.ts). The spec governs maruhi's own data; this
// consumes decrypted variables the way `run` injects them, and produces
// a value that lives in the proxy's memory for an hour.
//
// Error wording carries the connector, the variable name, the HTTP
// status, and GitHub's `message` field — never an input or the token.

import { pemBody, pkcs1ToPkcs8 } from "../der.ts";
import { CLI_VERSION } from "../version.ts";
import type { ConnectorKind } from "./proxy-config.ts";
import type { BrokeredCredential } from "./proxy-rules.ts";

/** A minted credential and when it stops being valid (null = no expiry known). */
interface Minted {
  readonly value: Uint8Array;
  readonly expiresAt: number | null;
}

/** The decrypted inputs a connector consumes (input name → bytes). */
export type ConnectorInputs = Readonly<Record<string, Uint8Array>>;

/** The seams a connector uses (tests redirect the API base). */
export interface ConnectorDeps {
  readonly fetch: typeof fetch;
  readonly now: () => number;
  /** The API origin (production: the connector's fixed host). */
  readonly apiBase?: string | undefined;
}

/** How long before expiry a cached credential is re-minted. */
const REFRESH_MARGIN_MS = 5 * 60 * 1000;

const decoder = new TextDecoder();

/* -------------------------------------------------------------------------- */
/* github-app                                                                   */
/* -------------------------------------------------------------------------- */

const GITHUB_API = "https://api.github.com";
/** GitHub accepts at most 10 minutes; back-date `iat` for clock skew as GitHub suggests. */
const JWT_BACKDATE_S = 60;
const JWT_LIFETIME_S = 9 * 60;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The App key as a WebCrypto signing key (PKCS#1 or PKCS#8 PEM). */
async function importAppKey(pemText: string): Promise<CryptoKey> {
  const pkcs1 = pemBody(pemText, "RSA PRIVATE KEY");
  const pkcs8 = pkcs1 === null ? pemBody(pemText, "PRIVATE KEY") : pkcs1ToPkcs8(pkcs1);
  if (pkcs8 === null) {
    throw new Error(
      "the private key is not a PEM RSA key (expected a `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN PRIVATE KEY-----` block, as downloaded from the GitHub App's settings)",
    );
  }
  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch {
    throw new Error("the private key could not be imported as an RSA signing key");
  }
}

/** A signed App JWT (RS256), per GitHub's authentication docs. */
async function appJwt(key: CryptoKey, appId: string, nowMs: number): Promise<string> {
  const now = Math.floor(nowMs / 1000);
  const encoder = new TextEncoder();
  const header = base64Url(encoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = base64Url(
    encoder.encode(
      JSON.stringify({ iat: now - JWT_BACKDATE_S, exp: now + JWT_LIFETIME_S, iss: appId }),
    ),
  );
  const signingInput = `${header}.${payload}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, encoder.encode(signingInput)),
  );
  return `${signingInput}.${base64Url(signature)}`;
}

/** A trimmed single-line input (IDs); rejects anything but a short token of printable ASCII. */
function textInput(inputs: ConnectorInputs, name: string): string {
  const bytes = inputs[name];
  if (bytes === undefined) {
    throw new Error(`input ${name} is missing`);
  }
  const text = decoder.decode(bytes).trim();
  if (!/^[\x21-\x7E]{1,128}$/.test(text)) {
    throw new Error(`input ${name} is not a single-line identifier`);
  }
  return text;
}

/** GitHub's `access_tokens` response → the minted token (the status and `message` on refusal). */
/** The response body as a JSON object (an empty object when it is not one). */
function jsonObjectOf(text: string): Record<string, unknown> {
  try {
    const body: unknown = JSON.parse(text);
    return typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function parseTokenResponse(status: number, text: string): Minted {
  const record = jsonObjectOf(text);
  if (status !== 201) {
    const message = typeof record["message"] === "string" ? record["message"] : "no message";
    throw new Error(`GitHub answered ${status} (${message})`);
  }
  const token = record["token"];
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("GitHub's response carried no token");
  }
  const expiresAt =
    typeof record["expires_at"] === "string" ? Date.parse(record["expires_at"]) : Number.NaN;
  return {
    value: new TextEncoder().encode(token),
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : null,
  };
}

async function mintGithubApp(inputs: ConnectorInputs, deps: ConnectorDeps): Promise<Minted> {
  const appId = textInput(inputs, "appId");
  const installationId = textInput(inputs, "installationId");
  if (!/^\d+$/.test(installationId)) {
    throw new Error("input installationId must be the numeric installation ID");
  }
  const keyBytes = inputs["privateKey"];
  if (keyBytes === undefined) {
    throw new Error("input privateKey is missing");
  }
  const key = await importAppKey(decoder.decode(keyBytes));
  const jwt = await appJwt(key, appId, deps.now());
  const base = deps.apiBase ?? GITHUB_API;
  const response = await deps.fetch(`${base}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${jwt}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": `maruhi-cli/${CLI_VERSION}`,
    },
  });
  return parseTokenResponse(response.status, await response.text());
}

/**
 * Revokes an installation token at teardown (`DELETE /installation/token`,
 * authenticated with the token itself) so the credential's life is the
 * run's, not GitHub's hour (pf4-design.md §19 D-14a). A refusal (already
 * expired, network) is reported by the caller as a Note.
 */
async function revokeGithubApp(token: Uint8Array, deps: ConnectorDeps): Promise<void> {
  const base = deps.apiBase ?? GITHUB_API;
  const response = await deps.fetch(`${base}/installation/token`, {
    method: "DELETE",
    headers: {
      // Reason for unwrapping: the token authenticates its own revocation (GitHub's API shape)
      authorization: `token ${decoder.decode(token)}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": `maruhi-cli/${CLI_VERSION}`,
    },
  });
  // 204 = revoked; 401 = already invalid (expired or revoked) — nothing left to do
  if (response.status !== 204 && response.status !== 401) {
    throw new Error(`GitHub answered ${response.status} to the revocation`);
  }
}

interface ConnectorImpl {
  readonly mint: (inputs: ConnectorInputs, deps: ConnectorDeps) => Promise<Minted>;
  readonly revoke: (value: Uint8Array, deps: ConnectorDeps) => Promise<void>;
}

const CONNECTORS: Readonly<Record<ConnectorKind, ConnectorImpl>> = {
  "github-app": { mint: mintGithubApp, revoke: revokeGithubApp },
};

/**
 * A brokered credential backed by a connector: `resolve` mints on first
 * use, caches until near expiry, and re-mints (one flight at a time). A
 * failure is reported with the connector and variable name and the
 * reason — the proxy turns it into a 502 toward the child.
 */
export function makeConnectorCredential(input: {
  readonly name: string;
  readonly kind: ConnectorKind;
  readonly inputs: ConnectorInputs;
  readonly placeholder: string;
  readonly hosts: BrokeredCredential["hosts"];
  readonly surfaces: BrokeredCredential["surfaces"];
  readonly deps: ConnectorDeps;
}): BrokeredCredential {
  const { mint, revoke } = CONNECTORS[input.kind];
  let cached: Minted | null = null;
  // The token before a re-mint: still valid for a while and worth scrubbing
  let previous: Minted | null = null;
  let inFlight: Promise<Uint8Array> | null = null;
  const fresh = (now: number): boolean =>
    cached !== null && (cached.expiresAt === null || cached.expiresAt - REFRESH_MARGIN_MS > now);
  return {
    name: input.name,
    placeholder: input.placeholder,
    hosts: input.hosts,
    surfaces: input.surfaces,
    known: () =>
      [cached, previous]
        .filter((minted): minted is Minted => minted !== null)
        .map((minted) => minted.value),
    release: async () => {
      const held = [cached, previous].filter((minted): minted is Minted => minted !== null);
      cached = null;
      previous = null;
      // Every held token is revoked even when one revocation fails (a
      // token left alive would outlive the run — review finding §21 R-3)
      const failures: string[] = [];
      for (const minted of held) {
        await revoke(minted.value, input.deps).catch((error: unknown) => {
          failures.push(error instanceof Error ? error.message : "revocation failed");
        });
      }
      if (failures.length > 0) {
        throw new Error(failures.join("; "));
      }
    },
    resolve: () => {
      if (cached !== null && fresh(input.deps.now())) {
        return Promise.resolve(cached.value);
      }
      if (inFlight === null) {
        inFlight = mint(input.inputs, input.deps)
          .then((minted) => {
            previous = cached;
            cached = minted;
            return minted.value;
          })
          .catch((error: unknown) => {
            const reason = error instanceof Error ? error.message : "unknown failure";
            throw new Error(`connector ${input.kind} for ${input.name}: ${reason}`);
          })
          .finally(() => {
            inFlight = null;
          });
      }
      return inFlight;
    },
  };
}
