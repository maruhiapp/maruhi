// Small pieces shared inside the worker: the Env and secrets services
// and the DO RPC call helper (with its typed failure).

import { Context, Data, Effect, Redacted } from "effect";

import type { Env, ProjectChainDO } from "./do/chain-do.ts";

/** The Env fields that are secret configuration values (read only through `readWorkerSecrets`). */
type SecretName = "GITHUB_CLIENT_SECRET" | "SERVER_ENC_KEY_IKM" | "OPS_ALERT_WEBHOOK_URL";

/**
 * The Env as handlers see it: the bindings and the non-secret
 * configuration. The secret fields are left out of the type, so a
 * handler reaches them only as `Redacted` through WorkerSecrets.
 */
type WorkerBindings = Omit<Env, SecretName>;

export class WorkerEnv extends Context.Service<WorkerEnv, WorkerBindings>()("WorkerEnv") {}

/**
 * The worker's secret configuration values, each wrapped in `Redacted`
 * at the moment it is read from the env: string, JSON, and inspection
 * output (logs, error messages, Cause renderings) show only
 * `<redacted:NAME>`. `undefined` = unset or empty — a deployment
 * lacking the secret leaves it undefined at runtime, and all
 * consumers already treated an empty value the same as an unset one.
 * `Redacted.value` is called only where a value is used: the
 * token-exchange body (auth.package/github.ts), the HKDF input
 * (server-key.ts), and the webhook request's URL (ops/ops-alerts.ts).
 */
interface WorkerSecretsShape {
  readonly githubClientSecret: Redacted.Redacted<string> | undefined;
  readonly serverEncKeyIkm: Redacted.Redacted<string> | undefined;
  readonly opsAlertWebhookUrl: Redacted.Redacted<string> | undefined;
}

export class WorkerSecrets extends Context.Service<WorkerSecrets, WorkerSecretsShape>()(
  "WorkerSecrets",
) {}

/** Wraps one secret as read from the env, labeled with its name (unset or empty → undefined). */
function redactSecret(
  raw: string | undefined,
  label: SecretName,
): Redacted.Redacted<string> | undefined {
  return raw === undefined || raw === "" ? undefined : Redacted.make(raw, { label });
}

/**
 * The env-reading boundary for secrets: one call per entry point that
 * receives the Workers env (index.ts's buildServices and scheduled(),
 * and the chain DO's constructor). The parameter names only the secret
 * fields, all optional: a deployment lacking a secret has it undefined
 * at runtime whatever Env declares.
 */
export function readWorkerSecrets(env: {
  readonly GITHUB_CLIENT_SECRET?: string;
  readonly SERVER_ENC_KEY_IKM?: string;
  readonly OPS_ALERT_WEBHOOK_URL?: string;
}): WorkerSecretsShape {
  return {
    githubClientSecret: redactSecret(env.GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET"),
    serverEncKeyIkm: redactSecret(env.SERVER_ENC_KEY_IKM, "SERVER_ENC_KEY_IKM"),
    opsAlertWebhookUrl: redactSecret(env.OPS_ALERT_WEBHOOK_URL, "OPS_ALERT_WEBHOOK_URL"),
  };
}

/** Resolves the project DO's stub (DO name = project ID). */
export const projectStub = (
  env: Pick<Env, "PROJECT_CHAIN">,
  projectId: string,
): DurableObjectStub<ProjectChainDO> =>
  env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));

/**
 * A DO RPC that rejected, or threw before returning its promise (DO
 * unreachable, a DO-side defect, a storage fault). It carries only the
 * rejection's error class name (`errorName` — "unknown" for a non-Error
 * value), never the message or the error itself: the rejection's text
 * comes from the DO and can carry stored data or identifiers, and this
 * error may be logged. The class name is what the existing static
 * failure lines already log.
 */
export class RpcCallError extends Data.TaggedError("RpcCallError")<{
  readonly errorName: string;
}> {}

// The workers-types RPC stub types distribute a union return value
// into a per-member Promise intersection, so this converts back to
// the DO method's declared Promise<Outcome>. A rejection is a typed
// RpcCallError; a call site with no recovery turns it into a defect
// (Effect.orDie — the HTTP boundary's 500)
export const rpcCall = <T>(call: () => PromiseLike<unknown>): Effect.Effect<T, RpcCallError> =>
  Effect.tryPromise({
    try: () => call() as Promise<T>,
    catch: (cause) =>
      new RpcCallError({ errorName: cause instanceof Error ? cause.name : "unknown" }),
  });

/**
 * The period (seconds) of the ratelimits binding's fixed window.
 * Since period cannot be read from the binding, **keep it in sync
 * manually** with the `rateLimit` bindings' `simple.period` in
 * cloudflare.config.ts (used for the 429 response's
 * retryAfterSeconds / the Retry-After header).
 * Changing only one side makes the advertised wait drift from the
 * real window (the limit itself still works — a convenience-side
 * degradation, not a safety one). It cannot be enforced by types or
 * tests (the deploy config is unreadable at runtime and workerd
 * tests cannot read files), so the pair is marked by comments on
 * both sides (cloudflare.config.ts carries the same note).
 */
export const IP_RATE_LIMIT_PERIOD_SECONDS = 60;

/**
 * Normalization of rate-limit keys: IPv6 is rounded to its /64
 * prefix.
 * Rotating the lower 64 bits inside a standard /64 assignment would
 * make every request a fresh key under a raw address key and
 * neutralize the window entirely (the same reason Cloudflare WAF's
 * rate limiting aggregates by /64 by default). IPv4 is used as-is.
 * An unparseable value falls back to the raw string key (the
 * per-address limit is preserved).
 */
export function rateLimitKeyOf(ip: string): string {
  if (!ip.includes(":")) {
    return ip;
  }
  const groups = ipv6Groups(ip);
  if (groups === null) {
    return ip;
  }
  // IPv4-mapped (::ffff:a.b.c.d) uses the embedded IPv4 as the key:
  // under /64 aggregation, every IPv4 client arriving v4-mapped would
  // fold into the single bucket "0:0:0:0::/64", letting one origin
  // consume the whole IPv4 userbase's window
  const upperZero = groups.slice(0, 5).every((group) => Number.parseInt(group, 16) === 0);
  if (upperZero && Number.parseInt(groups[5] ?? "", 16) === 0xff_ff) {
    const hi = Number.parseInt(groups[6] ?? "0", 16);
    const lo = Number.parseInt(groups[7] ?? "0", 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  const prefix = groups.slice(0, 4).map((group) => Number.parseInt(group, 16).toString(16));
  return `${prefix.join(":")}::/64`;
}

/** The group lists of the halves split by "::" (null for malformed input or two or more "::"). */
function splitIpv6Halves(
  ip: string,
): { readonly head: string[]; readonly tail: string[]; readonly compressed: boolean } | null {
  const halves = (ip.split("%")[0] ?? ip).split("::");
  if (halves.length > 2) {
    return null;
  }
  const compressed = halves.length === 2;
  const tailRaw = halves[1] ?? "";
  // An embedded IPv4 may only sit at the **end** of the address
  // (RFC 4291 §2.2 (3)). Permission goes only to the half containing
  // the tail, and within it only to the last piece: this rejects
  // shapes like "1.2.3.4::" and "::ffff:1.2.3.4:0"
  const ipv4InTail = compressed && tailRaw !== "";
  const head = parseIpv6Groups(halves[0] ?? "", !compressed);
  const tail = parseIpv6Groups(tailRaw, ipv4InTail);
  if (head === null || tail === null) {
    return null;
  }
  return { head, tail, compressed };
}

/** The normalized 8 groups after expanding the compressed form ("::") and an embedded IPv4 tail (null when malformed). */
function ipv6Groups(ip: string): string[] | null {
  const split = splitIpv6Halves(ip);
  if (split === null) {
    return null;
  }
  const zeros = 8 - split.head.length - split.tail.length;
  if (!split.compressed) {
    // The uncompressed form carries all 8 groups in the first half
    // (no "::", so the second half is empty)
    return zeros === 0 ? split.head : null;
  }
  return zeros >= 1 ? [...split.head, ...Array<string>(zeros).fill("0"), ...split.tail] : null;
}

/**
 * A ":"-separated group list → an array of hex groups (empty string
 * → empty array; malformed → null).
 * `ipv4Tail` controls whether the **last piece** of this half may
 * carry an embedded IPv4.
 */
function parseIpv6Groups(raw: string, ipv4Tail: boolean): string[] | null {
  const groups: string[] = [];
  const pieces = raw === "" ? [] : raw.split(":");
  for (const [index, piece] of pieces.entries()) {
    const parsed = groupsOfPiece(piece, ipv4Tail && index === pieces.length - 1);
    if (parsed === null) {
      return null;
    }
    groups.push(...parsed);
  }
  return groups;
}

/**
 * The strict form of a decimal octet: 0-255; no leading zeros, no
 * empty, no hex, no exponential notation, no whitespace.
 * `Number()`'s coercion would pass "" → 0, "0x10" → 16, "1e2" →
 * 100, which the later range check cannot catch (the conversion has
 * already succeeded).
 */
const DECIMAL_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** One piece → hex groups (an embedded IPv4 yields 2 groups; malformed → null). */
function groupsOfPiece(piece: string, ipv4Allowed: boolean): readonly string[] | null {
  if (!piece.includes(".")) {
    return /^[0-9a-fA-F]{1,4}$/.test(piece) ? [piece.toLowerCase()] : null;
  }
  if (!ipv4Allowed) {
    return null;
  }
  const octets = piece.split(".");
  if (octets.length !== 4 || !octets.every((octet) => DECIMAL_OCTET.test(octet))) {
    return null;
  }
  const [a = 0, b = 0, c = 0, d = 0] = octets.map(Number);
  return [((a << 8) | b).toString(16), ((c << 8) | d).toString(16)];
}

/**
 * Best-effort per-source-IP rate limiting (the Workers Rate
 * Limiting binding). true = allowed.
 *
 * The fail-open boundary (everything tips toward availability):
 * - A missing CF-Connecting-IP passes as unattributable. On the
 *   production Cloudflare path it is a header the edge always
 *   **overwrites**, leaving no room for client spoofing; it is absent
 *   only on direct arrival (cf dev, tests)
 * - A failure of the limiter itself passes too (auth and lease
 *   paths must not halt wholesale on a limiter failure)
 */
export function ipRateLimitAllowed(
  limiter: RateLimit,
  request: { readonly source: unknown },
): Effect.Effect<boolean> {
  const source = request.source;
  const ip = source instanceof Request ? source.headers.get("cf-connecting-ip") : null;
  if (ip === null || ip === "") {
    return Effect.succeed(true);
  }
  return Effect.tryPromise({
    try: async () => (await limiter.limit({ key: rateLimitKeyOf(ip) })).success,
    catch: (error) => error,
  }).pipe(
    Effect.catch((error: unknown) =>
      // The **explicit** fail-open recovery (an availability-side
      // design decision — see the doc above). But it is not swallowed
      // silently (CLAUDE.md): if a binding misconfiguration leaves
      // the limiter permanently down, every limit stays disabled and
      // nobody notices. A static message is left in the Workers logs
      // (wrangler tail / Workers Logs — read only by the operator;
      // not an external send); no request contents or IPs are logged.
      // error.message is a string outside our control (a future
      // limiter implementation could put the key in it), so only the
      // kind name is logged, honoring the "no IPs" promise
      Effect.logWarning(
        "rate limiter binding failed; allowing the request (fail-open)",
        error instanceof Error ? error.name : "unknown",
      ).pipe(Effect.as(true)),
    ),
  );
}
