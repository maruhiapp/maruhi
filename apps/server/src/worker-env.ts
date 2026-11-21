import { SetupIncompleteError } from "@maruhi/api-schema";
import type { ProjectId } from "@maruhi/core";
import { Context, Data, Effect, Redacted } from "effect";

import type { Env, ProjectChainDO } from "./do/chain-do.ts";

type SecretName =
  | "GITHUB_CLIENT_ID"
  | "GITHUB_CLIENT_SECRET"
  | "SERVER_ENC_KEY_IKM"
  | "OPS_ALERT_WEBHOOK_URL";

export type SecretBindingValue = string | SecretsStoreSecret;

type WorkerBindings = Omit<Env, SecretName>;

export class WorkerEnv extends Context.Service<WorkerEnv, WorkerBindings>()("WorkerEnv") {}

interface WorkerSecretsShape {
  readonly githubClientId: string | undefined;
  readonly githubClientSecret: Redacted.Redacted<string> | undefined;
  readonly serverEncKeyIkm: Redacted.Redacted<string> | undefined;
  readonly opsAlertWebhookUrl: Redacted.Redacted<string> | undefined;
}

export class WorkerSecrets extends Context.Service<WorkerSecrets, WorkerSecretsShape>()(
  "WorkerSecrets",
) {}

function redactSecret(
  raw: string | undefined,
  label: SecretName,
): Redacted.Redacted<string> | undefined {
  return raw === undefined || raw === "" ? undefined : Redacted.make(raw, { label });
}

function resolveSecretString(
  raw: SecretBindingValue | undefined,
): Effect.Effect<string | undefined> {
  if (raw === undefined || typeof raw === "string") {
    return Effect.succeed(raw === "" ? undefined : raw);
  }
  return Effect.tryPromise(() => raw.get()).pipe(
    Effect.map((value) => (typeof value === "string" && value !== "" ? value : undefined)),
    Effect.catch(() => Effect.succeed(undefined)),
  );
}

export function readWorkerSecret(
  raw: SecretBindingValue | undefined,
  label: SecretName,
): Effect.Effect<Redacted.Redacted<string> | undefined> {
  return resolveSecretString(raw).pipe(Effect.map((value) => redactSecret(value, label)));
}

export function readWorkerSecrets(env: {
  readonly GITHUB_CLIENT_ID?: SecretBindingValue;
  readonly GITHUB_CLIENT_SECRET?: SecretBindingValue;
  readonly SERVER_ENC_KEY_IKM?: SecretBindingValue;
  readonly OPS_ALERT_WEBHOOK_URL?: SecretBindingValue;
}): Effect.Effect<WorkerSecretsShape> {
  return Effect.gen(function* () {
    const githubClientId = yield* resolveSecretString(env.GITHUB_CLIENT_ID);
    const githubClientSecret = yield* readWorkerSecret(
      env.GITHUB_CLIENT_SECRET,
      "GITHUB_CLIENT_SECRET",
    );
    const serverEncKeyIkm = yield* readWorkerSecret(env.SERVER_ENC_KEY_IKM, "SERVER_ENC_KEY_IKM");
    const opsAlertWebhookUrl = yield* readWorkerSecret(
      env.OPS_ALERT_WEBHOOK_URL,
      "OPS_ALERT_WEBHOOK_URL",
    );
    return { githubClientId, githubClientSecret, serverEncKeyIkm, opsAlertWebhookUrl };
  });
}

export const projectStub = (
  env: Pick<Env, "PROJECT_CHAIN">,
  projectId: ProjectId,
): DurableObjectStub<ProjectChainDO> =>
  env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));

export class RpcCallError extends Data.TaggedError("RpcCallError")<{
  readonly errorName: string;
}> {}

export const rpcCall = <T>(call: () => PromiseLike<unknown>): Effect.Effect<T, RpcCallError> =>
  Effect.tryPromise({
    try: () => call() as Promise<T>,
    catch: (cause) =>
      new RpcCallError({ errorName: cause instanceof Error ? cause.name : "unknown" }),
  });

export const IP_RATE_LIMIT_PERIOD_SECONDS = 60;

export function rateLimitKeyOf(ip: string): string {
  if (!ip.includes(":")) {
    return ip;
  }
  const groups = ipv6Groups(ip);
  if (groups === null) {
    return ip;
  }
  const upperZero = groups.slice(0, 5).every((group) => Number.parseInt(group, 16) === 0);
  if (upperZero && Number.parseInt(groups[5] ?? "", 16) === 0xff_ff) {
    const hi = Number.parseInt(groups[6] ?? "0", 16);
    const lo = Number.parseInt(groups[7] ?? "0", 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  const prefix = groups.slice(0, 4).map((group) => Number.parseInt(group, 16).toString(16));
  return `${prefix.join(":")}::/64`;
}

function splitIpv6Halves(
  ip: string,
): { readonly head: string[]; readonly tail: string[]; readonly compressed: boolean } | null {
  const halves = (ip.split("%")[0] ?? ip).split("::");
  if (halves.length > 2) {
    return null;
  }
  const compressed = halves.length === 2;
  const tailRaw = halves[1] ?? "";
  const ipv4InTail = compressed && tailRaw !== "";
  const head = parseIpv6Groups(halves[0] ?? "", !compressed);
  const tail = parseIpv6Groups(tailRaw, ipv4InTail);
  if (head === null || tail === null) {
    return null;
  }
  return { head, tail, compressed };
}

function ipv6Groups(ip: string): string[] | null {
  const split = splitIpv6Halves(ip);
  if (split === null) {
    return null;
  }
  const zeros = 8 - split.head.length - split.tail.length;
  if (!split.compressed) {
    return zeros === 0 ? split.head : null;
  }
  return zeros >= 1 ? [...split.head, ...Array<string>(zeros).fill("0"), ...split.tail] : null;
}

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

const DECIMAL_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

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

export function ipRateLimitAllowed(
  limiter: RateLimit | undefined,
  request: { readonly source: unknown },
): Effect.Effect<boolean, SetupIncompleteError> {
  if (limiter === undefined) {
    return Effect.fail(new SetupIncompleteError({ reason: "rate-limit-unconfigured" }));
  }
  const source = request.source;
  const ip = source instanceof Request ? source.headers.get("cf-connecting-ip") : null;
  if (ip === null || ip === "") {
    return Effect.succeed(true);
  }
  return Effect.tryPromise({
    try: async () => (await limiter.limit({ key: rateLimitKeyOf(ip) })).success,
    catch: (error) => (error instanceof Error ? error.name : "unknown"),
  }).pipe(
    Effect.catch((errorName) =>
      Effect.logWarning(
        "rate limiter call failed; allowing the request (fail-open)",
        errorName,
      ).pipe(Effect.as(true)),
    ),
  );
}
