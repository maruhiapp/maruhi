// The brokering vocabulary of `maruhi proxy run` (PF4): a brokered
// credential, its placeholder, and how a destination is matched against
// a rule's hosts. Pure functions — the network is proxy-server.ts.

import type { HostPattern, Surface } from "./proxy-config.ts";

/** A destination the child asked for: scheme (what the proxy will speak upstream), host, port. */
export interface Target {
  readonly scheme: "https" | "http";
  /** Lower-cased host name or IPv4 literal. */
  readonly host: string;
  readonly port: number;
}

/**
 * One credential the proxy brokers: the child holds `placeholder`, the
 * proxy swaps it for the real value toward `hosts`, on `surfaces` only.
 */
export interface BrokeredCredential {
  /** The environment variable name the child sees (identifies the rule in messages). */
  readonly name: string;
  readonly placeholder: string;
  readonly hosts: readonly HostPattern[];
  readonly surfaces: readonly Surface[];
  /**
   * The real value right now. A `broker` rule returns the variable's bytes;
   * a `connector` rule mints or refreshes a short-lived credential (and may
   * fail with a reason that carries no secret).
   */
  readonly resolve: () => Promise<Uint8Array>;
}

/** Whether `pattern` names `target` (scheme, port, and host — exact or `*.` suffix). */
export function matchesTarget(pattern: HostPattern, target: Target): boolean {
  if (pattern.scheme !== target.scheme || pattern.port !== target.port) {
    return false;
  }
  if (!pattern.wildcard) {
    return pattern.host === target.host;
  }
  // `*.example.com` matches `a.example.com` and `a.b.example.com`, never `example.com` itself
  return target.host.endsWith(`.${pattern.host}`);
}

/** The credentials whose rules name `target`. */
export function credentialsFor(
  credentials: readonly BrokeredCredential[],
  target: Target,
): readonly BrokeredCredential[] {
  return credentials.filter((credential) =>
    credential.hosts.some((pattern) => matchesTarget(pattern, target)),
  );
}

const PLACEHOLDER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/**
 * A fresh placeholder for `name`: `mhp_<NAME>_<22 random alphanumerics>`
 * (~131 bits). The prefix and the name make it readable in a log or a
 * transcript as "a maruhi placeholder for X"; the random tail makes an
 * accidental match in traffic impossible and keeps one run's placeholders
 * useless to another.
 */
export function makePlaceholder(name: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(22));
  let tail = "";
  for (const byte of bytes) {
    tail += PLACEHOLDER_ALPHABET[byte % PLACEHOLDER_ALPHABET.length];
  }
  return `mhp_${name}_${tail}`;
}

/** `host:port` for messages and map keys. */
export function authorityOf(target: Target): string {
  return `${target.host}:${target.port}`;
}
