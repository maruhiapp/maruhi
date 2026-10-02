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
  /**
   * The address the sandbox-mode guard resolved and checked (proxy-guard.ts
   * — §21 R-19). When present the connection goes to it, never to a second
   * resolution of `host` (a counting resolver would answer differently).
   */
  readonly resolved?: string | undefined;
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
   * fail with a reason that carries no secret). Called only when a request
   * toward one of `hosts` carries the placeholder.
   */
  readonly resolve: () => Promise<Uint8Array>;
  /**
   * The values already held, **without minting**: the variable's bytes for
   * a `broker` rule; the current and the previous token for a connector
   * (both may still be valid). Used to scrub responses (the proxy must
   * never mint a credential just to look for it in a response — review
   * finding pf4-design.md §19 D-1).
   */
  readonly known: () => readonly Uint8Array[];
  /**
   * Teardown for a credential that outlives nothing (a connector revokes
   * its minted token). Best effort; failures are reported, never fatal.
   */
  readonly release?: (() => Promise<void>) | undefined;
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
  return `mhp_${name}_${randomAlphanumeric(22)}`;
}

// Bytes at or above this are discarded so every alphabet character is
// equally likely (256 is not a multiple of 62 — rejection sampling)
const UNBIASED_LIMIT = 256 - (256 % PLACEHOLDER_ALPHABET.length);

/** `length` uniformly random alphanumerics (~5.95 bits each; 22 ≈ 131 bits). Also the run's proxy credential. */
export function randomAlphanumeric(length: number): string {
  let text = "";
  while (text.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
      if (byte < UNBIASED_LIMIT && text.length < length) {
        text += PLACEHOLDER_ALPHABET[byte % PLACEHOLDER_ALPHABET.length];
      }
    }
  }
  return text;
}

/** `host:port` for messages and map keys. */
export function authorityOf(target: Target): string {
  return `${target.host}:${target.port}`;
}

/** The `Host` header for `target` (RFC 9112 §3.2 — the port only when it is not the scheme's default). */
export function hostHeaderOf(target: Target): string {
  const defaultPort = target.scheme === "https" ? 443 : 80;
  return target.port === defaultPort ? target.host : `${target.host}:${target.port}`;
}
