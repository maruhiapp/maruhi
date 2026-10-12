// The chain-read grants of issued leases (AUTH_SPEC §14-2 — Sc-3a): an
// authorized issuance (issueLease) records the head it was judged against
// under a fresh single-use token, and the chain read (leaseChain) takes it.
// Instance memory only: the read follows the issuance within the same
// request, and an eviction in between fails that lease with a 500.

import { randomHex } from "../ids.ts";

/** How long an issued lease's chain read stays open (it follows within the same request). */
const LEASE_CHAIN_GRANT_TTL_MS = 60_000;

export interface LeaseChainHead {
  readonly seq: number;
  readonly hashHex: string;
}

export class LeaseChainGrants {
  readonly #ttlMs: number;
  readonly #grants = new Map<
    string,
    { readonly head: LeaseChainHead; readonly expiresAtMs: number }
  >();

  constructor(ttlMs: number = LEASE_CHAIN_GRANT_TTL_MS) {
    this.#ttlMs = ttlMs;
  }

  /** Records `head` under a fresh 256-bit token (expired grants are dropped on the way). */
  grant(head: LeaseChainHead, nowMs: number): string {
    for (const [token, grant] of this.#grants) {
      if (grant.expiresAtMs <= nowMs) {
        this.#grants.delete(token);
      }
    }
    const token = randomHex(32);
    this.#grants.set(token, { head, expiresAtMs: nowMs + this.#ttlMs });
    return token;
  }

  /** The head granted under `token`, consumed; undefined when unknown, spent or expired. */
  take(token: string, nowMs: number): LeaseChainHead | undefined {
    const grant = this.#grants.get(token);
    this.#grants.delete(token);
    return grant === undefined || grant.expiresAtMs <= nowMs ? undefined : grant.head;
  }
}
