import { randomHexSync } from "../ids.ts";

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

  grant(head: LeaseChainHead, nowMs: number): string {
    for (const [token, grant] of this.#grants) {
      if (grant.expiresAtMs <= nowMs) {
        this.#grants.delete(token);
      }
    }
    const token = randomHexSync(32);
    this.#grants.set(token, { head, expiresAtMs: nowMs + this.#ttlMs });
    return token;
  }

  take(token: string, nowMs: number): LeaseChainHead | undefined {
    const grant = this.#grants.get(token);
    this.#grants.delete(token);
    return grant === undefined || grant.expiresAtMs <= nowMs ? undefined : grant.head;
  }
}
