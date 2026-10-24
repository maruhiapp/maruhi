// How a chain head stands against a verified chain: an entry of it, behind
// or ahead of it, or a fork. `maruhi mirror sync` and `status` report the
// heads they read this way; mark's and promote's guards ask headOnChain.

import type { VerifiedProject } from "../chain-sync.ts";
import { countNoun } from "../display.ts";

/** Whether a head is an entry of a verified chain (its head, or an earlier entry). */
export function headOnChain(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  chain: VerifiedProject,
): boolean {
  return head.chainHeadSeq === chain.state.headSeq
    ? head.chainHeadHashHex === chain.state.headHashHex
    : head.chainHeadSeq < chain.state.headSeq &&
        chain.history.entryHashAt(head.chainHeadSeq) === head.chainHeadHashHex;
}

/** How a head stands against the verified view of the server (the same cross-check as `project export`). */
export function headNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string {
  const fork = forkNote(head, verified);
  if (fork !== null) {
    return fork;
  }
  if (head.chainHeadHashHex === verified.state.headHashHex) {
    return "in sync with the verified view";
  }
  if (head.chainHeadSeq < verified.state.headSeq) {
    return `behind the verified view by ${countNoun(verified.state.headSeq - head.chainHeadSeq, "chain entry")} (seq ${head.chainHeadSeq} of ${verified.state.headSeq})`;
  }
  return `ahead of the verified view (seq ${head.chainHeadSeq} > ${verified.state.headSeq}) — the mirror was promoted and written to, the server rolled back, the mirror's recorded source is not this server, or a replication was forced from another server; run \`maruhi project verify\``;
}

/**
 * A head that is not on the verified view's chain and not past it: the
 * view and the head are both signature-verified, so only an equivocating
 * server produces this (never an honest race — "behind" and "ahead" are
 * those). A sync whose replica shows it fails after the commit (ruling H
 * revision, round 8: a cron must notice). null = no fork evidence.
 */
export function forkNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string | null {
  if (head.chainHeadHashHex === verified.state.headHashHex) {
    return null;
  }
  if (head.chainHeadSeq < verified.state.headSeq) {
    return verified.history.entryHashAt(head.chainHeadSeq) === head.chainHeadHashHex
      ? null
      : `on a different chain (its seq ${head.chainHeadSeq} is not the verified view's entry) — evidence of a fork (CRYPTO_SPEC §6.3); do not promote it and run \`maruhi project verify\``;
  }
  if (head.chainHeadSeq === verified.state.headSeq) {
    return `a different chain at the same height as the verified view (head ${verified.state.headHashHex}) — evidence of a fork (CRYPTO_SPEC §6.3); do not promote it and run \`maruhi project verify\``;
  }
  return null;
}
