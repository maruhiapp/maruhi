import type { VerifiedProject } from "../chain-sync.ts";
import { countNoun } from "../display.ts";

export function headOnChain(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  chain: VerifiedProject,
): boolean {
  return head.chainHeadSeq === chain.state.headSeq
    ? head.chainHeadHashHex === chain.state.headHashHex
    : head.chainHeadSeq < chain.state.headSeq &&
        chain.history.entryHashAt(head.chainHeadSeq) === head.chainHeadHashHex;
}

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
