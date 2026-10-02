// Host-local destinations in sandbox mode (pf4-design.md §21 R-12).
//
// When `proxy run --listen` binds beyond the loopback, the proxy is the
// sandbox's path to the network — and it runs on the host, in the host's
// network namespace. A destination no rule names is tunnelled or relayed
// as it is (`unmatched: allow`), so without this guard a sandboxed child
// could ask the proxy for `http://169.254.169.254/` (the cloud metadata
// service) or `127.0.0.1:<a host service>` and reach what the sandbox was
// built to keep it from. Refused here: a loopback, link-local, or
// unspecified address, by literal or by what the name resolves to (the
// resolution happens before the connection, so a name that points at the
// loopback is caught) — unless a rule names the host (a member's explicit
// decision, `http://localhost:8787` for a dev server included). On the
// default loopback binding the child is on the host already and gains
// nothing from the proxy, so the guard is off there.
//
// Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7) stay reachable: a
// sandbox on a bridge network reaches them on its own, and an internal API
// on one is an ordinary destination.

import dns from "node:dns";
import net from "node:net";

/** Whether a bind address keeps the proxy on this machine (then the guard is off). */
export function isLoopbackBind(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === "localhost" || lower === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower);
}

/** `localhost` and every name under `.localhost` (RFC 6761 — resolution is not needed to know). */
export function isHostLocalName(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === "localhost" || lower.endsWith(".localhost");
}

/** Loopback (127/8, ::1), link-local (169.254/16, fe80::/10 — the metadata service lives there), unspecified (0.0.0.0, ::). */
export function isHostLocalAddress(ip: string): boolean {
  const lower = ip.toLowerCase();
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(lower);
  if (mapped?.[1] !== undefined) {
    return isHostLocalAddress(mapped[1]);
  }
  if (net.isIPv4(lower)) {
    return /^(127|0)\./.test(lower) || lower.startsWith("169.254.");
  }
  if (net.isIPv6(lower)) {
    return lower === "::1" || lower === "::" || /^fe[89ab][0-9a-f]:/.test(lower);
  }
  return false;
}

export type Lookup = (
  host: string,
) => Promise<readonly { readonly address: string; readonly family: number }[]>;

const systemLookup: Lookup = (host) => dns.promises.lookup(host, { all: true });

/**
 * Why `host` must not be reached from the sandbox through this proxy, or
 * null when it may. A name that cannot be resolved is refused too: the
 * connection would fail anyway, and refusing keeps the rule fail-closed.
 */
export async function hostLocalReason(
  host: string,
  lookup: Lookup = systemLookup,
): Promise<string | null> {
  if (isHostLocalName(host) || isHostLocalAddress(host)) {
    return `${host} is a host-local destination (this machine's loopback)`;
  }
  if (net.isIP(host) !== 0) {
    return null;
  }
  let addresses: readonly { readonly address: string }[];
  try {
    addresses = await lookup(host);
  } catch {
    return `${host} cannot be resolved`;
  }
  const local = addresses.find((entry) => isHostLocalAddress(entry.address));
  return local === undefined
    ? null
    : `${host} resolves to a host-local address (${local.address} — loopback or link-local, where the cloud metadata service lives)`;
}

/** `host:port`, with an IPv6 literal in brackets (RFC 3986) — for URLs and messages. */
export function formatAuthority(host: string, port: number): string {
  return net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
}
