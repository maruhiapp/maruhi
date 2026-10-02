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

/**
 * The host-local ranges, matched **by value** (review findings §21 R-16 —
 * `0:0:0:0:0:0:0:1`, `::0:1`, the hex-mapped `::ffff:7f00:1` are the
 * loopback as much as `::1` and `::ffff:127.0.0.1` are): loopback (127/8,
 * ::1), unspecified (0/8, ::), link-local (169.254/16 — the IPv4 metadata
 * service; fe80::/10), the IPv4-mapped forms of those three, and the AWS
 * IPv6 metadata service (fd00:ec2::254). `net.BlockList` parses every
 * textual form; measured identical under Bun 1.4.2 and Node.
 */
const HOST_LOCAL = new net.BlockList();
HOST_LOCAL.addSubnet("127.0.0.0", 8, "ipv4");
HOST_LOCAL.addSubnet("0.0.0.0", 8, "ipv4");
HOST_LOCAL.addSubnet("169.254.0.0", 16, "ipv4");
// Shared address space (RFC 6598, 100.64/10): never a public destination;
// cloud providers put metadata endpoints there (Alibaba Cloud's
// 100.100.100.200) — §21 R-20
HOST_LOCAL.addSubnet("100.64.0.0", 10, "ipv4");
HOST_LOCAL.addSubnet("::1", 128, "ipv6");
HOST_LOCAL.addSubnet("::", 128, "ipv6");
HOST_LOCAL.addSubnet("fe80::", 10, "ipv6");
HOST_LOCAL.addSubnet("::ffff:7f00:0", 104, "ipv6");
HOST_LOCAL.addSubnet("::ffff:0:0", 104, "ipv6");
HOST_LOCAL.addSubnet("::ffff:a9fe:0", 112, "ipv6");
HOST_LOCAL.addSubnet("::ffff:6440:0", 106, "ipv6");
HOST_LOCAL.addAddress("fd00:ec2::254", "ipv6");

/** An IP literal without URL brackets (`[::1]` from `URL.hostname`) or a zone id (`fe80::1%eth0`). */
function bareLiteral(ip: string): string {
  return ip.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
}

/** Whether `ip` (any textual form) is a host-local address — see {@link HOST_LOCAL}. */
export function isHostLocalAddress(ip: string): boolean {
  const bare = bareLiteral(ip);
  const family = net.isIP(bare);
  return family !== 0 && HOST_LOCAL.check(bare, family === 4 ? "ipv4" : "ipv6");
}

export type Lookup = (
  host: string,
) => Promise<readonly { readonly address: string; readonly family: number }[]>;

const systemLookup: Lookup = (host) => dns.promises.lookup(host, { all: true });

/** The guard's answer: a refusal with its reason, or clearance with the address that was checked (null for a literal — it is its own address). */
export type HostLocalCheck =
  | { readonly refused: string }
  | { readonly refused?: undefined; readonly address: string | null };

/**
 * Whether `host` may be reached from the sandbox through this proxy. A
 * literal is classified as it is; a name is resolved and **every** address
 * checked, and the first one is returned so the connection goes to the
 * address that was checked — never to a second resolution, which a
 * resolver under the sandbox's control could answer differently (query
 * counting, not a timing race — §21 R-19). A name that cannot be resolved
 * is refused: the connection would fail anyway, and refusing keeps the
 * rule fail-closed.
 */
export async function checkHostLocal(
  host: string,
  lookup: Lookup = systemLookup,
): Promise<HostLocalCheck> {
  if (isHostLocalName(host) || isHostLocalAddress(host)) {
    return {
      refused: `${host} is a host-local destination (this machine's loopback or link-local, shared address space, or the cloud metadata service)`,
    };
  }
  if (net.isIP(bareLiteral(host)) !== 0) {
    return { address: null };
  }
  let addresses: readonly { readonly address: string }[];
  try {
    addresses = await lookup(host);
  } catch {
    return { refused: `${host} cannot be resolved` };
  }
  const local = addresses.find((entry) => isHostLocalAddress(entry.address));
  if (local !== undefined) {
    return {
      refused: `${host} resolves to a host-local address (${local.address} — loopback or link-local, where the cloud metadata service lives)`,
    };
  }
  const first = addresses[0];
  return first === undefined
    ? { refused: `${host} cannot be resolved` }
    : { address: first.address };
}

/** `host:port`, with an IPv6 literal in brackets (RFC 3986) — for URLs and messages. */
export function formatAuthority(host: string, port: number): string {
  return net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
}
