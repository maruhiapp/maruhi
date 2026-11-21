import dns from "node:dns";
import net from "node:net";

export function isLoopbackBind(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === "localhost" || lower === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower);
}

export function isHostLocalName(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === "localhost" || lower.endsWith(".localhost");
}

const HOST_LOCAL = new net.BlockList();
HOST_LOCAL.addSubnet("127.0.0.0", 8, "ipv4");
HOST_LOCAL.addSubnet("0.0.0.0", 8, "ipv4");
HOST_LOCAL.addSubnet("169.254.0.0", 16, "ipv4");
HOST_LOCAL.addSubnet("100.64.0.0", 10, "ipv4");
HOST_LOCAL.addSubnet("192.0.0.0", 24, "ipv4");
HOST_LOCAL.addAddress("168.63.129.16", "ipv4");
HOST_LOCAL.addSubnet("::1", 128, "ipv6");
HOST_LOCAL.addSubnet("::", 128, "ipv6");
HOST_LOCAL.addSubnet("fe80::", 10, "ipv6");
HOST_LOCAL.addSubnet("::ffff:7f00:0", 104, "ipv6");
HOST_LOCAL.addSubnet("::ffff:0:0", 104, "ipv6");
HOST_LOCAL.addSubnet("::ffff:a9fe:0", 112, "ipv6");
HOST_LOCAL.addSubnet("::ffff:6440:0", 106, "ipv6");
HOST_LOCAL.addSubnet("::ffff:c000:0", 120, "ipv6");
HOST_LOCAL.addAddress("::ffff:a83f:8110", "ipv6");
HOST_LOCAL.addAddress("fd00:ec2::254", "ipv6");

function bareLiteral(ip: string): string {
  return ip.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
}

export function isHostLocalAddress(ip: string): boolean {
  const bare = bareLiteral(ip);
  const family = net.isIP(bare);
  return family !== 0 && HOST_LOCAL.check(bare, family === 4 ? "ipv4" : "ipv6");
}

export type Lookup = (
  host: string,
) => Promise<readonly { readonly address: string; readonly family: number }[]>;

const systemLookup: Lookup = (host) => dns.promises.lookup(host, { all: true });

export type HostLocalCheck =
  | { readonly refused: string }
  | { readonly refused?: undefined; readonly address: string | null };

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

export function formatAuthority(host: string, port: number): string {
  return net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
}
