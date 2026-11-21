import type { HostPattern, Surface } from "./proxy-config.ts";

export interface Target {
  readonly scheme: "https" | "http";
  readonly host: string;
  readonly port: number;
  readonly resolved?: string | undefined;
}

export interface BrokeredCredential {
  readonly name: string;
  readonly placeholder: string;
  readonly hosts: readonly HostPattern[];
  readonly surfaces: readonly Surface[];
  readonly resolve: () => Promise<Uint8Array>;
  readonly known: () => readonly Uint8Array[];
  readonly release?: (() => Promise<void>) | undefined;
}

export function matchesTarget(pattern: HostPattern, target: Target): boolean {
  if (pattern.scheme !== target.scheme || pattern.port !== target.port) {
    return false;
  }
  if (!pattern.wildcard) {
    return pattern.host === target.host;
  }
  return target.host.endsWith(`.${pattern.host}`);
}

export function credentialsFor(
  credentials: readonly BrokeredCredential[],
  target: Target,
): readonly BrokeredCredential[] {
  return credentials.filter((credential) =>
    credential.hosts.some((pattern) => matchesTarget(pattern, target)),
  );
}

const PLACEHOLDER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export function makePlaceholder(name: string): string {
  return `mhp_${name}_${randomAlphanumeric(22)}`;
}

const UNBIASED_LIMIT = 256 - (256 % PLACEHOLDER_ALPHABET.length);

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

export function authorityOf(target: Target): string {
  return `${target.host}:${target.port}`;
}

export function hostHeaderOf(target: Target): string {
  const defaultPort = target.scheme === "https" ? 443 : 80;
  return target.port === defaultPort ? target.host : `${target.host}:${target.port}`;
}
