import { type ExecPreset, EXEC_PRESETS } from "./sync-exec.ts";
import { HTTP_PRESETS } from "./sync-http-presets.ts";
import type { HttpPreset } from "./sync-http.ts";
import type { DriverKind, PresetId, ResolvedOptions } from "./sync-types.ts";

export interface UnavailableDriver {
  readonly unavailable: string;
}

export interface SyncPreset {
  readonly id: PresetId;
  readonly exec: ExecPreset | UnavailableDriver;
  readonly http: HttpPreset | UnavailableDriver;
  readonly isProduction: (options: ResolvedOptions) => boolean;
}

export function isUnavailable(
  declaration: ExecPreset | HttpPreset | UnavailableDriver,
): declaration is UnavailableDriver {
  return "unavailable" in declaration;
}

export function defaultDriverOf(preset: SyncPreset): DriverKind {
  return isUnavailable(preset.exec) ? "http" : "exec";
}

const NETLIFY_PRODUCTION_CONTEXTS = new Set(["production", "all"]);

export const SYNC_PRESETS: Readonly<Record<PresetId, SyncPreset>> = {
  "cloudflare-workers": {
    id: "cloudflare-workers",
    exec: EXEC_PRESETS["cloudflare-workers"],
    http: HTTP_PRESETS["cloudflare-workers"],
    isProduction: (options) => options["environment"] === undefined,
  },
  vercel: {
    id: "vercel",
    exec: EXEC_PRESETS.vercel,
    http: HTTP_PRESETS.vercel,
    isProduction: (options) => options["environment"] === "production",
  },
  netlify: {
    id: "netlify",
    exec: {
      unavailable:
        "the netlify preset has no exec driver: the Netlify CLI takes the value as a command-line argument (visible in ps), so maruhi only talks to the Netlify API",
    },
    http: HTTP_PRESETS.netlify,
    isProduction: (options) => NETLIFY_PRODUCTION_CONTEXTS.has(String(options["context"])),
  },
  "github-actions": {
    id: "github-actions",
    exec: EXEC_PRESETS["github-actions"],
    http: {
      unavailable:
        "the github-actions preset has no http driver: the GitHub API takes the value sealed to the repository's public key with libsodium, which maruhi does not implement, so maruhi only drives the gh CLI",
    },
    isProduction: (options) =>
      options["environment"] === undefined ||
      String(options["environment"]).toLowerCase() === "production",
  },
};
