// A `maruhi sync` preset = declarations of the 2 driver kinds for
// one sync target (integration-options.md §3 supplement 13 W1 "1
// interface × 2 kinds").
//
// exec (sync-exec.ts — an installed vendor CLI) and http
// (sync-http.ts — the vendor API) share the same preset id; the
// config's `driver` chooses which to use. A receipt carries only
// the preset id, so switching drivers keeps the prior delivery
// records usable (the fact of having delivered the same
// name+version to the same target does not depend on the driver).
//
// Some sync targets can only have one driver (SY4's ruling A):
// Netlify's CLI takes the value as an argument (argv = visible in
// `ps`), so no safe exec recipe exists and it has only http.
// GitHub Actions secrets conversely cannot have http (the API
// requires a libsodium sealed box to the repository's public key,
// which WebCrypto lacks — supplement 5. maruhi does not implement
// sealing and leaves it to `gh`). In place of a declaration, a
// **reason** (`unavailable`) is stored, which becomes the message
// when the config picks that driver. A config omitting `driver`
// gets exec if present, otherwise http.

import { type ExecPreset, EXEC_PRESETS } from "./sync-exec.ts";
import { type HttpPreset, HTTP_PRESETS } from "./sync-http.ts";
import type { DriverKind, PresetId, ResolvedOptions } from "./sync-types.ts";

/** A driver the preset does not offer, with the reason shown to whoever configures it. */
export interface UnavailableDriver {
  readonly unavailable: string;
}

/** One deploy target kind: the same destination reachable through either driver. */
export interface SyncPreset {
  readonly id: PresetId;
  readonly exec: ExecPreset | UnavailableDriver;
  readonly http: HttpPreset | UnavailableDriver;
  /** The production judgment when unstated (the default of the misoperation guard — sync-config.ts). */
  readonly isProduction: (options: ResolvedOptions) => boolean;
}

/** Whether the driver has no declaration (a reason only). */
export function isUnavailable(
  declaration: ExecPreset | HttpPreset | UnavailableDriver,
): declaration is UnavailableDriver {
  return "unavailable" in declaration;
}

/** The default for a config omitting `driver`: exec if present, otherwise http. */
export function defaultDriverOf(preset: SyncPreset): DriverKind {
  return isUnavailable(preset.exec) ? "http" : "exec";
}

// The Netlify deploy contexts treated as production (`all` includes production)
const NETLIFY_PRODUCTION_CONTEXTS = new Set(["production", "all"]);

/** Built-in presets (first-class targets — owner decision: Vercel / Cloudflare Workers; Netlify = http only; GitHub Actions secrets = exec only). */
export const SYNC_PRESETS: Readonly<Record<PresetId, SyncPreset>> = {
  "cloudflare-workers": {
    id: "cloudflare-workers",
    exec: EXEC_PRESETS["cloudflare-workers"],
    http: HTTP_PRESETS["cloudflare-workers"],
    // No wrangler named environment = the top-level Worker (production)
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
    // Repository secrets (no Environment) affect every workflow =
    // treated as production. Environment secrets only when the
    // name is production — GitHub's Environment names are
    // case-insensitive (docs "Managing environments"), so fold
    // them for comparison
    isProduction: (options) =>
      options["environment"] === undefined ||
      String(options["environment"]).toLowerCase() === "production",
  },
};
