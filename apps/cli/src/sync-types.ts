// The declaration types shared by `maruhi sync`'s 2 drivers (exec =
// sync-exec.ts / http = sync-http.ts). Preset composition is
// sync-preset.ts.

/** Preset identifiers accepted by the sync config (`targets.<name>.preset`), in display order. */
export const PRESET_IDS = ["cloudflare-workers", "vercel", "netlify", "github-actions"] as const;

/** One of {@link PRESET_IDS}. */
export type PresetId = (typeof PRESET_IDS)[number];

/** Driver identifiers accepted by the sync config (`targets.<name>.driver`). */
export type DriverKind = "exec" | "http";

/** Declaration of one preset option (validated by sync-config.ts). */
export interface OptionSpec {
  readonly type: "string" | "boolean";
  readonly required: boolean;
  /** A closed set (e.g. Vercel's environment names). */
  readonly values?: readonly string[];
  /**
   * The shape of a string option (not a closed set but a value that
   * rides on argv or a URL — e.g. GitHub's `OWNER/REPO`). Not
   * combined with `values`. `hint` is the refusal text's "expected
   * shape".
   */
  readonly pattern?: { readonly regex: RegExp; readonly hint: string };
}

/** Options given by the config (verified against the preset's declarations). */
export type ResolvedOptions = Readonly<Record<string, string | boolean>>;

/**
 * What the target's stdin reader does with trailing newlines — the driver refuses the
 * values whose bytes it could not deliver unchanged:
 * - `kept`: nothing is stripped (wrangler's JSON, the http APIs)
 * - `strippedFromSingleLine`: one trailing newline goes from a single-line value only
 *   (Vercel CLI) → a single-line value ending in one newline is refused
 * - `stripped`: every trailing CR / LF goes, from any value (gh) → a value ending in
 *   a newline is refused
 */
export type TrailingNewlineHandling = "kept" | "strippedFromSingleLine" | "stripped";

/**
 * What the target accepts as a name. The maruhi name is sent unchanged, so a name the
 * target would rename or refuse is refused here first (before anything is sent).
 */
export interface NameConstraint {
  readonly regex: RegExp;
  /** The rule's description attached to the refusal text (part of a sentence that carries only the name). */
  readonly rule: string;
}

/** Value constraints the driver imposes on what it can carry. */
export interface ValueConstraints {
  /** A single value's cap (bytes). Exceeding it is refused (truncation never happens silently). */
  readonly maxBytes: number | null;
  /** Refuses an empty value (a CLI that reads empty stdin as "no value"). */
  readonly nonEmpty: boolean;
  /** Trailing-newline handling (refuses values of the shape that would get dropped). */
  readonly trailingNewline: TrailingNewlineHandling;
  /** The name rule (none = `null` = the maruhi name passes as-is). */
  readonly name: NameConstraint | null;
}
