export const PRESET_IDS = ["cloudflare-workers", "vercel", "netlify", "github-actions"] as const;

export type PresetId = (typeof PRESET_IDS)[number];

export type DriverKind = "exec" | "http";

export interface OptionSpec {
  readonly type: "string" | "boolean";
  readonly required: boolean;
  readonly values?: readonly string[];
  readonly pattern?: { readonly regex: RegExp; readonly hint: string };
}

export type ResolvedOptions = Readonly<Record<string, string | boolean>>;

export type TrailingNewlineHandling = "kept" | "strippedFromSingleLine" | "stripped";

export interface NameConstraint {
  readonly regex: RegExp;
  readonly rule: string;
}

export interface ValueConstraints {
  readonly maxBytes: number | null;
  readonly nonEmpty: boolean;
  readonly trailingNewline: TrailingNewlineHandling;
  readonly name: NameConstraint | null;
}
