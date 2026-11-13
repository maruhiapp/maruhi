// Theme generation for the apex site (LP + docs — Blume) (ruling B —
// docs/notes/web-design-pass.md §4 "rulings made while implementing DP2").
//
// The only home for brand definitions is apps/web/theme/ (ADR-0013). From
// its artifact maruhi.css (the output of `astryx theme build` — the
// vermilion pair + on-accent pair are fixed in tokens, warm neutral is
// HCT-derived), this **writes** Blume's theme tokens (`--blume-*`) and the
// constants blume.config.ts reads. To avoid hand-writing raw hex on the
// site side (no double bookkeeping), the artifacts are committed and
// test/unit/theme.test.ts checks "regenerated = committed" (the same shape
// as DP1's "matches the generated CSS" contract).
//
// Along the same path, brand assets (favicon / logo / OG / apple-touch-icon)
// are copied from apps/web/public, and the dark-mode logo (an SVG with fill
// swapped to the dark accent) is derived.
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** A pair of values, light and dark. */
export interface ModePair {
  readonly light: string;
  readonly dark: string;
}

/** Brand tokens extracted from maruhi.css (all hex). */
export interface BrandTokens {
  readonly accent: ModePair;
  readonly onAccent: ModePair;
  readonly background: ModePair;
  readonly surface: ModePair;
  readonly popover: ModePair;
  readonly foreground: ModePair;
  readonly mutedForeground: ModePair;
  readonly border: ModePair;
  readonly radius: string;
}

/** Repo-relative paths (the catalog of generation inputs and outputs). */
export const paths = {
  /** Input: the Astryx theme's generated CSS (the canonical brand artifact). */
  webThemeCss: "apps/web/theme/maruhi.css",
  /** Input: the single-color vermilion logo (painted with the light accent). */
  webLogo: "apps/web/public/logo.svg",
  /** Output: Blume's theme.css (design-token overrides). */
  themeCss: "apps/site/theme.css",
  /** Output: the constants blume.config.ts reads. */
  tokensTs: "apps/site/theme/tokens.ts",
  /** Output: the dark-mode logo (fill swapped to the dark accent). */
  logoDark: "apps/site/public/logo-dark.svg",
} as const;

/** Brand assets copied unmodified from apps/web/public to apps/site/public. */
export const copiedAssets = ["favicon.svg", "logo.svg", "og.png", "apple-touch-icon.png"] as const;

const HEX = "#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?";

/**
 * Returns the theme's own token block: the `:scope { ... }` rule inside the
 * maruhi `@scope` of `@layer astryx-theme`, where the generator declares
 * the theme's custom properties. Since @astryxdesign 0.7.15 the generator
 * also writes concrete light-dark pairs into component-state rules outside
 * this block (a selected item's --color-text-secondary, for example,
 * carries the neutral value, not the brand one), so brand extraction must
 * read only this block; whole-file uniqueness no longer holds.
 */
function themeTokenBlock(css: string): string {
  const layerAt = css.indexOf("@layer astryx-theme {");
  const themeAt = layerAt < 0 ? -1 : css.indexOf('@scope ([data-astryx-theme="maruhi"])', layerAt);
  const scopeAt = themeAt < 0 ? -1 : css.indexOf(":scope {", themeAt);
  if (scopeAt < 0) {
    throw new Error(
      "apps/web/theme/maruhi.css: theme token block (:scope in @layer astryx-theme) not found",
    );
  }
  const openAt = css.indexOf("{", scopeAt);
  let depth = 0;
  for (let i = openAt; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}") {
      depth--;
      if (depth === 0) return css.slice(openAt + 1, i);
    }
  }
  throw new Error("apps/web/theme/maruhi.css: theme token block is not closed");
}

/**
 * Extracts exactly one `--<token>: light-dark(<hex>, <hex>)` declaration
 * from the theme token block. Uniqueness is required within the block
 * (multiple differing pairs means the generation rule's premise changed —
 * fail).
 */
function pickPair(css: string, token: string): ModePair {
  const re = new RegExp(`--${token}:\\s*light-dark\\((${HEX}),\\s*(${HEX})\\)`, "g");
  const pairs = new Set<string>();
  for (const m of css.matchAll(re)) pairs.add(`${m[1]!.toLowerCase()} ${m[2]!.toLowerCase()}`);
  if (pairs.size !== 1) {
    throw new Error(
      `apps/web/theme/maruhi.css: expected exactly one light-dark hex pair for --${token}, found ${pairs.size}`,
    );
  }
  const [light, dark] = [...pairs][0]!.split(" ") as [string, string];
  return { light: light.toUpperCase(), dark: dark.toUpperCase() };
}

function pickLength(css: string, token: string): string {
  const values = new Set(
    [...css.matchAll(new RegExp(`--${token}:\\s*([0-9.]+(?:rem|px))`, "g"))].map((m) => m[1]!),
  );
  if (values.size !== 1) {
    throw new Error(
      `apps/web/theme/maruhi.css: expected exactly one value for --${token}, found ${values.size}`,
    );
  }
  return [...values][0]!;
}

/** Extracts the brand tokens from maruhi.css's theme token block. */
export function extractBrand(webThemeCss: string): BrandTokens {
  const block = themeTokenBlock(webThemeCss);
  return {
    accent: pickPair(block, "color-accent"),
    onAccent: pickPair(block, "color-on-accent"),
    background: pickPair(block, "color-background-body"),
    surface: pickPair(block, "color-background-surface"),
    popover: pickPair(block, "color-background-popover"),
    foreground: pickPair(block, "color-text-primary"),
    mutedForeground: pickPair(block, "color-text-secondary"),
    border: pickPair(block, "color-border"),
    radius: pickLength(block, "radius-element"),
  };
}

const GENERATED_BANNER = `@generated by apps/site/scripts/build-theme.ts from ${paths.webThemeCss} — do not edit manually.
Re-run: bun run --filter @maruhi/site theme:build`;

const blumeTokenMap = (
  b: BrandTokens,
  mode: keyof ModePair,
): readonly (readonly [string, string])[] => [
  ["--blume-background", b.background[mode]],
  ["--blume-foreground", b.foreground[mode]],
  ["--blume-muted", b.surface[mode]],
  ["--blume-muted-foreground", b.mutedForeground[mode]],
  ["--blume-border", b.border[mode]],
  ["--blume-accent", b.accent[mode]],
  ["--blume-accent-foreground", b.onAccent[mode]],
  ["--blume-action", b.accent[mode]],
  ["--blume-code-background", b.popover[mode]],
];

/**
 * Renders Blume's theme.css. Blume reads `:root` as light and
 * `:root[data-theme="dark"]` as dark (with theme.mode "system", the inline
 * bootstrap script sets data-theme from the OS setting).
 */
export function renderThemeCss(b: BrandTokens): string {
  const block = (selector: string, mode: keyof ModePair): string =>
    `${selector} {\n${blumeTokenMap(b, mode)
      .map(([name, value]) => `  ${name}: ${value.toLowerCase()};`)
      .join("\n")}\n}\n`;
  return `/*\n * ${GENERATED_BANNER.split("\n").join("\n * ")}\n *\n * Blume design tokens ← Astryx maruhi theme (ADR-0013: brand values live in apps/web/theme/).\n * Fonts are set from blume.config.ts (theme.fonts → Astro Fonts API), not here.\n */\n${block(":root", "light")}\n${block(':root[data-theme="dark"]', "dark")}\n:root {\n  --blume-radius: ${b.radius};\n}\n`;
}

const pair = (p: ModePair): string => `{ light: "${p.light}", dark: "${p.dark}" }`;

/** Renders the constants module imported by blume.config.ts / e2e (on-accent and surface are used only on the theme.css side). */
export function renderTokensTs(b: BrandTokens): string {
  return `// ${GENERATED_BANNER.split("\n").join("\n// ")}
// Brand tokens extracted from the Astryx maruhi theme (docs/notes/web-design-pass.md §3 / §4).

/** Vermilion accent — the red of the ㊙ mark (light) and its dark-mode tone. */
export const accent = ${pair(b.accent)} as const;

/** Page background (warm neutral body). */
export const background = ${pair(b.background)} as const;

/** Body text. */
export const foreground = ${pair(b.foreground)} as const;

/** Secondary text. */
export const mutedForeground = ${pair(b.mutedForeground)} as const;

/** Borders and dividers. */
export const border = ${pair(b.border)} as const;
`;
}

/**
 * Dark-mode logo: replaces the fill of apps/web/public/logo.svg (fill =
 * the light accent) with the dark accent. If no replacement target is
 * found, the premise (the SVG's red = light accent — DP1 ruling A) is
 * broken, so it fails.
 */
export function renderLogoDark(logoSvg: string, b: BrandTokens): string {
  const light = b.accent.light.toLowerCase();
  const re = new RegExp(`fill="${light}"`, "gi");
  if (!re.test(logoSvg)) {
    throw new Error(
      `apps/web/public/logo.svg: no fill="${b.accent.light}" found (DP1 ruling A: the SVG's red = light accent)`,
    );
  }
  const note = `<!-- @generated: apps/web/public/logo.svg with the fill swapped to the dark-mode accent (${b.accent.dark}) — see apps/site/scripts/build-theme.ts -->\n`;
  const swapped = logoSvg.replace(re, `fill="${b.accent.dark}"`);
  // Insert the provenance right after the original leading comment (before <svg)
  const at = swapped.indexOf("<svg");
  return `${swapped.slice(0, at)}${note}${swapped.slice(at)}`;
}

/** The whole set of artifacts (path → content). Binary assets are copied as Buffer. */
export function renderAll(repoRoot: string): ReadonlyMap<string, string | Buffer> {
  const css = readFileSync(join(repoRoot, paths.webThemeCss), "utf8");
  const brand = extractBrand(css);
  const logo = readFileSync(join(repoRoot, paths.webLogo), "utf8");
  const out = new Map<string, string | Buffer>();
  out.set(paths.themeCss, renderThemeCss(brand));
  out.set(paths.tokensTs, renderTokensTs(brand));
  out.set(paths.logoDark, renderLogoDark(logo, brand));
  for (const asset of copiedAssets) {
    out.set(`apps/site/public/${asset}`, readFileSync(join(repoRoot, "apps/web/public", asset)));
  }
  return out;
}
