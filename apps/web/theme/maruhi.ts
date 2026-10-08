// The maruhi brand theme (ADR-0013: the only place brand definitions
// live). What ships is static CSS produced by `astryx theme build`
// (the <Theme> runtime injection inserts an inline <style>, which is
// incompatible with style-src 'self').
//
// The color rulings are docs/notes/web-design-pass.md §1-1 / §1-2 and
// §3 "rulings recorded while implementing DP1" (A / B).
// The only raw hex values here are the two "vermilion" values plus the
// two on-accent values; everything else is left to HCT derivation.
//
// Fonts are docs/notes/web-design-pass.md §1-3: the dashboard (the TCB)
// loads no web fonts and uses the system stack.
import { defineTheme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral";

// Vermilion — the red of the ㊙ mark. Same value as the fill of the SVG
// logo (apps/web/public/logo*.svg, favicon).
// HCT: hue 44 / chroma 76 / tone 44. Kept 16° of hue away from danger
// (--color-error = crimson, hue 28).
// The light-side value is the brand's source of truth (single-color
// logos are drawn in this color).
const VERMILION_LIGHT = "#C1330B";
// The dark side is the same hue and chroma raised to tone 63 (6.6:1 on
// the dark body, 4.6:1 on a popover).
// Astryx's seed derivation pins the dark accent to a tone-80 pastel
// (chroma ≈ 31), so meeting "do not lower the chroma" (§1-1) requires
// stating it in tokens (ruling A).
const VERMILION_DARK = "#FF693C";
// on-accent. light is white (5.6:1). dark is warm-neutral tone 10 (=
// the same value as the derived dark surface. 6.0:1) — the seed-
// derived PD[20] (#780000) is 4.1:1 and does not reach AA, so it is
// stated explicitly.
const ON_VERMILION_LIGHT = "#FFFFFF";
const ON_VERMILION_DARK = "#241915";

// The system UI stack (the Astryx default). theme-neutral puts "Figtree"
// in front of it, but nothing loads Figtree on this origin, so every
// browser fell back to this stack anyway; naming it first keeps the
// token honest.
const SYSTEM_SANS = {
  family: "-apple-system",
  fallbacks: 'BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
};

export const maruhiTheme = defineTheme({
  name: "maruhi",
  extends: neutralTheme,
  // heading inherits the family from body (and keeps theme-neutral's
  // h3/h4 weights)
  typography: { body: SYSTEM_SANS },
  color: {
    // seed tuple: align the derived palettes — neutral (warm) hue and
    // everything but --color-on-accent — on the vermilion hue
    accent: [VERMILION_LIGHT, VERMILION_DARK],
    neutralStyle: "warm",
  },
  tokens: {
    // Replace the derived values (light tone 40 / dark tone 80) with the
    // settled vermilion values.
    // --color-accent-muted / --color-text-accent / --color-icon-accent
    // follow automatically, being generated as var(--color-accent)
    // references. Only --color-on-accent is baked from the seed, so it is
    // overridden in step
    "--color-accent": [VERMILION_LIGHT, VERMILION_DARK],
    "--color-on-accent": [ON_VERMILION_LIGHT, ON_VERMILION_DARK],
  },
});

export default maruhiTheme;
