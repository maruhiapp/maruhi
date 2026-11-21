import { defineTheme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral";

const VERMILION_LIGHT = "#C1330B";
const VERMILION_DARK = "#FF693C";
const ON_VERMILION_LIGHT = "#FFFFFF";
const ON_VERMILION_DARK = "#241915";

const SYSTEM_SANS = {
  family: "-apple-system",
  fallbacks: 'BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
};

export const maruhiTheme = defineTheme({
  name: "maruhi",
  extends: neutralTheme,
  typography: { body: SYSTEM_SANS },
  color: {
    accent: [VERMILION_LIGHT, VERMILION_DARK],
    neutralStyle: "warm",
  },
  components: {
    text: {
      "type:code": { overflowWrap: "anywhere", minWidth: "0" },
    },
    code: {
      base: { fontSize: "inherit" },
    },
  },
  tokens: {
    "--color-accent": [VERMILION_LIGHT, VERMILION_DARK],
    "--color-on-accent": [ON_VERMILION_LIGHT, ON_VERMILION_DARK],
  },
});
