import { mount, syncShortcutHints } from "@cloudflare/nimbus-docs/client";

mount("[data-search-trigger]", (btn) => {
  syncShortcutHints(btn);
  return () => {};
});
