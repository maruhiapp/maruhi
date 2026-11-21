import {
  mount,
  SHORTCUTS_CHANGE,
  setSingleKeyShortcutsEnabled,
  singleKeyShortcutsEnabled,
  syncShortcutHints,
} from "@cloudflare/nimbus-docs/client";

mount("[data-nb-shortcuts-toggle]", (button) => {
  const sync = () => button.setAttribute("aria-checked", String(singleKeyShortcutsEnabled()));
  const change = () => setSingleKeyShortcutsEnabled(button.getAttribute("aria-checked") === "true");
  sync();
  syncShortcutHints();
  button.addEventListener("change", change);
  document.addEventListener(SHORTCUTS_CHANGE, sync);
  return () => {
    button.removeEventListener("change", change);
    document.removeEventListener(SHORTCUTS_CHANGE, sync);
  };
});
