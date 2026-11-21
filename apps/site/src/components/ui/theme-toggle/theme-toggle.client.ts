import { mount } from "@cloudflare/nimbus-docs/client";

declare global {
  interface Window {
    nbApplyTheme?: (mode?: "light" | "dark") => void;
  }
}

function initThemeToggle(button: HTMLElement): () => void {
  function handleClick() {
    const mode = document.documentElement.getAttribute("data-mode") === "dark" ? "light" : "dark";
    try {
      localStorage.setItem("ui-mode", mode);
      window.nbApplyTheme?.();
    } catch {
      window.nbApplyTheme?.(mode);
    }
    syncPressed();
  }

  function syncPressed() {
    button.setAttribute("aria-pressed", String(document.documentElement.dataset.mode === "dark"));
  }

  window.nbApplyTheme?.();
  syncPressed();
  button.addEventListener("click", handleClick);
  return () => button.removeEventListener("click", handleClick);
}

mount("[data-nb-theme-toggle]", initThemeToggle);
