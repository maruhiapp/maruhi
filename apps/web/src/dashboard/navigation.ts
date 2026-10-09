// Imperative SPA navigation, kept out of the component modules so Fast
// Refresh can treat those as component-only.

/**
 * Imperative navigation inside the SPA (e.g. the direct-ID-input Open).
 * If the Navigation API exists it is an SPA transition; otherwise it
 * degrades to a full page load (same degradation line as the Router's
 * fallback="static").
 */
export function navigateTo(path: string): void {
  const nav = (window as { navigation?: { navigate: (url: string) => void } }).navigation;
  if (nav) {
    nav.navigate(path);
  } else {
    window.location.assign(path);
  }
}
