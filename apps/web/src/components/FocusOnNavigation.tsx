"use client";

import { useEffect } from "react";

/**
 * Focus management for SPA navigation (audit A-2).
 *
 * On a client-side navigation the browser's default focus reset sends
 * focus to `<body>` — a screen reader user then has to travel the whole
 * page again. Once the navigation's transition finishes, focus moves to
 * the page's h1 (the same place a full page load puts it). `tabIndex = -1`
 * makes the heading programmatically focusable without entering the tab
 * order — the same treatment as the sign-in heading (DashboardShell).
 *
 * - First load is excluded by construction: `currententrychange` only
 *   fires on entry *changes*, and `navigationType` is null for same-entry
 *   state updates — neither fires for the initial document.
 * - With `fallback="static"` (no Navigation API) every navigation is a
 *   full page load, so native focus already does this — the listener is
 *   simply absent.
 * - A page with no h1 is left alone (focus stays wherever the transition
 *   put it).
 */
export function FocusOnNavigation() {
  useEffect(() => {
    const nav = globalThis.navigation;
    if (nav === undefined) {
      return;
    }
    const focusHeading = () => {
      const heading = document.querySelector("h1");
      if (heading instanceof HTMLElement) {
        heading.tabIndex = -1;
        heading.focus();
      }
    };
    const onEntryChange = (event: NavigationCurrentEntryChangeEvent) => {
      if (event.navigationType === null) {
        return;
      }
      // `transition` covers intercepted navigations; the rAF fallback is
      // for traversals that commit without one (focus after the route
      // has rendered either way)
      const transition = nav.transition;
      if (transition === null) {
        const frame = requestAnimationFrame(focusHeading);
        return () => cancelAnimationFrame(frame);
      }
      let cancelled = false;
      void transition.finished.then(() => {
        if (!cancelled) {
          focusHeading();
        }
      });
      return () => {
        cancelled = true;
      };
    };
    const cleanups: (() => void)[] = [];
    const handler = (event: Event) => {
      const cleanup = onEntryChange(event as NavigationCurrentEntryChangeEvent);
      if (cleanup !== undefined) {
        cleanups.push(cleanup);
      }
    };
    nav.addEventListener("currententrychange", handler);
    return () => {
      nav.removeEventListener("currententrychange", handler);
      for (const cleanup of cleanups) {
        cleanup();
      }
    };
  }, []);
  return null;
}
