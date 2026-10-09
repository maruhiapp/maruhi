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
 * - Navigations the router did not intercept carry no `transition`
 *   (fragment links, raw `history.pushState`). They are left alone —
 *   pulling focus to the h1 would steal it from an anchor or skip-link
 *   target.
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
      const transition = nav.transition;
      if (transition === null) {
        return;
      }
      // A rejected `finished` means the navigation was superseded or its
      // intercept handler failed — either way focus must not move. The
      // rejection callback is also what keeps the rejection from surfacing
      // as an unhandled promise error (the UA only marks `finished`
      // itself handled, not the promise `then` returns).
      void transition.finished.then(focusHeading, () => {
        // superseded or failed navigation: leave focus where it is
      });
    };
    const handler = (event: Event) => {
      onEntryChange(event as NavigationCurrentEntryChangeEvent);
    };
    nav.addEventListener("currententrychange", handler);
    return () => {
      nav.removeEventListener("currententrychange", handler);
    };
  }, []);
  return null;
}
