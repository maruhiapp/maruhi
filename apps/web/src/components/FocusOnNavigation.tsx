"use client";

import { useEffect } from "react";

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
      void transition.finished.then(focusHeading, () => {});
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
