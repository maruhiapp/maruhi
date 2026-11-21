import { mount, onShortcut, syncShortcutHints } from "@cloudflare/nimbus-docs/client";

function warm(href: string) {
  if (document.head.querySelector(`link[rel="prefetch"][href="${CSS.escape(href)}"]`)) return;
  const link = document.createElement("link");
  link.rel = "prefetch";
  link.href = href;
  document.head.append(link);
}

function initPagination(root: HTMLElement): () => void {
  const highlight = root.querySelector<HTMLElement>("[data-slot='pagination-highlight']");
  const items = Array.from(root.querySelectorAll<HTMLAnchorElement>("[data-nb-pagination-item]"));
  const cleanups: Array<() => void> = [];
  let current: HTMLElement | null = null;

  const show = (item: HTMLElement) => {
    current = item;
    if (!highlight) return;
    highlight.style.left = `${item.offsetLeft}px`;
    highlight.style.width = `${item.offsetWidth}px`;
    highlight.dataset.state = "visible";
  };
  const hide = () => {
    current = null;
    if (highlight) highlight.dataset.state = "hidden";
  };

  for (const item of items) {
    const onShow = () => {
      show(item);
      const title = item.querySelector<HTMLElement>("[data-slot='pagination-title']");
      if (title) {
        const cut =
          title.scrollWidth > title.clientWidth || title.scrollHeight > title.clientHeight;
        if (cut) item.title = title.textContent?.trim() ?? "";
        else item.removeAttribute("title");
      }
    };
    item.addEventListener("pointerenter", onShow);
    item.addEventListener("focus", onShow);
    cleanups.push(() => {
      item.removeEventListener("pointerenter", onShow);
      item.removeEventListener("focus", onShow);
    });
  }
  const onLeave = () => hide();
  const onFocusOut = (e: FocusEvent) => {
    if (!root.contains(e.relatedTarget as Node)) hide();
  };
  root.addEventListener("pointerleave", onLeave);
  root.addEventListener("focusout", onFocusOut);

  const resize = new ResizeObserver(() => {
    if (current) show(current);
  });
  resize.observe(root);

  const press = (item: HTMLAnchorElement) => {
    warm(item.href);
    item.querySelector("[data-slot='pagination-key']")?.setAttribute("data-down", "");
    show(item);
    window.setTimeout(() => item.click(), 140);
  };
  const keyed = items.filter((item) => item.dataset.nbShortcutFor);
  if (root.dataset.keys === "false") {
    for (const item of keyed) {
      item.removeAttribute("data-nb-shortcut-for");
      item.removeAttribute("aria-keyshortcuts");
    }
  } else {
    root.setAttribute("data-nb-shortcut-scope", "");
    const pageWide = root === document.querySelector("[data-nb-page-nav]");
    for (const item of keyed) {
      const go = (e: KeyboardEvent) => {
        e.preventDefault();
        press(item);
      };
      cleanups.push(onShortcut(item.dataset.nbShortcutFor!, go, { within: root }));
      if (pageWide) cleanups.push(onShortcut(item.dataset.nbShortcutFor!, go));
    }
    syncShortcutHints(root);
  }

  return () => {
    cleanups.forEach((fn) => fn());
    root.removeEventListener("pointerleave", onLeave);
    root.removeEventListener("focusout", onFocusOut);
    resize.disconnect();
  };
}

mount("[data-nb-pagination]", initPagination);
