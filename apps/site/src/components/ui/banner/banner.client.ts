import { mount } from "@cloudflare/nimbus-docs/client";

const KEY_PREFIX = "nb-banner-dismissed-";

function isDismissed(key: string): boolean {
  try {
    const stored = localStorage.getItem(key);
    if (!stored) return false;
    const expiry = Number(stored);
    if (expiry === 0 || expiry > Date.now()) return true;
    localStorage.removeItem(key);
  } catch {}
  return false;
}

function initBanner(banner: HTMLElement): () => void {
  const id = banner.dataset.nbBannerDismiss;
  if (!id) return () => {};

  const key = banner.dataset.nbBannerKey ?? `${KEY_PREFIX}${id}`;

  if (isDismissed(key)) {
    banner.remove();
    return () => {};
  }

  const btn = banner.querySelector<HTMLButtonElement>("[data-nb-banner-close]");
  if (!btn) return () => {};

  function handleClick() {
    const days = Number(banner.dataset.nbBannerDays) || 0;
    const value = days > 0 ? String(Date.now() + days * 86400000) : "0";
    try {
      localStorage.setItem(key, value);
    } catch {}
    banner.remove();
  }

  btn.addEventListener("click", handleClick);

  return () => btn.removeEventListener("click", handleClick);
}

mount("[data-nb-banner-dismiss]", initBanner);
