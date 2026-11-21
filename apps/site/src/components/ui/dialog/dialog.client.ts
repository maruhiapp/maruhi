import { lockScroll, mount, unlockScroll } from "@cloudflare/nimbus-docs/client";

mount("[data-dialog]", (root) => {
  if (!(root instanceof HTMLDialogElement)) return () => {};
  const dialog = root;

  const sync = () => (dialog.open ? lockScroll() : unlockScroll());
  const observer = new MutationObserver(sync);
  observer.observe(dialog, { attributes: true, attributeFilter: ["open"] });

  let pressedOn: EventTarget | null = null;
  const onPress = (e: PointerEvent) => {
    pressedOn = e.target;
  };
  const onBackdrop = (e: MouseEvent) => {
    if (e.target === dialog && pressedOn === dialog) dialog.close();
    pressedOn = null;
  };
  dialog.addEventListener("pointerdown", onPress);
  dialog.addEventListener("click", onBackdrop);

  return () => {
    observer.disconnect();
    dialog.removeEventListener("pointerdown", onPress);
    dialog.removeEventListener("click", onBackdrop);
    if (dialog.open) unlockScroll();
  };
});
