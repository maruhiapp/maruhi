export function navigateTo(path: string): void {
  const nav = (window as { navigation?: { navigate: (url: string) => void } }).navigation;
  if (nav) {
    nav.navigate(path);
  } else {
    window.location.assign(path);
  }
}
