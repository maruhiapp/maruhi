const RESUME_MARKER_KEY = "maruhi-resume-dashboard";

export function markResumeToDashboard(): void {
  try {
    window.sessionStorage.setItem(RESUME_MARKER_KEY, "1");
  } catch {}
}

export function consumeResumeToDashboard(): boolean {
  try {
    const marked = window.sessionStorage.getItem(RESUME_MARKER_KEY) !== null;
    if (marked) window.sessionStorage.removeItem(RESUME_MARKER_KEY);
    return marked;
  } catch {
    return false;
  }
}
