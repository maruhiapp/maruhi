// The post-sign-in /dashboard return marker (ruling BU —
// docs/notes/session-43.md §10).
//
// The OAuth callback always redirects to `${origin}/` (the S1 landing)
// (API-side behavior). When the dashboard's Sign in is clicked, a
// one-shot marker is placed in sessionStorage; only when the S1 side
// consumes the marker does it check `/auth/me` once and return to
// /dashboard. An S1 without the marker (a P1 visitor) calls no API at
// all (removing the "extra hop" that had been accepted, without
// resurrecting the "always query /auth/me on S1" rejected in BP round
// 3).
//
// sessionStorage is per-tab and the OAuth round-trip is an in-tab
// navigation, so the marker arrives. In environments where storage is
// unavailable (private mode etc.), the exception is mapped to the typed
// "no marker" and degrades to the current funnel (a static link)
// (classification, not swallowing — same discipline as api.ts).

const RESUME_MARKER_KEY = "maruhi-resume-dashboard";

/** Called when Sign in is clicked: records the intent to return to /dashboard after completion. */
export function markResumeToDashboard(): void {
  try {
    window.sessionStorage.setItem(RESUME_MARKER_KEY, "1");
  } catch {
    // storage unavailable = treated as no marker, degrading to the
    // current funnel (landing on the landing)
  }
}

/** Consumed once on the S1 side: if the marker exists, removes it and returns true. */
export function consumeResumeToDashboard(): boolean {
  try {
    const marked = window.sessionStorage.getItem(RESUME_MARKER_KEY) !== null;
    if (marked) window.sessionStorage.removeItem(RESUME_MARKER_KEY);
    return marked;
  } catch {
    return false;
  }
}
