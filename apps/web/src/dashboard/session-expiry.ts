// The notification path for session expiry.
//
// The shell (DashboardLayout) mounts once across navigations and calls
// `GET /auth/me` only once. So when a screen's fetch returns 401
// mid-session, the shell cannot find its way back from "signed in" on
// its own. When the screen-side FailureNotice renders a 401 it notifies
// the parent through here, and the shell switches to the sign-in screen
// on the spot (no reload needed).
// It only reacts to the first 401 — no per-navigation /auth/me
// re-check (one round trip) is added.
import { createContext, useContext, useEffect } from "react";

/** The "session expired" receiver the parent shell provides. undefined outside the shell. */
export const SessionExpiredContext = createContext<(() => void) | undefined>(undefined);

/** Notifies the parent shell when `expired` (= a screen fetch got a 401). */
export function useReportSessionExpired(expired: boolean): void {
  const report = useContext(SessionExpiredContext);
  useEffect(() => {
    if (expired) report?.();
  }, [expired, report]);
}
