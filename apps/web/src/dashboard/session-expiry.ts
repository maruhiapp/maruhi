import { createContext, useContext, useEffect } from "react";

export const SessionExpiredContext = createContext<(() => void) | undefined>(undefined);

export function useReportSessionExpired(expired: boolean): void {
  const report = useContext(SessionExpiredContext);
  useEffect(() => {
    if (expired) report?.();
  }, [expired, report]);
}
