"use client";

import { useCallback, useRef, useState } from "react";

import { apiDelete, type ApiFailure } from "./api.ts";

export interface RevocationState {
  readonly armedId: string | undefined;
  readonly pendingId: string | undefined;
  readonly failure: ApiFailure | undefined;
  readonly succeeded: string | undefined;
}

const IDLE: RevocationState = {
  armedId: undefined,
  pendingId: undefined,
  failure: undefined,
  succeeded: undefined,
};

export function useRevocation(
  revokePath: (id: string) => string,
  reload: () => void,
): {
  revocation: RevocationState;
  arm: (id: string | undefined) => void;
  confirm: (id: string, successMessage: string) => void;
} {
  const [revocation, setRevocation] = useState<RevocationState>(IDLE);
  const pendingRef = useRef(false);
  const arm = useCallback((id: string | undefined) => {
    if (pendingRef.current) return;
    setRevocation({ ...IDLE, armedId: id });
  }, []);
  const confirm = useCallback(
    (id: string, successMessage: string) => {
      if (pendingRef.current) return;
      pendingRef.current = true;
      setRevocation({ ...IDLE, armedId: id, pendingId: id });
      void apiDelete(revokePath(id)).then((result) => {
        pendingRef.current = false;
        setRevocation({
          ...IDLE,
          failure: result.kind === "ok" ? undefined : result,
          succeeded: result.kind === "ok" ? successMessage : undefined,
        });
        reload();
      });
    },
    [revokePath, reload],
  );
  return { revocation, arm, confirm };
}
