"use client";

// The per-row state machine for revocation (DELETE) (ruling CO —
// docs/notes/session-45.md). Shared between S8 (invites) and S9
// (tokens).
//
// - Arming is always a single row (arming another row or Cancel disarms)
// - Confirming issues the DELETE (the api layer always attaches the
//   CSRF header — AUTH_SPEC §11-4)
// - The list is re-fetched after completion regardless of outcome (no
//   optimistic update renders client-guessed state — same side as
//   display discipline §4. A 410 / 404 is also a sign the state moved
//   elsewhere)
// - State survives across the list resource's re-fetch (the caller
//   holds this hook outside the list — at screen level): a failure
//   display must not disappear on an unmount mid-refetch
// - On success, the wording the caller passed at confirm time (which
//   includes the target's name — decided at confirm time because the
//   target may be absent from the list after re-fetch) is kept in
//   `succeeded` and announced via a role="status" Banner below the list.
//   It clears on the next arming
import { useCallback, useRef, useState } from "react";

import { apiDelete, type ApiFailure } from "./api.ts";

/** The screen state of a revocation (armed, in-flight, latest failure, latest success wording). */
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

/** The state and operations of a two-step revocation (revokePath is an id → DELETE path builder). */
export function useRevocation(
  revokePath: (id: string) => string,
  reload: () => void,
): {
  revocation: RevocationState;
  arm: (id: string | undefined) => void;
  confirm: (id: string, successMessage: string) => void;
} {
  const [revocation, setRevocation] = useState<RevocationState>(IDLE);
  // In-flight guard: while a DELETE is running, arm / confirm are not
  // accepted — this blocks the race where a late-arriving completion
  // overwrites another row's armed state and the failure looks like it
  // belongs to a different revocation. The UI side also disables other
  // rows' Revoke by watching pendingId (RevokeControl's isLocked) — the
  // guard is a second layer so we produce buttons that do not work
  // rather than invisible buttons
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
