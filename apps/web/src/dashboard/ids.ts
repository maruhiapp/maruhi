// Display shapes of identifiers (kept outside component files — React
// Doctor's only-export-components).

/** The shortened form of an identifier (first and last 6 digits — for headings, sidebar child items, and scope chips. The full text is shown alongside via HexText etc.). */
export function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-6)}`;
}

// The project-ID format (the genesis entry's SHA-256 hex —
// CRYPTO_SPEC §6.4).
// Same shape as @maruhi/core's isProjectId, but kept as a literal
// because the policy is to not bring executable code into the bundle
// (ruling BR). The check lives here in one place (shared by input,
// route, and sidebar)
const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/** Whether the value is 64 lowercase hex digits (client-side format check before asking the server). */
export function isProjectId(value: string): boolean {
  return PROJECT_ID_PATTERN.test(value);
}
