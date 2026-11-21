export function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-6)}`;
}

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

export function isProjectId(value: string): boolean {
  return PROJECT_ID_PATTERN.test(value);
}
