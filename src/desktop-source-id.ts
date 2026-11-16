const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** UUID-era Desktop sources were case-insensitive; imported opaque text sources are not. */
export function normalizeDesktopSourceId(value: string): string {
  return UUID.test(value) ? value.toLowerCase() : value;
}
