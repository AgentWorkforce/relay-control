/** Synthetic/local use only until remote verification is separately authorized. */
export function localDatabaseUrl(value: string | undefined): string {
  if (!value) throw new Error("missing_url");
  const url = new URL(value);
  if (!["postgres:", "postgresql:"].includes(url.protocol)
    || !["127.0.0.1", "[::1]"].includes(url.hostname)
    || [...url.searchParams.keys()].some((key) => !["sslmode"].includes(key))) {
    throw new Error("local_database_required");
  }
  return value;
}
