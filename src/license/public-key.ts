/**
 * The Ed25519 public key that verifies self-host licences: base64 of the raw
 * 32-byte key, or null.
 *
 * It ships as null. Choosing and holding the signing key is a separate
 * custody decision; until a real key is compiled in, every supplied licence
 * is `invalid` and the installation runs as core. A real key is a source
 * change and a new image, never a runtime setting.
 */
export const LICENSE_PUBLIC_KEY: string | null = null;
