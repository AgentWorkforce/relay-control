# Bundled common-password list: provenance and licence

`common-passwords.ts` is generated from one file of SecLists:

- Project: SecLists, https://github.com/danielmiessler/SecLists
- File: `Passwords/Common-Credentials/10k-most-common.txt`
- Upstream commit: `dbdbd9ae1135fc53ecb0a9880af94178d0fc6264`
- SHA-256 of the upstream file: `68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce`
- Licence: MIT, Copyright (c) 2018 Daniel Miessler. The full licence text is
  reproduced in the repository `NOTICE` file, which ships in the package.

## Transformation

Each line is trimmed and lowercased, empty lines are dropped and duplicates
removed (10,001 entries). The result is embedded as one newline-separated
string so it compiles into `dist/` with the rest of the server; the policy
loads it once into a `Set`.

## Regenerating

1. Download the file at a pinned commit and check its SHA-256.
2. Lowercase, trim, de-duplicate and join with `\n`.
3. Write it as `export const COMMON_PASSWORDS_TEXT: string = <JSON string>;`
   with the generated-file header, and update the commit and hash above.

## Coverage note

Most entries are shorter than the 12-character minimum, so the length rule
already rejects them. The policy also strips a short trailing run of digits
and symbols before the lookup (`password2024!` is rejected because `password`
is listed). For breach-corpus coverage turn on the HIBP check
(`SELFHOST_PASSWORD_HIBP=on`).
