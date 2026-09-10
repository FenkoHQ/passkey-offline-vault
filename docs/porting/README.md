# Moving credentials in and out

Fenko Vault reads the export files other providers write, and writes files they
can read back. Nothing leaves the device: parsing, key conversion and
de-duplication all happen inside the extension.

- Import: **Options → Danger Zone → Import Data**, or the dedicated import page
  (drag a file onto it).
- Export: **Options → Danger Zone → Export All Data**, pick a format.
- MFA only, in a hurry: paste into **Add Code** in the popup — a single
  `otpauth://` URI, a list of them, or a Google Authenticator export QR.

## What can be imported

### Passkeys

| Source                                        | File          | Notes                                                    |
| --------------------------------------------- | ------------- | -------------------------------------------------------- |
| Apple, Google, 1Password, Bitwarden, Dashlane | `.json` (CXF) | Credential Exchange Format — the FIDO standard for this  |
| Bitwarden                                     | `.json`       | `login.fido2Credentials`; the CSV export has no passkeys |
| Proton Pass                                   | `.json`       | `content.passkeys`                                       |
| Dashlane                                      | `.json`       | `PASSKEY` records                                        |
| Fenko Vault                                   | `.json`       | Plain or password-protected backup                       |
| Anything else                                 | `.csv`        | Fill in the passkey template                             |

Chrome, Edge and Safari cannot export passkeys at all yet. KeePassXC keeps them
inside the `.kdbx` database and leaves them out of its CSV.

### MFA (TOTP / HOTP)

| Source                                                                   | File             | Notes                                                           |
| ------------------------------------------------------------------------ | ---------------- | --------------------------------------------------------------- |
| Google Authenticator                                                     | QR / text        | `otpauth-migration://` — every account in one payload           |
| Aegis                                                                    | `.json`          | Export with encryption off                                      |
| 2FAS                                                                     | `.2fas`, `.json` | Export without a password                                       |
| Ente Auth                                                                | `.txt`           | Plain `otpauth://` list                                         |
| andOTP, FreeOTP+, Raivo, LastPass Authenticator                          | `.json`          |                                                                 |
| Bitwarden, 1Password, Proton Pass, Dashlane, KeePassXC, LastPass, Keeper | `.json`, `.csv`  | The TOTP column of a password export                            |
| Anything else                                                            | `.json`, `.csv`  | Generic `{secret, issuer, account}` shapes, or the MFA template |

A 1Password `.1pux` file is a zip: unzip it and import the `export.data` file
inside. Everything else is imported as downloaded.

Encrypted exports are rejected with a message telling you which setting to turn
off — the extension never asks for another provider's password.

## The CSV templates

Both templates are on the import page, and both import straight back.

`fenko-mfa-template.csv`

```csv
type,issuer,account,secret,algorithm,digits,period,counter
totp,GitHub,you@example.com,JBSWY3DPEHPK3PXP,SHA1,6,30,0
```

- `secret` — the base32 key shown next to the site's QR code. Spaces are fine.
- `type` — `totp` (default) or `hotp`. `counter` matters for HOTP only.
- `algorithm` — `SHA1` (default), `SHA256`, `SHA512`. `digits` — 6 or 8.
- `period` — seconds, 30 unless the site says otherwise.

`fenko-passkey-template.csv`

```csv
rpId,userName,userDisplayName,userHandle,credentialId,privateKey,counter
example.com,you@example.com,Your Name,,,MIGHAgEAMBMGByqGSM49AgEG...,0
```

- `privateKey` — an ES256 (P-256) key as base64 PKCS#8. PEM and JWK also work,
  as does a bare 32-byte scalar.
- `credentialId` and `userHandle` are base64url. Leave `credentialId` blank and
  a random one is minted.
- The public key is derived from the private key; there is no column for it.

Rows starting with `#` are comments, so the templates carry their own notes.

## What can be exported

| Format                           | Contains       | Read by                                       |
| -------------------------------- | -------------- | --------------------------------------------- |
| Fenko Vault backup (JSON)        | Passkeys + MFA | Another Fenko Vault                           |
| Credential Exchange Format (CXF) | Passkeys + MFA | Apple, Google, 1Password, Bitwarden, Dashlane |
| `otpauth://` URI list (TXT)      | MFA            | Aegis, Ente Auth, 2FAS, most authenticators   |
| MFA spreadsheet (CSV)            | MFA            | Spreadsheets, and this vault                  |
| Passkey spreadsheet (CSV)        | Passkeys       | Spreadsheets, and this vault                  |

Every one of these is plaintext, because that is what the receiving app
expects. They contain passkey private keys and MFA seeds: delete the file once
the other app has imported it. The popup's password-protected backup stays the
right choice for anything you intend to keep.

## De-duplication

Re-importing the same file twice adds nothing.

- Passkeys are matched on credential id.
- MFA seeds have no stable id across apps, so they are matched on issuer,
  account and secret.

The import preview says how many entries were already present before anything
is written.

## Adding a format

Parsers live in `src/porting/formats/` and are plain functions: sniff the file
in `detect`, return entries from `parse`. Register the parser in
`IMPORT_PARSERS` (`src/porting/import.ts`) — specific vendor shapes first, the
generic readers last — and add a fixture to `tests/porting/`.
