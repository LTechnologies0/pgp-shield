# Changelog

## 1.0.1

- Fix ECDSA P-384/P-521 public-key export interoperability with GnuPG, Kleopatra, and OpenKeychain by signing certifications with SHA-384/SHA-512 (SHA-256 is rejected for those curves). Existing P-384/P-521 keys must be regenerated to become importable.
- Cleartext signatures now hash CRLF-canonicalized text (RFC 4880), so `gpg --verify` / Kleopatra accept them.
- New keys advertise preferred AES/hash/compression algorithms and MDC Features (avoids GnuPG “not in recipient preferences”).
- Hide Ed448/X448 from Android key generation (GnuPG 2.4 / OpenKeychain skip those algorithm tags on import).
- Autocrypt `keydata` parsed as binary base64 (no broken hand-rolled armor).
- Import intent detects GnuPG `SECRET KEY BLOCK` as well as `PRIVATE KEY BLOCK`.
- QR export fails closed when a public key exceeds QR capacity (no more truncated armor).
- Overlay encoding: correct symmetric magic detection (`OS1`), zero-width re-encode without nesting, padding CRLF tolerance, no silent armor truncation.

## 1.0.0-alpha

- Greenfield MVP: PGP key manager + accessibility overlay encryption
- Modules: `:pgp-engine`, `:data`, `:encoding`, `:api-client`, `:api-client-stub`, `:app`
- RSA-3072 key generation with sign/encrypt subkeys
- Encrypt/decrypt/sign via Bouncy Castle
- Room metadata + EncryptedFile blob storage
- `PgpShieldClient` AIDL service (not OpenPgp v11)
- Compose UI: key list, create, import, crypto, settings, onboarding
- Zero-width and padding encoders
- ACS overlay coordinator with encrypt/decrypt buttons
