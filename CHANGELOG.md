# Changelog

## Unreleased

- Fix ECDSA P-384/P-521 public-key export interoperability with GnuPG, Kleopatra, and OpenKeychain by signing certifications with SHA-384/SHA-512 (SHA-256 is rejected for those curves). Existing P-384/P-521 keys must be regenerated to become importable.

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
