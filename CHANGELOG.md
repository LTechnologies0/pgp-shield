# Changelog

## Unreleased

## 1.0.4

### Security
- OpenPGP policy harden: Argon2+AEAD secret protect by default; reject weak RSA/DSA/ElGamal/ECC curves; hash allowlist (no MD5/SHA-1 verify); ECDSA digest strength checks; SEIPDv2 no silent MDC downgrade
- Encrypt gates: refuse Never-trusted / revoked / expired / policy-invalid recipients across Crypto UI, Overlay, binder API, OpenPGP API, and share intents
- OpenPGP API: `GET_KEY` / `BACKUP` return public rings only (no secret-blob fallback via `exportKeyRing`)
- Autocrypt: validate + import public rings on ingest; never overwrite an existing secret ring
- WKD / keyserver: HTTPS-only with manual redirect follow (no cleartext downgrade); loopback HTTP limited to unit tests
- Passphrase hygiene: CharArray buffers + wipe in Crypto / SmartCard / CreateKey / KeyDetail; remove DebugAgentLog hot-path telemetry
- ExportedKeyProvider: omit revoked and Never-trusted keys from email_status queries
- Residual: BC unlock still materializes private keys in process RAM during sign/decrypt (needs card/HSM for C13)

### Added
- OpenPGP modernity: SEIPDv2 AEAD + LibrePGP v5 AEAD encrypt, recipient Features awareness, optional native Ed25519/X25519 tags
- S/MIME (CMS) engine + on-disk certificate store; Crypto UI OpenPGP/S-MIME mode with PKCS#12 import
- OpenPGP Card NFC/USB (CCID) smart-card port: PIN, bindKeyIds, divert-to-card decrypt/sign; USB permission flow
- FIDO / security-key preference: strong-biometric second factor after app unlock
- Hardware-managed passphrase vault (StrongBox/TEE auth-bound AES) for new keys
- WKD client, Autocrypt peers screen (refresh/remove/open key), Autocrypt ingest gated by settings
- OpenPGP API: `GET_KEY`, `GET_SIGN_KEY_ID`, `DECRYPT_METADATA`
- Experimental PQC UI (fail-closed until BC OpenPGP PQC lands); interop/SOP-style unit harness
- Material 3 settings: interop profiles, smart-card / Autocrypt navigation

### Fixed
- Key creation `AEADBadTagException`: isolate EncryptedFile Tink keysets per MasterKey alias so StrongBox vault v2 no longer collides with the legacy AndroidX default keyset after upgrade
- Vault write resets a corrupted isolated v2 keyset once and retries (leaves legacy/1.0.3 default keysets intact)
- Vault read tries three keyset slots (isolated v2 → v2-on-default → legacy) so fresh 1.0.3 installs remain readable
- Encrypted settings prefs recover from MasterKey/keyset corruption instead of crashing at startup
- **Critical:** vault migrate no longer renames EncryptedFile ciphertext (AAD = filename); write-in-place + verify + backup restore
- Recover vault blobs damaged by the 1.0.3 rename/AAD migrator
- `getKeyDetail` only purges Room rows on missing blob files — not on AEAD/app-lock failures
- Lint/security: use public `ApplicationInfo.memtagMode` / `gwpAsanMode` (no private reflection); declare `USE_BIOMETRIC`; fix `URLEncoder` NewApi
- Vault write/migrate crash-safe via raw `.rawbak` + verify; `purgeMissingBlobKeys` / `getKeyDetail` restore sidecars before dropping Room rows
- Intent activities + OpenPGP services gated behind app lock; Compose NavHost / translation lint fixes
- USB permission BroadcastReceiver no longer leaks when UsbManager is absent / request fails
- ExportedKeyProvider reports VERIFIED when local trust is full; Room keeps data on 5→6 upgrades
- Smart-card / stub settings strings cleaned (EN/FR/ES)

## 1.0.3

### Security (Pixel StrongBox / Android Keystore)
- Vault MasterKey prefers **StrongBox** (Titan), falls back to TEE Keystore
- Secret blobs migrate transparently to StrongBox-backed alias `_pgp_shield_vault_v2_`
- Settings migrated from cleartext prefs to **EncryptedSharedPreferences** (StrongBox-preferred)
- App lock: Class-3 biometric **or** device PIN/pattern (`BiometricPrompt`) before UI / secret access
- Screen-off / low-memory: wipe overlay passphrases + re-lock app
- Settings shows live hardware security summary (StrongBox / TEE / device lock)
- **ARM MTE** built-in: `android:memtagMode=async` (release) / `sync` (debug); **GWP-ASan always**; TBI pointer tagging on; `extractNativeLibs=false`

## 1.0.2

- Dependency updates (AGP 9.3, Kotlin 2.4, Compose BOM 2026.06, Room/Hilt/BouncyCastle and related libraries).
- CI GitHub Actions bumps.

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
