# Security Policy

## Supported Versions

| Version     | Supported |
| ----------- | --------- |
| 1.0.x-alpha | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

1. Use **GitHub Private Vulnerability Reporting** (Security → Advisories → Report a vulnerability) on this repository.
2. Or email the maintainers with:
   - Affected version(s)
   - Steps to reproduce
   - Impact assessment (key material exposure, API bypass, overlay injection, etc.)

We aim to acknowledge reports within **72 hours** and provide a fix or mitigation timeline within **14 days** for confirmed issues.

## Scope

In scope:

- PGP Shield application code in this repository
- Gradle build scripts and GitHub Actions workflows
- Key storage (`EncryptedBlobStore`), passphrase handling, API access control
- Accessibility overlay coordinator and third-party app integration

Out of scope:

- Third-party Android OS bugs
- Compromised devices (root malware, accessibility malware)
- Weak user-chosen passphrases
- Attacks requiring physical device access with unlocked screen

## Security Design

- **Encrypted at rest**: OpenPGP secret key material stored in AES-GCM `EncryptedFile` blobs; Room holds metadata only.
- **No hardcoded secrets**: signing keys, SDK paths, and debug ingest URLs are never committed (`keystore.properties`, `local.properties` are gitignored).
- **Release hardening**: R8 minification, resource shrinking, privacy-safe logging via `PrivacyLog` and `LogRedactor`.
- **Backup disabled**: `android:allowBackup="false"` in the manifest.
- **API protection**: `PgpShieldService` is signature-protected; callers must be granted access by the user.
- **CI signing**: release keystores are provided via GitHub Actions encrypted secrets only (`RELEASE_KEYSTORE_*`).
- **Screen security**: optional `FLAG_SECURE`, sensitive clipboard auto-wipe, passphrase cleared on screen-off.

## Recommended Repository Settings

Enable these free GitHub security features under **Settings → Code security**:

- Dependabot alerts
- Dependabot security updates
- Secret scanning + push protection
- Code scanning (CodeQL workflow included in `.github/workflows/ci.yml`)
- Private vulnerability reporting

## CI Secrets (maintainers only)

| Secret | Description |
|--------|-------------|
| `RELEASE_KEYSTORE_BASE64` | Base64-encoded `.keystore` or `.jks` file |
| `RELEASE_KEYSTORE_PASSWORD` | Keystore password |
| `RELEASE_KEY_ALIAS` | Key alias (default: `pgp-shield`) |
| `RELEASE_KEY_PASSWORD` | Key password (optional if same as keystore) |

Generate a keystore locally with `scripts/generate-release-keystore.sh` — never commit the output.
