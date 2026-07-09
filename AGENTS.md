# AGENTS.md

## Cursor Cloud specific instructions

PGP Shield is an Android (Kotlin) OpenPGP app; multi-module Gradle project
(`app` + `pgp-engine` + `data` + `encoding` + `api-client*`). Standard commands and
architecture live in `README.md`, `docs/`, and `.github/workflows/ci.yml`.

The Cloud VM is already provisioned: OpenJDK 17 and 21, the Android SDK at
`$HOME/android-sdk` (env vars exported in `~/.bashrc`), and a generated
`local.properties` (gitignored) with `sdk.dir`.

- **JDK: use 21.** CI builds PGP Shield with Temurin 21. Run Gradle with
  `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64`.
- **Build (debug APK):** `./gradlew :app:assembleDebug -Ponionphone.devAbi=arm64-v8a --no-daemon`
  → `app/build/outputs/apk/debug/app-debug.apk`.
- **Unit tests:** see the slow-test caveat below before running the full `test` task.
- **Lint:** `./gradlew :app:lintDebug --no-daemon`.

Non-obvious caveats:
- **The full `./gradlew test` is a trap in this environment.**
  `pgp-engine`'s `PgpRoundTripTest.dsaElgamal_roundTrip` generates **3072-bit DSA +
  ElGamal safe primes** via BouncyCastle (`PgpAlgorithmPolicy.defaultElGamalBits = 3072`).
  Safe-prime generation is single-threaded and **has no JUnit timeout**, so it can run
  for 30+ minutes (observed >55 min) and appear hung at ~98% CPU. For fast iteration run
  `./gradlew test -x :pgp-engine:testDebugUnitTest --no-daemon` (all other modules) plus
  targeted crypto tests such as
  `./gradlew :pgp-engine:testDebugUnitTest --tests "*PgpControlFlowTest"` or
  `--tests "*PgpRoundTripTest.generateEncryptDecrypt_roundTrip"` (RSA/ECC keygen is fast).
- `compileSdk`/`targetSdk` are **37**; installed SDK platforms are `android-37.0` /
  `android-37.1` (no plain `platforms;android-37`). AGP 9.1.1 handles this — do not change it.
- Headless VM with **no `/dev/kvm`** → no Android emulator. Verify the engine by running
  the encrypt→decrypt round-trip tests (core functionality) and inspect the APK with
  `$ANDROID_SDK_ROOT/build-tools/37.0.0/aapt dump badging <apk>`.
