# Privacy-safe release logging — strip debug-only profiling / NDJSON ingest.
# Release builds keep only PrivacyLog boolean flags (OpPrivacy tag).

-assumenosideeffects class ltechnologies.onionphone.pgpshield.util.DebugAgentLog {
    public void log(...);
}

# Timber verbose levels in pgp-shield release (LogRedactor handles ERROR only).
-assumenosideeffects class timber.log.Timber {
    public static void v(...);
    public static void d(...);
    public static void i(...);
    public static void w(...);
}

-keep class ltechnologies.onionphone.**.PrivacyLog { *; }
