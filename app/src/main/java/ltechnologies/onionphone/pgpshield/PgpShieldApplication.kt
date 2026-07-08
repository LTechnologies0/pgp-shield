package ltechnologies.onionphone.pgpshield

/**
 * Application entry point and process-wide bootstrap for PGP Shield.
 *
 * This file wires up the Hilt dependency graph, logging, crash handling, the
 * BouncyCastle security provider and the lifecycle hooks that keep decrypted
 * passphrase material from lingering in memory.
 */

import android.app.Application
import android.content.BroadcastReceiver
import android.content.ComponentCallbacks2
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import dagger.hilt.android.HiltAndroidApp
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.PaddingTemplateDao
import ltechnologies.onionphone.pgpshield.data.db.PaddingTemplateEntity
import ltechnologies.onionphone.pgpshield.engine.BouncyCastleProviderHolder
import ltechnologies.onionphone.pgpshield.overlay.OverlayPassphraseSession
import ltechnologies.onionphone.pgpshield.util.LogRedactor
import ltechnologies.onionphone.pgpshield.util.PrivacyLog
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Root [Application] annotated with [HiltAndroidApp] to generate the Hilt
 * dependency container.
 *
 * Responsibilities performed on process start:
 * - Configures [Timber] logging (verbose in debug, redacted in release) and
 *   [android.os.StrictMode] policies during development.
 * - Installs a global uncaught-exception handler that wipes cached passphrases
 *   before delegating to the platform default handler.
 * - Registers the BouncyCastle security provider and seeds default database
 *   records on a background [appScope] coroutine.
 * - Listens for `ACTION_SCREEN_OFF` and low-memory callbacks to proactively
 *   clear the in-memory [OverlayPassphraseSession] cache.
 */
@HiltAndroidApp
class PgpShieldApplication : Application() {
    @Inject lateinit var paddingTemplateDao: PaddingTemplateDao
    @Inject lateinit var settingsRepository: SettingsRepository
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var overlayPassphraseSession: OverlayPassphraseSession

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != Intent.ACTION_SCREEN_OFF) return
            val pendingResult = goAsync()
            Thread {
                try {
                    overlayPassphraseSession.clearAll()
                } finally {
                    pendingResult.finish()
                }
            }.start()
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            android.os.StrictMode.setThreadPolicy(
                android.os.StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build(),
            )
            android.os.StrictMode.setVmPolicy(
                android.os.StrictMode.VmPolicy.Builder().detectAll().penaltyLog().build(),
            )
            Timber.plant(Timber.DebugTree())
        } else {
            Timber.plant(LogRedactor.createReleaseTree())
        }
        installCrashHandler()
        BouncyCastleProviderHolder.ensureRegistered()
        appScope.launch {
            paddingTemplateDao.insert(
                PaddingTemplateEntity(
                    templateId = "default",
                    title = "Draft",
                    content = "Notes:\n",
                ),
            )
            val purged = keyRepository.purgeMissingBlobKeys()
            if (purged > 0) {
                Timber.w("Purged %d key(s) with missing encrypted blobs", purged)
            }
            checkBackupReminder()
        }
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(screenOffReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(screenOffReceiver, filter)
        }
    }

    private suspend fun checkBackupReminder() {
        val settings = settingsRepository.current()
        if (!settings.backupReminderEnabled) return
        val keys = keyRepository.observeKeys().first()
        if (keys.isEmpty()) return
        val lastExport = settingsRepository.lastExportMillis()
        val staleMs = 30L * 24 * 60 * 60 * 1000
        if (lastExport == 0L || System.currentTimeMillis() - lastExport > staleMs) {
            Timber.w("Backup reminder: export your secret keys — last export %s", if (lastExport == 0L) "never" else "over 30 days ago")
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_BACKGROUND) {
            overlayPassphraseSession.clearAll()
        }
    }

    override fun onTerminate() {
        unregisterReceiver(screenOffReceiver)
        super.onTerminate()
    }

    private fun installCrashHandler() {
        val default = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            PrivacyLog.flag("crash_handler", ok = false)
            if (BuildConfig.DEBUG) {
                Timber.e(throwable, "Uncaught on %s", thread.name)
            }
            runCatching { overlayPassphraseSession.clearAll() }
            default?.uncaughtException(thread, throwable)
        }
    }
}
