package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for encrypting a folder into a single encrypted archive.
 */

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.engine.NamedFile
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Handles incoming encrypt-folder intents.
 *
 * Collects the folder's files (with their relative paths) into a GnuPG tar,
 * encrypts it to the resolved recipient key and writes the archive to the
 * caller-specified output path.
 */
@AndroidEntryPoint
class EncryptFolderActivity : ComponentActivity() {
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the encrypt-folder UI and, in integration mode, auto-runs archiving. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val integrationMode = IntentResultWriter.isCallerIntegration(intent)
        val archiveName = intent.getStringExtra(PgpIntentActions.EXTRA_ARCHIVE_NAME) ?: "archive.gpg"
        val folderLabel = intent.getStringExtra(PgpIntentActions.EXTRA_FOLDER_LABEL) ?: archiveName
        setContent {
            PgpShieldTheme {
                var status by remember {
                    mutableStateOf(getString(R.string.intent_status_ready_encrypt_folder_fmt, folderLabel))
                }
                var error by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                var started by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                val runEncrypt: () -> Unit = {
                    if (!busy) {
                        busy = true
                        error = null
                        scope.launch {
                            try {
                                encryptFolderArchive(archiveName)
                                status = getString(R.string.intent_status_encrypted_folder_fmt, archiveName)
                                IntentResultWriter.finishOk(this@EncryptFolderActivity)
                            } catch (e: Exception) {
                                error = e.message
                                status = getString(R.string.intent_status_encryption_failed)
                                if (integrationMode) {
                                    IntentResultWriter.finishCancel(this@EncryptFolderActivity)
                                }
                            } finally {
                                busy = false
                            }
                        }
                    }
                }

                if (integrationMode) {
                    LaunchedEffect(Unit) {
                        if (!started) {
                            started = true
                            runEncrypt()
                        }
                    }
                }

                IntentFlowScaffold(
                    title = stringResource(R.string.intent_encrypt_folder_title),
                    onBack = { finish() },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        Text(status, modifier = Modifier.padding(top = 8.dp))
                        if (!integrationMode) {
                            Button(
                                onClick = runEncrypt,
                                modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                                enabled = !busy,
                            ) {
                                if (busy) {
                                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                                }
                                Text(stringResource(R.string.intent_encrypt_folder_action))
                            }
                        } else if (busy) {
                            CircularProgressIndicator(modifier = Modifier.padding(top = 16.dp))
                        }
                        error?.let {
                            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        }
    }

    private suspend fun encryptFolderArchive(archiveName: String) {
        val named = readNamedFiles()
        require(named.isNotEmpty()) { "No files to encrypt" }
        val public = IntentIoHelper.loadEncryptPublicKey(keyRepository, settingsRepository)
        val result = withContext(Dispatchers.Default) {
            cryptoOperations.encryptTar(named, listOf(public), asciiArmor = false)
        }
        val outputDir = intent.getStringExtra(PgpIntentActions.EXTRA_OUTPUT_PATH)
            ?: error("Missing output path")
        val outFile = File(outputDir, archiveName)
        withContext(Dispatchers.IO) { outFile.writeBytes(result.ciphertext) }
    }

    private suspend fun readNamedFiles(): List<NamedFile> = withContext(Dispatchers.IO) {
        val uris = readStreamUris()
        val paths = intent.getStringArrayListExtra(PgpIntentActions.EXTRA_RELATIVE_PATHS).orEmpty()
        require(uris.size == paths.size) { "URI / path count mismatch" }
        uris.mapIndexed { index, uri ->
            val bytes = contentResolver.openInputStream(uri)?.use { PgpIo.readLimited(it) }
                ?: error("Could not read ${paths[index]}")
            NamedFile(paths[index], bytes)
        }
    }

    @Suppress("DEPRECATION")
    private fun readStreamUris(): List<Uri> {
        val fromExtra = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
        }
        return fromExtra.orEmpty()
    }
}
