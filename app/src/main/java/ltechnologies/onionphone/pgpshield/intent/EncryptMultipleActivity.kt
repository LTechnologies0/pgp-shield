package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for encrypting multiple selected files at once.
 */

import android.content.Intent
import android.net.Uri
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
import androidx.core.content.FileProvider
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
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
 * Handles incoming multi-file encrypt intents (`ACTION_SEND_MULTIPLE` etc.).
 *
 * Encrypts each selected URI individually to the resolved recipient key. In
 * integration mode results are written back per source path; otherwise the
 * encrypted files are offered via a multi-share chooser.
 */
@AndroidEntryPoint
class EncryptMultipleActivity : ComponentActivity() {
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the multi-encrypt UI and, in integration mode, auto-runs encryption. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val integrationMode = IntentResultWriter.isCallerIntegration(intent)
        val count = intent.clipData?.itemCount
            ?: intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.size
            ?: intent.data?.let { 1 }
            ?: 0
        setContent {
            PgpShieldTheme {
                var status by remember { mutableStateOf(getString(R.string.intent_status_ready_encrypt_many_fmt, count)) }
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
                                encryptAndDeliver()
                            } catch (e: Exception) {
                                error = e.message
                                status = getString(R.string.intent_status_encryption_failed)
                                if (integrationMode) {
                                    IntentResultWriter.finishCancel(this@EncryptMultipleActivity)
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
                    title = stringResource(R.string.intent_encrypt_multiple_title),
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
                                Text(stringResource(R.string.intent_encrypt_and_share))
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

    private suspend fun encryptAndDeliver() {
        val uris = readAllUris()
        if (uris.isEmpty()) error("No files in intent")
        val sourcePaths = intent.getStringArrayListExtra(PgpIntentActions.EXTRA_SOURCE_PATHS)
        val public = IntentIoHelper.loadEncryptPublicKey(keyRepository, settingsRepository)
        val integrationMode = !sourcePaths.isNullOrEmpty()

        if (integrationMode) {
            var encryptedCount = 0
            for ((index, source) in uris.withIndex()) {
                val bytes = withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(source)?.use { PgpIo.readLimited(it) }
                } ?: continue
                val path = sourcePaths.getOrNull(index) ?: continue
                val encrypted = withContext(Dispatchers.Default) {
                    cryptoOperations.encrypt(bytes, listOf(public), asciiArmor = false)
                }
                IntentResultWriter.writeEncryptedForCaller(intent, path, encrypted.ciphertext)
                encryptedCount++
            }
            if (encryptedCount == 0) error("Could not encrypt any files")
            IntentResultWriter.finishOk(this)
            return
        }

        val outUris = ArrayList<Uri>()
        val dir = File(cacheDir, "shared").also { it.mkdirs() }
        for ((index, source) in uris.withIndex()) {
            val bytes = withContext(Dispatchers.IO) {
                contentResolver.openInputStream(source)?.use { PgpIo.readLimited(it) }
            } ?: continue
            val name = source.lastPathSegment ?: "file$index.bin"
            val encrypted = withContext(Dispatchers.Default) {
                cryptoOperations.encrypt(bytes, listOf(public), asciiArmor = false)
            }
            val out = File(dir, "$name.gpg")
            withContext(Dispatchers.IO) {
                out.writeBytes(encrypted.ciphertext)
            }
            outUris.add(
                FileProvider.getUriForFile(
                    this@EncryptMultipleActivity,
                    "$packageName.fileprovider",
                    out,
                ),
            )
        }
        if (outUris.isEmpty()) error("Could not encrypt any files")
        shareEncryptedFiles(outUris)
    }

    private fun readAllUris(): List<Uri> {
        intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.let { return it }
        val clip = intent.clipData
        if (clip != null) {
            return (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
        }
        intent.data?.let { return listOf(it) }
        return emptyList()
    }

    private fun shareEncryptedFiles(uris: List<Uri>) {
        val send = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "application/octet-stream"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(send, getString(R.string.intent_share_encrypted_files)))
    }
}
