package ltechnologies.onionphone.pgpshield.ui.qr

/**
 * Compose UI and view model for exchanging OpenPGP public keys via QR codes
 * (encode to bitmap or scan from an image).
 */

import android.graphics.Bitmap
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import dagger.hilt.android.lifecycle.HiltViewModel
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.ui.keys.KeyListViewModel
import ltechnologies.onionphone.pgpshield.util.ArmoredKeyDetector
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * [ViewModel] exposing the key list and public-key export for QR encoding.
 */
@HiltViewModel
class QrKeyViewModel @Inject constructor(
    private val keyRepository: KeyRepository,
) : ViewModel() {
    /** Observable list of all keys in the repository. */
    val keys = keyRepository.observeKeys()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** Returns the ASCII-armored public key for [keyId], or null if missing. */
    suspend fun loadPublicArmored(keyId: Long): String? =
        keyRepository.getArmoredPublic(keyId)?.let { String(it, Charsets.UTF_8) }
}

/**
 * QR key exchange screen.
 *
 * Lets the user pick a key, render its armored public block as a QR bitmap, or
 * scan a QR image to import a public key via [listViewModel].
 *
 * @param onBack invoked to navigate back.
 * @param listViewModel view model for key import after a scan.
 * @param qrViewModel view model for key list and export reads.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrKeyScreen(
    onBack: () -> Unit,
    listViewModel: KeyListViewModel = hiltViewModel(),
    qrViewModel: QrKeyViewModel = hiltViewModel(),
) {
    val keys by qrViewModel.keys.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var selectedKeyId by remember { mutableStateOf<Long?>(keys.firstOrNull()?.masterKeyId) }
    var qrBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var keyMenuExpanded by remember { mutableStateOf(false) }

    val pickQrImage = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val text = withContext(Dispatchers.Default) { decodeQrFromUri(context, uri) }
            if (text == null) {
                status = "No QR code found in image"
                return@launch
            }
            if (ArmoredKeyDetector.isSecretBlock(text) == null) {
                status = "QR payload is not an armored OpenPGP key"
                return@launch
            }
            val secret = ArmoredKeyDetector.isSecretBlock(text) == true
            listViewModel.importArmored(text, secret) {
                status = "Key imported from QR"
            }
        }
    }

    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.qr_keys_title),
            showBack = true,
            onBack = onBack,
        ) { padding ->
            AdaptiveScreenColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                Text(
                    stringResource(R.string.qr_keys_desc),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (keys.isEmpty()) {
                    Text(stringResource(R.string.qr_no_keys), modifier = Modifier.padding(top = 8.dp))
                    return@AdaptiveScreenColumn
                }
                ExposedDropdownMenuBox(
                    expanded = keyMenuExpanded,
                    onExpandedChange = { keyMenuExpanded = it },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                ) {
                    val selected = keys.find { it.masterKeyId == selectedKeyId }
                    OutlinedTextField(
                        value = selected?.primaryUserId ?: stringResource(R.string.common_select_key),
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.qr_public_key)) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(keyMenuExpanded) },
                        modifier = Modifier.menuAnchor().fillMaxWidth(),
                    )
                    ExposedDropdownMenu(expanded = keyMenuExpanded, onDismissRequest = { keyMenuExpanded = false }) {
                        keys.forEach { key ->
                            DropdownMenuItem(
                                text = { Text("${key.primaryUserId} (${formatKeyId(key.masterKeyId)})") },
                                onClick = {
                                    selectedKeyId = key.masterKeyId
                                    keyMenuExpanded = false
                                },
                            )
                        }
                    }
                }
                Button(
                    onClick = {
                        scope.launch {
                            val id = selectedKeyId ?: return@launch
                            val armored = qrViewModel.loadPublicArmored(id)
                            if (armored == null) {
                                status = "Could not load public key"
                                return@launch
                            }
                            qrBitmap = withContext(Dispatchers.Default) { encodeQr(armored) }
                            status = "QR generated"
                        }
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                ) { Text(stringResource(R.string.qr_show_public_key)) }
                qrBitmap?.let { bmp ->
                    Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = stringResource(R.string.qr_public_key_content_desc),
                        modifier = Modifier
                            .padding(top = 16.dp)
                            .size(280.dp),
                    )
                }
                Button(
                    onClick = { pickQrImage.launch(arrayOf("image/*")) },
                    modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                ) { Text(stringResource(R.string.qr_scan_from_image)) }
                status?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
                }
            }
        }
    }
}

private fun encodeQr(text: String): Bitmap {
    // ponytail: chunk if key exceeds QR capacity; upgrade path is multi-QR sequence
    val payload = text.take(2000)
    val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 512, 512)
    val w = matrix.width
    val h = matrix.height
    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.RGB_565)
    for (x in 0 until w) {
        for (y in 0 until h) {
            bmp.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
    }
    return bmp
}

private const val QR_DECODE_MAX_DIMENSION = 1024

private fun decodeQrFromUri(context: android.content.Context, uri: Uri): String? {
    val resolver = context.contentResolver
    val bounds = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
    resolver.openInputStream(uri)?.use { stream ->
        android.graphics.BitmapFactory.decodeStream(stream, null, bounds)
    } ?: return null
    val sampleSize = calculateInSampleSize(bounds, QR_DECODE_MAX_DIMENSION, QR_DECODE_MAX_DIMENSION)
    val bmp = resolver.openInputStream(uri)?.use { stream ->
        android.graphics.BitmapFactory.decodeStream(
            stream,
            null,
            android.graphics.BitmapFactory.Options().apply { inSampleSize = sampleSize },
        )
    } ?: return null
    return try {
        val width = bmp.width
        val height = bmp.height
        val pixels = IntArray(width * height)
        bmp.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = RGBLuminanceSource(width, height, pixels)
        val binary = BinaryBitmap(HybridBinarizer(source))
        runCatching {
            MultiFormatReader().decode(binary).text
        }.getOrNull()
    } finally {
        bmp.recycle()
    }
}

private fun calculateInSampleSize(
    options: android.graphics.BitmapFactory.Options,
    reqWidth: Int,
    reqHeight: Int,
): Int {
    val (height, width) = options.outHeight to options.outWidth
    var inSampleSize = 1
    if (height > reqHeight || width > reqWidth) {
        var halfHeight = height / 2
        var halfWidth = width / 2
        while (halfHeight / inSampleSize >= reqHeight && halfWidth / inSampleSize >= reqWidth) {
            inSampleSize *= 2
        }
    }
    return inSampleSize
}
