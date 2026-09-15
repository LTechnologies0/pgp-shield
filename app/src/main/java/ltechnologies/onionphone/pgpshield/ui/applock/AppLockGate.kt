package ltechnologies.onionphone.pgpshield.ui.applock

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.security.AppLockAuthResult
import ltechnologies.onionphone.pgpshield.security.AppLockAuthenticator
import ltechnologies.onionphone.pgpshield.security.AppLockManager
import ltechnologies.onionphone.pgpshield.security.AppLockState
import ltechnologies.onionphone.pgpshield.security.FidoAppLockManager

@Composable
fun AppLockGate(
    appLockManager: AppLockManager,
    authenticator: AppLockAuthenticator,
    fidoAppLockManager: FidoAppLockManager? = null,
    unlockedContent: @Composable () -> Unit,
) {
    val lockState by appLockManager.state.collectAsStateWithLifecycle()
    when (lockState) {
        AppLockState.DEVICE_INSECURE -> DeviceInsecureScreen(
            onSecuritySettings = {
                // After returning from Settings, re-check Keyguard.
            },
            onResumeCheck = { appLockManager.refreshDeviceSecurity() },
        )
        AppLockState.LOCKED -> AppLockScreen(
            authenticator = authenticator,
            fidoRequired = fidoAppLockManager?.requiresSecurityKey() == true,
            fidoLabel = fidoAppLockManager?.current()?.credentialLabel,
            onSuccess = { appLockManager.markUnlocked() },
        )
        AppLockState.UNLOCKED -> unlockedContent()
    }
}

@Composable
private fun AppLockScreen(
    authenticator: AppLockAuthenticator,
    fidoRequired: Boolean = false,
    fidoLabel: String? = null,
    onSuccess: () -> Unit,
) {
    val context = LocalContext.current
    val activity = remember(context) { context.findFragmentActivity() }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var promptShown by remember { mutableStateOf(false) }
    var fidoConfirmed by remember { mutableStateOf(!fidoRequired) }
    val fragmentActivityRequired = stringResource(R.string.app_lock_fragment_activity_required)
    val securityKeyFallback = stringResource(R.string.app_lock_security_key_fallback)

    fun launchPrompt() {
        val act = activity ?: run {
            errorMessage = fragmentActivityRequired
            return
        }
        promptShown = true
        fun afterPrimary(result: AppLockAuthResult) {
            when (result) {
                is AppLockAuthResult.Failure -> {
                    errorMessage = result.message
                    promptShown = false
                }
                is AppLockAuthResult.Cancelled -> promptShown = false
                is AppLockAuthResult.Success -> {
                    if (fidoRequired && !fidoConfirmed) {
                        authenticator.confirmSecurityKey(act, fidoLabel) { fidoResult ->
                            when (fidoResult) {
                                is AppLockAuthResult.Success -> {
                                    fidoConfirmed = true
                                    onSuccess()
                                }
                                is AppLockAuthResult.Failure -> {
                                    errorMessage = fidoResult.message
                                    promptShown = false
                                }
                                is AppLockAuthResult.Cancelled -> promptShown = false
                            }
                        }
                    } else {
                        onSuccess()
                    }
                }
            }
        }
        authenticator.authenticate(act, ::afterPrimary)
    }

    LaunchedEffect(activity) {
        if (activity != null && !promptShown) {
            launchPrompt()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.app_lock_title),
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.app_lock_body),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (fidoRequired) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(
                    R.string.app_lock_fido_required_fmt,
                    fidoLabel ?: securityKeyFallback,
                ),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            Text(
                text = stringResource(R.string.app_lock_fido_confirm_hint),
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
        errorMessage?.let {
            Spacer(modifier = Modifier.height(12.dp))
            Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
        }
        Spacer(modifier = Modifier.height(24.dp))
        Button(
            onClick = { launchPrompt() },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.app_lock_unlock))
        }
    }
}

@Composable
private fun DeviceInsecureScreen(
    onSecuritySettings: () -> Unit = {},
    onResumeCheck: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                onResumeCheck()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = Icons.Default.Lock,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.error,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.app_lock_device_insecure_title),
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.app_lock_device_insecure_body),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(
            onClick = {
                onSecuritySettings()
                context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.app_lock_open_security_settings))
        }
    }
}

private fun Context.findFragmentActivity(): FragmentActivity? {
    var ctx: Context? = this
    while (ctx is ContextWrapper) {
        if (ctx is FragmentActivity) return ctx
        ctx = ctx.baseContext
    }
    return null
}
