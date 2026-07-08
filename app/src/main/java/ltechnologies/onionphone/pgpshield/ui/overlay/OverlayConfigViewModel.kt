package ltechnologies.onionphone.pgpshield.ui.overlay

/**
 * State holder for configuring per-app overlay behaviour, padding templates and
 * the list of installed applications the overlay can target.
 */

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.data.db.OverlayAppConfigEntity
import ltechnologies.onionphone.pgpshield.data.db.OverlayConfigDao
import ltechnologies.onionphone.pgpshield.data.db.PaddingTemplateDao
import ltechnologies.onionphone.pgpshield.data.db.PaddingTemplateEntity
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A user-installed application eligible for overlay configuration. */
data class InstalledApp(
    val packageName: String,
    val label: String,
)

/**
 * [ViewModel] exposing overlay per-app configs, padding templates, keys and the
 * installed-app list, and persisting configuration changes.
 */
@HiltViewModel
class OverlayConfigViewModel @Inject constructor(
    private val overlayConfigDao: OverlayConfigDao,
    private val paddingTemplateDao: PaddingTemplateDao,
    keyRepository: KeyRepository,
    @ApplicationContext private val context: Context,
) : ViewModel() {
    val configs: StateFlow<List<OverlayAppConfigEntity>> =
        overlayConfigDao.observeAll()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val keys: StateFlow<List<KeySummary>> =
        keyRepository.observeKeys()
            .distinctUntilChanged()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val paddingTemplates: StateFlow<List<PaddingTemplateEntity>> =
        paddingTemplateDao.observeAll()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _installedApps = MutableStateFlow<List<InstalledApp>>(emptyList())
    val installedApps: StateFlow<List<InstalledApp>> = _installedApps
    private var appsLoaded = false

    /** Loads the installed-app list once, no-op if already loaded. */
    fun ensureInstalledAppsLoaded() {
        if (appsLoaded) return
        loadInstalledApps()
    }

    /** Loads and sorts user-installed (plus messenger) apps off the main thread. */
    fun loadInstalledApps() {
        viewModelScope.launch {
            _installedApps.value = withContext(Dispatchers.Default) {
                val pm = context.packageManager
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    .asSequence()
                    .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 || it.packageName.contains("messenger") }
                    .map { info ->
                        InstalledApp(
                            packageName = info.packageName,
                            label = info.loadLabel(pm).toString(),
                        )
                    }
                    .sortedBy { it.label.lowercase() }
                    .toList()
            }
            appsLoaded = true
        }
    }

    /** Inserts or updates the per-app overlay config [entity]. */
    fun save(entity: OverlayAppConfigEntity) {
        viewModelScope.launch { overlayConfigDao.upsert(entity) }
    }

    /** Removes the overlay config for the given caller [packageName]. */
    fun delete(packageName: String) {
        viewModelScope.launch { overlayConfigDao.delete(packageName) }
    }
}
