package ltechnologies.onionphone.pgpshield.ui.navigation

/**
 * Top-level Compose navigation: route constants and the adaptive tab NavHost.
 */

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import ltechnologies.onionphone.pgpshield.ui.components.LocalSnackbarHostState
import ltechnologies.onionphone.pgpshield.ui.components.ProvideAdaptiveMetrics
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.ui.keys.KeyListViewModel
import ltechnologies.onionphone.pgpshield.ui.components.RetainedTab
import ltechnologies.onionphone.pgpshield.ui.crypto.CryptoScreen
import ltechnologies.onionphone.pgpshield.ui.keys.CreateKeyScreen
import ltechnologies.onionphone.pgpshield.ui.keys.ImportKeyScreen
import ltechnologies.onionphone.pgpshield.ui.keys.KeyDetailScreen
import ltechnologies.onionphone.pgpshield.ui.keys.KeyListScreen
import ltechnologies.onionphone.pgpshield.ui.keys.KeySearchScreen
import ltechnologies.onionphone.pgpshield.ui.qr.QrKeyScreen
import ltechnologies.onionphone.pgpshield.ui.settings.SettingsScreen
import ltechnologies.onionphone.pgpshield.ui.smartcard.SmartCardScreen

/** Navigation route strings and helpers for building parameterized routes. */
object Routes {
    const val HOME = "home"
    const val CREATE_KEY = "create_key"
    const val IMPORT_KEY = "import_key"
    const val KEY_SEARCH = "key_search"
    const val KEY_DETAIL = "key_detail/{keyIdHex}"
    const val CRYPTO = "crypto"
    const val SETTINGS = "settings"
    const val QR_KEY = "qr_key"
    const val SMART_CARD = "smart_card"

    /** Builds the key-detail route for [keyId], encoding it for safe URL use. */
    fun keyDetail(keyId: Long) = "key_detail/${KeyNavIds.encode(keyId)}"
}

private enum class MainTab { Keys, Crypto, Settings }

private val mainTabs = listOf(
    MainTab.Keys to Icons.Default.Key,
    MainTab.Crypto to Icons.Default.Lock,
    MainTab.Settings to Icons.Default.Settings,
)

@Composable
private fun mainTabLabel(tab: MainTab): String = when (tab) {
    MainTab.Keys -> stringResource(R.string.keys_title)
    MainTab.Crypto -> stringResource(R.string.crypto_title)
    MainTab.Settings -> stringResource(R.string.settings_title)
}

/**
 * Root navigation composable presenting three retained tabs — Keys, Crypto and
 * Settings — inside an adaptive [NavigationSuiteScaffold].
 *
 * Each tab keeps its own [androidx.navigation.NavHostController] so tab state and
 * back stacks survive tab switches. The bottom/side navigation bar is hidden on
 * nested (non-root) destinations.
 */
@Composable
fun PgpShieldNavHost() {
    var mainTab by rememberSaveable { mutableStateOf(MainTab.Keys) }
    val snackbarHostState = LocalSnackbarHostState.current
    val keysNav = rememberNavController()
    val settingsNav = rememberNavController()
    val keysBackStack by keysNav.currentBackStackEntryAsState()
    val settingsBackStack by settingsNav.currentBackStackEntryAsState()
    val keysRoute = keysBackStack?.destination?.route
    val settingsRoute = settingsBackStack?.destination?.route
    val showNav = when (mainTab) {
        MainTab.Keys -> keysRoute == Routes.HOME
        MainTab.Crypto -> true
        MainTab.Settings -> settingsRoute == Routes.SETTINGS
    }

    val tabContent: @Composable (Modifier) -> Unit = { modifier ->
        Box(modifier.fillMaxSize()) {
            RetainedTab(visible = mainTab == MainTab.Keys) {
                NavHost(
                    navController = keysNav,
                    startDestination = Routes.HOME,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    composable(Routes.HOME) {
                        KeyListScreen(
                            onCreateKey = { keysNav.navigate(Routes.CREATE_KEY) },
                            onImportKey = { keysNav.navigate(Routes.IMPORT_KEY) },
                            onSearchKeys = { keysNav.navigate(Routes.KEY_SEARCH) },
                            onKeyClick = { id -> keysNav.navigate(Routes.keyDetail(id)) },
                            showTopBar = true,
                        )
                    }
                    composable(Routes.CREATE_KEY) {
                        CreateKeyScreen(onBack = { keysNav.popBackStack() })
                    }
                    composable(Routes.IMPORT_KEY) {
                        val homeEntry = keysNav.getBackStackEntry(Routes.HOME)
                        val listViewModel: KeyListViewModel = hiltViewModel(homeEntry)
                        ImportKeyScreen(
                            onBack = { keysNav.popBackStack() },
                            viewModel = listViewModel,
                        )
                    }
                    composable(Routes.KEY_SEARCH) {
                        KeySearchScreen(onBack = { keysNav.popBackStack() })
                    }
                    composable(
                        route = Routes.KEY_DETAIL,
                        arguments = listOf(navArgument("keyIdHex") { type = NavType.StringType }),
                    ) { entry ->
                        val homeEntry = keysNav.getBackStackEntry(Routes.HOME)
                        val listViewModel: KeyListViewModel = hiltViewModel(homeEntry)
                        KeyDetailScreen(
                            keyId = KeyNavIds.decode(entry.arguments?.getString("keyIdHex")),
                            onBack = { keysNav.popBackStack() },
                            listViewModel = listViewModel,
                        )
                    }
                }
            }
            RetainedTab(visible = mainTab == MainTab.Crypto) {
                CryptoScreen(showBack = false)
            }
            RetainedTab(visible = mainTab == MainTab.Settings) {
                NavHost(
                    navController = settingsNav,
                    startDestination = Routes.SETTINGS,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    composable(Routes.SETTINGS) {
                        SettingsScreen(
                            onBack = { /* main tab */ },
                            onOpenQrKeys = { settingsNav.navigate(Routes.QR_KEY) },
                            onOpenSmartCard = { settingsNav.navigate(Routes.SMART_CARD) },
                            showBack = false,
                            isActive = mainTab == MainTab.Settings,
                        )
                    }
                    composable(Routes.QR_KEY) {
                        QrKeyScreen(onBack = { settingsNav.popBackStack() })
                    }
                    composable(Routes.SMART_CARD) {
                        SmartCardScreen(onBack = { settingsNav.popBackStack() })
                    }
                }
            }
        }
    }

    if (showNav) {
        NavigationSuiteScaffold(
            containerColor = MaterialTheme.colorScheme.background,
            navigationSuiteItems = {
                mainTabs.forEach { (tab, icon) ->
                    item(
                        selected = mainTab == tab,
                        onClick = { mainTab = tab },
                        icon = { Icon(icon, contentDescription = mainTabLabel(tab)) },
                        label = { Text(mainTabLabel(tab)) },
                    )
                }
            },
        ) {
            ProvideAdaptiveMetrics(Modifier.fillMaxSize()) {
                Box(Modifier.fillMaxSize()) {
                    tabContent(Modifier.fillMaxSize())
                    SnackbarHost(
                        hostState = snackbarHostState,
                        modifier = Modifier.align(Alignment.BottomCenter),
                    )
                }
            }
        }
    } else {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            snackbarHost = { SnackbarHost(snackbarHostState) },
        ) { padding ->
            ProvideAdaptiveMetrics(Modifier.fillMaxSize().padding(padding)) {
                tabContent(Modifier.fillMaxSize())
            }
        }
    }
}
