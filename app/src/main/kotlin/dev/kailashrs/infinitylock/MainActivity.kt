package dev.kailashrs.infinitylock

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.currentCoroutineContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.kailashrs.infinitylock.engine.*
import dev.kailashrs.infinitylock.shell.*
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.theme.*
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.menu.OverlayIconDropdownMenu
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.More

class MainActivity : ComponentActivity() {
    private var connection by mutableStateOf("Waiting for Shizuku")
    private var engine by mutableStateOf<Engine?>(null)
    private var gates by mutableStateOf<Gates?>(null)
    private var attempt by mutableStateOf(Attempt())
    private var deviceLog by mutableStateOf("")
    private var note by mutableStateOf("")
    private var screenStarted by mutableStateOf(false)
    private var debugLogging by mutableStateOf(false)
    private var autoRoot by mutableStateOf(false)
    private val preferences get() = getSharedPreferences("settings", MODE_PRIVATE)
    private var unsubscribe: (() -> Unit)? = null
    private val app get() = application as InfinityLockApp

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        autoRoot = preferences.getBoolean("auto_root", false)
        debugLogging = preferences.getBoolean("debug_logging", false)
        if (autoRoot) runCatching { AutoRootService.start(this) }
        enableEdgeToEdge()
        setContent {
            MiuixTheme(colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Screen()
            }
        }
        unsubscribe = ShizukuGate.onStateChanged { state -> runOnUiThread {
            connection = when (state) {
                is ShizukuState.Ready -> "Connected · UID ${state.uid}"
                ShizukuState.NoPermission -> "Permission required"
                ShizukuState.NotRunning -> "Start Shizuku to connect"
                ShizukuState.Checking -> "Waiting for Shizuku"
            }
            if (state is ShizukuState.Ready) {
                app.engine?.let(::attach) ?: ShizukuGate.bindUserService(applicationContext) { service -> runOnUiThread {
                    if (service != null) {
                        val value = app.engine ?: Engine(applicationContext, service).also { app.engine = it }
                        attach(value)
                    } else {
                        app.engine = null; engine = null; gates = null
                        connection = "Shell disconnected · reconnect Shizuku"
                    }
                } }
            } else { engine = null; app.engine = null; gates = null }
        } }
    }

    private fun attach(value: Engine) {
        engine = value
        value.observe { state ->
            if (!isDestroyed) {
                attempt = state
                if (state.phase == Phase.FINISHED) refresh()
            }
        }
        refresh()
    }
    private fun refresh() { engine?.refreshGates { snapshot ->
        if (isDestroyed) return@refreshGates
        gates = snapshot
    } }
    private fun startAttempt() {
        note = ""; deviceLog = ""
        engine?.runAttempt()
    }
    private fun updateAutoRootPreference(enabled: Boolean) {
        autoRoot = enabled
        preferences.edit().putBoolean("auto_root", enabled).apply()
        if (enabled) {
            if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 101)
            }
            runCatching { AutoRootService.start(this) }.onFailure { toast("Background startup failed: ${it.message}") }
        } else stopService(Intent(this, AutoRootService::class.java))
    }
    private fun toast(text: String) { Toast.makeText(this, text, Toast.LENGTH_LONG).show() }

    @Composable
    private fun Screen() {
        var confirmAutoRoot by remember { mutableStateOf(false) }
        var confirmRun by remember { mutableStateOf(false) }
        var confirmReboot by remember { mutableStateOf(false) }
        var logsExpanded by rememberSaveable { mutableStateOf(false) }
        LaunchedEffect(engine, screenStarted, logsExpanded, attempt.busy) {
            val activeEngine = engine ?: return@LaunchedEffect
            if (!screenStarted) return@LaunchedEffect
            do {
                deviceLog = if (attempt.busy && attempt.phase in listOf(Phase.GATES, Phase.STAGING, Phase.LAUNCHING)) ""
                    else withContext(Dispatchers.IO) { activeEngine.deviceLogSnapshot() }
                if (!logsExpanded && !attempt.busy) break
                delay(1000)
            } while (currentCoroutineContext().isActive)
        }
        val g = gates
        val secondary = MiuixTheme.colorScheme.onSurfaceVariantSummary
        val dark = isSystemInDarkTheme()
        Scaffold(topBar = {
            Row(Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 24.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween) {
                Text("InfinityLock", fontSize = 34.sp)
            OverlayIconDropdownMenu(entry = DropdownEntry(items = listOf(
                DropdownItem(text = "Auto-root", selected = autoRoot,
                    summary = if (autoRoot) "On" else "Off", onClick = {
                        if (autoRoot) updateAutoRootPreference(false) else confirmAutoRoot = true
                    }),
                DropdownItem(text = "Debug logging", selected = debugLogging,
                    summary = if (debugLogging) "On" else "Off", enabled = !attempt.busy, onClick = {
                        debugLogging = !debugLogging
                        preferences.edit().putBoolean("debug_logging", debugLogging).apply()
                    }),
                DropdownItem(text = "Reboot", enabled = engine != null && !attempt.busy,
                    onClick = { confirmReboot = true })
            ))) {
                Icon(imageVector = MiuixIcons.More, contentDescription = "More options")
            }
            }
        }) { padding ->
            Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp).padding(top = 8.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Temporary root for Vivo X200 Ultra · Based on CVE-2026-98260", fontSize = 16.sp, color = secondary)
                Card(Modifier.fillMaxWidth(), insideMargin = PaddingValues(20.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Device", fontSize = 20.sp)
                        Text(when { g == null -> "Not checked"; g.firmwareMatch -> "Supported"; else -> "Unsupported" }, fontSize = 14.sp, color = secondary)
                    }
                    Spacer(Modifier.height(8.dp))
                    Text("Vivo X200 Ultra", fontSize = 16.sp)
                    Text(g?.kernel?.ifBlank { "Kernel unavailable" } ?: "Connect Shizuku to check firmware", fontSize = 12.sp, color = secondary)
                    if (g != null && !g.firmwareMatch) {
                        Text("Firmware does not match the supported build.", fontSize = 13.sp, color = MiuixTheme.colorScheme.error)
                    }

                }
                Card(modifier = Modifier.fillMaxWidth().clickable(role = Role.Button) {
                    if (engine == null) ShizukuGate.requestPermission() else refresh()
                }, insideMargin = PaddingValues(16.dp), colors = CardDefaults.defaultColors(
                    color = if (engine != null) {
                        if (dark) Color(0xFF1A3825) else Color(0xFFDFFAE4)
                    } else { if (dark) Color(0xFF3E2F1B) else Color(0xFFFFF0DB) }
                )) {
                    Text("Shizuku · $connection", fontSize = 15.sp)
                    if (engine == null) {
                        Spacer(Modifier.height(4.dp))
                        Text("Start Shizuku, then tap here to grant access.", fontSize = 13.sp, color = secondary)
                    }
                }
                Card(Modifier.fillMaxWidth(), insideMargin = PaddingValues(20.dp)) {
                    Text("Temporary root", fontSize = 22.sp)
                    Spacer(Modifier.height(8.dp))
                    Text(when {
                        attempt.busy -> "${attempt.phase} · ${attempt.elapsedS}s"
                        g?.ksuLoaded == true -> "KernelSU is loaded"
                        g?.parkedProcess == true || g?.attemptedThisBoot == true -> "Reboot before running again"
                        g?.allClear == true -> "Ready"
                        g == null -> "Waiting for Shizuku"
                        else -> "Device checks incomplete"
                    }, fontSize = 16.sp)
                    Spacer(Modifier.height(4.dp))
                    Text(note.ifBlank { attempt.detail.ifBlank {
                        if (g?.ksuLoaded == true) "Open Manager to check root status."
                        else "Root stays active until the next reboot."
                    } }, fontSize = 14.sp, color = secondary)
                    Spacer(Modifier.height(20.dp))
                    TextButton(text = if (attempt.busy) "Running…" else "Run",
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                        onClick = { confirmRun = true }, enabled = engine != null && g?.allClear == true && !attempt.busy,
                        modifier = Modifier.fillMaxWidth())
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(text = "Open KernelSU Manager", onClick = {
                        val intent = packageManager.getLaunchIntentForPackage("me.weishu.kernelsu")
                        if (intent == null) toast("Install and open official KernelSU Manager v3.3.1 first") else startActivity(intent)
                    }, modifier = Modifier.weight(1f))
                }
                Card(Modifier.fillMaxWidth(), insideMargin = PaddingValues(0.dp)) {
                    Row(Modifier.fillMaxWidth().clickable(role = Role.Button, onClickLabel = if (logsExpanded) "Collapse log" else "Expand log") {
                        logsExpanded = !logsExpanded
                    }.padding(20.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Diagnostics", fontSize = 20.sp)
                        Text(if (logsExpanded) "Hide log −" else "Show log +", fontSize = 14.sp, color = secondary)
                    }
                    AnimatedVisibility(visible = logsExpanded) {
                        Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            SelectionContainer {
                                Text(deviceLog.ifBlank { if (attempt.busy) "Waiting for runner output…" else "No runner log yet." },
                                    fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                            }
                            TextButton(text = "Share log", onClick = {
                                startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_TEXT, "${g?.kernel.orEmpty()}\n${attempt.detail}\n${deviceLog}")
                                }, "Share diagnostics"))
                            }, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            }
            OverlayDialog(title = "Enable auto-root?", show = confirmAutoRoot,
                summary = "Start at boot and run when Shizuku connects. One attempt per boot.",
                onDismissRequest = { confirmAutoRoot = false }) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(text = "Cancel", onClick = { confirmAutoRoot = false }, modifier = Modifier.weight(1f))
                    TextButton(text = "Enable", colors = ButtonDefaults.textButtonColorsPrimary(), onClick = {
                        confirmAutoRoot = false; updateAutoRootPreference(true)
                    }, modifier = Modifier.weight(1f))
                }
            }
            OverlayDialog(title = "Start temporary root?", show = confirmRun,
                summary = "This may take several attempts.",
                onDismissRequest = { confirmRun = false }) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(text = "Cancel", onClick = { confirmRun = false }, modifier = Modifier.weight(1f))
                    TextButton(text = "Run", colors = ButtonDefaults.textButtonColorsPrimary(), onClick = {
                        confirmRun = false
                        startAttempt()
                    }, modifier = Modifier.weight(1f))
                }
            }
            OverlayDialog(title = "Reboot phone?", show = confirmReboot,
                summary = "This ends temporary root and clears parked attempts. Save your work first.",
                onDismissRequest = { confirmReboot = false }) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    TextButton(text = "Cancel", onClick = { confirmReboot = false }, modifier = Modifier.weight(1f))
                    TextButton(text = "Reboot", colors = ButtonDefaults.textButtonColorsPrimary(), onClick = {
                        confirmReboot = false
                        engine?.reboot { ok, detail -> toast(if (ok) "Reboot requested" else detail) }
                    }, modifier = Modifier.weight(1f))
                }
            }
        }
    }
    override fun onStart() { super.onStart(); screenStarted = true }
    override fun onStop() { screenStarted = false; super.onStop() }
    override fun onResume() { super.onResume(); autoRoot = preferences.getBoolean("auto_root", false) }
    override fun onDestroy() { unsubscribe?.invoke(); engine?.stopObserving(); super.onDestroy() }
}
