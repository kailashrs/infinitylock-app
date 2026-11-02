package dev.kailashrs.infinitylock
import android.content.*
import android.util.Log
class StartupReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action !in setOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED)) return
        if (context.getSharedPreferences("settings", Context.MODE_PRIVATE).getBoolean("auto_root", false)) {
            runCatching { AutoRootService.start(context) }.onFailure { Log.w("InfinityLock", "Autostart was blocked", it) }
        }
    }
}
