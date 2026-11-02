package dev.kailashrs.infinitylock

import android.app.*
import android.content.*
import android.content.pm.ServiceInfo
import android.os.*
import dev.kailashrs.infinitylock.engine.*
import dev.kailashrs.infinitylock.shell.*

/** User-enabled, visible listener. No UI is launched and no reboot is issued. */
class AutoRootService : Service() {
    private val main = Handler(Looper.getMainLooper())
    private var unsubscribe: (() -> Unit)? = null
    private var currentEngine: Engine? = null
    private var checking = false
    private var handled = false
    private val enabled get() = getSharedPreferences("settings", MODE_PRIVATE).getBoolean("auto_root", false)
    override fun onBind(intent: Intent?) = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") {
            getSharedPreferences("settings", MODE_PRIVATE).edit().putBoolean("auto_root", false).apply()
            stopSelf(); return START_NOT_STICKY
        }
        if (!enabled) { stopSelf(); return START_NOT_STICKY }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Auto-root", NotificationManager.IMPORTANCE_LOW))
        val initial = notification("Waiting for Shizuku")
        if (Build.VERSION.SDK_INT >= 34) startForeground(ID, initial, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(ID, initial)
        if (unsubscribe == null) unsubscribe = ShizukuGate.onStateChanged { state -> main.post { onConnection(state) } }
        return START_STICKY
    }
    private fun onConnection(state: ShizukuState) {
        if (!enabled || handled || checking) return
        when (state) {
            is ShizukuState.Ready -> {
                checking = true
                status("Checking device")
                ShizukuGate.bindUserService(applicationContext) { shell -> main.post {
                    if (!enabled) { checking = false; stopSelf(); return@post }
                    if (shell == null) { checking = false; status("Shell disconnected · waiting for Shizuku"); return@post }
                    val app = application as InfinityLockApp
                    val engine = app.engine ?: Engine(applicationContext, shell).also { app.engine = it }
                    currentEngine = engine
                    engine.refreshGates { gates ->
                        checking = false
                        if (!enabled) { stopSelf(); return@refreshGates }
                        if (!gates.allClear) {
                            handled = true
                            status(when {
                                gates.ksuLoaded -> "KernelSU already loaded"
                                gates.parkedProcess || gates.attemptedThisBoot -> "Fresh boot required"
                                else -> "Device checks did not pass"
                            })
                            stopSelf(); return@refreshGates
                        }
                        handled = true
                        engine.observeService { attempt ->
                            if (attempt.phase == Phase.FINISHED) {
                                status(attempt.detail); stopSelf()
                            } else status("${attempt.phase} · ${attempt.elapsedS}s")
                        }
                        engine.runAttempt()
                    }
                } }
            }
            ShizukuState.NoPermission -> status("Open InfinityLock and grant Shizuku access")
            else -> {
                (application as InfinityLockApp).engine = null
                status("Waiting for Shizuku")
            }
        }
    }
    private fun status(text: String) {
        getSystemService(NotificationManager::class.java).notify(ID, notification(text))
    }
    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, AutoRootService::class.java).setAction("stop"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("InfinityLock · Auto-root").setContentText(text).setContentIntent(open)
            .setOngoing(true).setOnlyAlertOnce(true).addAction(Notification.Action.Builder(null, "Turn off", stop).build()).build()
    }
    override fun onDestroy() {
        unsubscribe?.invoke(); currentEngine?.observeService(null)
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
    companion object {
        private const val CHANNEL = "auto_root"
        private const val ID = 98260
        fun start(context: Context) { context.startForegroundService(Intent(context, AutoRootService::class.java)) }
    }
}
