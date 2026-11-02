package dev.kailashrs.infinitylock.shell

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import dev.kailashrs.infinitylock.util.componentName
import rikka.shizuku.Shizuku

/** UI-facing Shizuku connection state. */
sealed interface ShizukuState {
    data object Checking : ShizukuState
    data object NotRunning : ShizukuState
    data object NoPermission : ShizukuState
    data class Ready(val uid: Int, val version: Int) : ShizukuState

    val isConnected: Boolean get() = this is Ready
}

/**
 * Owns the Shizuku binder lifecycle and the user-service binding.
 *
 * Permission model mirrors the runtime-permission-like flow: when the binder
 * arrives, permission is either granted already or requested via
 * Shizuku.requestPermission, with the async result read from the
 * OnRequestPermissionResultListener.
 */
object ShizukuGate {

    private const val REQUEST_CODE = 99
    private val callbacks = mutableListOf<(ShizukuState) -> Unit>()
    private var cachedService: IShellService? = null
    private val serviceWaiters = mutableListOf<(IShellService?) -> Unit>()
    private var serviceConnection: ServiceConnection? = null
    private var args: Shizuku.UserServiceArgs? = null
    private var state: ShizukuState = ShizukuState.Checking

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener {
        if (Shizuku.isPreV11()) {
            setState(ShizukuState.NotRunning)
        } else if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
            onGranted()
        } else {
            setState(ShizukuState.NoPermission)
        }
    }

    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        componentUnbound()
        setState(ShizukuState.NotRunning)
    }

    private val permissionResultListener =
        object : Shizuku.OnRequestPermissionResultListener {
            override fun onRequestPermissionResult(requestCode: Int, grantResult: Int) {
                if (requestCode == REQUEST_CODE && grantResult == PackageManager.PERMISSION_GRANTED) {
                    onGranted()
                } else {
                    setState(ShizukuState.NoPermission)
                }
            }
        }

    /** Register listeners. Call exactly once from Application.onCreate. */
    fun init() {
        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        Shizuku.addRequestPermissionResultListener(permissionResultListener)
        if (!Shizuku.pingBinder()) setState(ShizukuState.NotRunning)
    }

    /** Unregister listeners and unbind the user service. */
    fun dispose() {
        runCatching { Shizuku.removeRequestPermissionResultListener(permissionResultListener) }
        runCatching { Shizuku.removeBinderDeadListener(binderDeadListener) }
        runCatching { Shizuku.removeBinderReceivedListener(binderReceivedListener) }
        componentUnbound()
        synchronized(callbacks) { callbacks.clear() }
    }

    fun onStateChanged(callback: (ShizukuState) -> Unit): () -> Unit {
        synchronized(callbacks) { callbacks.add(callback) }
        callback(state)
        return { synchronized(callbacks) { callbacks.remove(callback) } }
    }

    /** Request permission (runtime-like); the result arrives via the listener. */
    fun requestPermission() {
        runCatching { Shizuku.requestPermission(REQUEST_CODE) }
    }

    private fun onGranted() {
        runCatching { setState(ShizukuState.Ready(Shizuku.getUid(), Shizuku.getVersion())) }
            .onFailure { setState(ShizukuState.NotRunning) }
    }

    /**
     * Bind the ShellService user service. It is instantiated inside the
     * Shizuku server process, inheriting the ADB-equivalent uid/SELinux context.
     */
    fun bindUserService(context: Context, onService: (IShellService?) -> Unit) {
        cachedService?.takeIf { it.asBinder().isBinderAlive }?.let { onService(it); return }
        serviceWaiters.add(onService)
        if (serviceConnection != null) return
        val helper = ShizukuGateBinder(context) { service ->
            if (service == null) { serviceConnection = null; args = null }
            cachedService = service
            val waiters = serviceWaiters.toList(); serviceWaiters.clear()
            waiters.forEach { it(service) }
        }
        val conn = helper.connection
        val myArgs = Shizuku.UserServiceArgs(
            componentName(context, ShellService::class.java),
        )
            .daemon(false)
            .processNameSuffix("engine")
            .debuggable(false)
            .version(1)
        args = myArgs
        serviceConnection = conn
        runCatching {
            Shizuku.bindUserService(myArgs, conn)
        }.onFailure {
            serviceConnection = null
            args = null
            val waiters = serviceWaiters.toList(); serviceWaiters.clear()
            waiters.forEach { it(null) }
        }
    }

    fun isBound(): Boolean = serviceConnection != null

    private fun componentUnbound() {
        cachedService = null
        serviceWaiters.clear()
        val myArgs = args
        val conn = serviceConnection
        if (myArgs != null) {
            runCatching { Shizuku.unbindUserService(myArgs, conn, true) }
        }
        args = null
        serviceConnection = null
    }

    private fun setState(s: ShizukuState) {
        state = s
        val snapshot = synchronized(callbacks) { callbacks.toList() }
        snapshot.forEach { it(s) }
    }

    private val _sync = Any()
    private fun Any.callbacksSyncLock(): Any = _sync
}

/** Holder that wires the standard ServiceConnection to the AIDL iface. */
private class ShizukuGateBinder(
    private val context: Context,
    private val onService: (IShellService?) -> Unit,
) {
    val connection: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            if (binder != null && binder.pingBinder()) {
                onService(IShellService.Stub.asInterface(binder))
            } else {
                onService(null)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) { onService(null) }
    }
}
