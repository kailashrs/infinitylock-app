package dev.kailashrs.infinitylock
import android.app.Application
import dev.kailashrs.infinitylock.engine.Engine
import dev.kailashrs.infinitylock.shell.ShizukuGate
class InfinityLockApp : Application() {
    var engine: Engine? = null
    override fun onCreate() { super.onCreate(); ShizukuGate.init() }
}
