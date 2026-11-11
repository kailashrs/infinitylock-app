package dev.kailashrs.infinitylock.shell

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import androidx.annotation.Keep
import java.io.File

/**
 * Shizuku user service. Instantiated inside the Shizuku server process with
 * uid 2000 (adb/shell) or 0 (root) — the same Linux/SELinux context as ADB.
 *
 * IMPORTANT: this process must never kill, reap or reboot anything. It only
 * stages, launches with setsid (detached, survives app death), observes, and
 * classifies. Parked exploitation processes are cleaned up exclusively by an
 * explicitly consented reboot.
 */
@Keep
class ShellService : IShellService.Stub {

    /** Required no-arg constructor. */
    constructor()

    /** Constructor with Context, available since Shizuku API v13. */
    @Keep
    constructor(context: Context)

    @Keep
    override fun destroy() {
        System.exit(0)
    }

    override fun exit() {
        destroy()
    }

    @Keep
    override fun exec(command: String): ExecResult {
        val process = ProcessBuilder("sh", "-c", command)
            .redirectErrorStream(true)
            .start()
        val text = process.inputStream.bufferedReader().use { it.readText() }
        val code = process.waitFor()
        return ExecResult(code, text)
    }

    @Keep
    override fun processAlive(pattern: String): Boolean =
        exec("pidof ${shQuote(pattern)}").exitCode == 0

    @Keep
    override fun ksuModuleListed(): Boolean =
        // Hidden-module profile: the hardened module removes itself from
        // /proc/modules after init, so the runner's stage stamps a
        // boot-scoped liveness marker once its root-side gated-supercall
        // verification succeeds. Either signal means KernelSU is live for
        // this boot; unprivileged callers cannot forge the stamp because it
        // is compared against the kernel's current boot id.
        exec(
            "grep -q '^kernelsu ' /proc/modules || " +
                "[ \"\$(cat /data/local/tmp/ksu-live.stamp 2>/dev/null)\" = " +
                "\"\$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)\" ]",
        ).exitCode == 0

    @Keep
    override fun writeStream(pfd: ParcelFileDescriptor?, dir: String, name: String, mode: Int): Long {
        if (pfd == null) return -1L
        return try {
            val target = File(dir, name)
            ParcelFileDescriptor.AutoCloseInputStream(pfd).use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            val bytes = target.length()
            Os.chmod(target.absolutePath, mode)
            bytes
        } catch (_: Throwable) {
            -1L
        }
    }

    @Keep
    override fun readFile(path: String, maxBytes: Int): String {
        val file = File(path)
        if (!file.exists() || !file.isFile) return ""
        return runCatching {
            val cap = maxBytes.coerceAtLeast(1)
            val bytes = java.io.RandomAccessFile(file, "r").use { input ->
                val length = input.length()
                val start = (length - cap).coerceAtLeast(0L)
                input.seek(start)
                val buf = ByteArray((length - start).toInt())
                var read = 0
                while (read < buf.size) {
                    val n = input.read(buf, read, buf.size - read)
                    if (n < 0) break
                    read += n
                }
                buf.copyOf(read)
            }
            String(bytes, Charsets.UTF_8)
        }.getOrDefault("")
    }

    @Keep
    override fun writeFile(dir: String, name: String, mode: Int, content: String) {
        val target = File(dir, name)
        target.writeText(content)
        Os.chmod(target.absolutePath, mode)
    }

    @Keep
    override fun pathExists(path: String): Boolean = File(path).exists()

    @Keep
    override fun mkdirs(dir: String, mode: Int) {
        val f = File(dir)
        f.mkdirs()
        Os.chmod(dir, mode)
    }

    private fun shQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
