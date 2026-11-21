package dev.kailashrs.infinitylock.engine

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import dev.kailashrs.infinitylock.shell.IShellService
import java.io.File
import kotlin.concurrent.thread

/** Result classifier outputs — same set as the runner's classify(). */
enum class Outcome {
    NONE, REFUSED, MODULE_LOADED, DONE, COMPLETE_NO_KSU,
    PARK_BURST, PARK_OTHER, CRASH_INCOMPLETE, WINDOW_ELAPSED,
}

enum class Phase { IDLE, GATES, STAGING, LAUNCHING, RUNNING, FINISHED }

/** Pre-run gate snapshot for the status card. */
data class Gates(
    val kernel: String = "",
    val productVersion: String = "",
    val ksuLoaded: Boolean = false,
    val parkedProcess: Boolean = false,
    val attemptedThisBoot: Boolean = false,
    val bootId: String = "",
) {
    val kernelMatch: Boolean get() = Target.SUPPORTED_FIRMWARE.any { it.kernel == kernel }
    val productVersionMatch: Boolean get() = Target.SUPPORTED_FIRMWARE.any { it.productVersion == productVersion }

    /** Strict pair check: kernel and firmware must belong to the same entry. */
    val firmwareMatch: Boolean
        get() = Target.SUPPORTED_FIRMWARE.any { it.kernel == kernel && it.productVersion == productVersion }

    val allClear: Boolean
        get() = bootId.matches(Regex("[0-9a-fA-F-]{36}")) && firmwareMatch &&
            !ksuLoaded && !parkedProcess && !attemptedThisBoot
}

/** One-attempt state surfaced to the UI. */
data class Attempt(
    val phase: Phase = Phase.IDLE,
    val outcome: Outcome = Outcome.NONE,
    val detail: String = "",
    val elapsedS: Int = 0,
    val lines: List<String> = emptyList(),
    val busy: Boolean = false,
) {
    val canRun: Boolean get() = !busy && phase in listOf(Phase.IDLE, Phase.FINISHED)
}

/**
 * Faithful app-side port of the runner's run98260.sh semantics:
 *
 *  - exact kernel/firmware gate + fresh-boot gate (no loaded KernelSU module,
 *    no parked exploit process, one attempt per boot_id)
 *  - sha256-verified staging of runtime payloads (no manager APK)
 *  - exactly ONE detached (setsid) launch attempt; the exploit survives the
 *    app being killed
 *  - park-don't-kill: this code never kills or reaps anything; a parked
 *    process is cleaned up only by a user-consented reboot
 *  - staged files under /data/local/tmp are removed after a terminal verdict
 *    once no bootstrap is alive, and again on the next app start, so a
 *    completed or refused attempt does not leave identifiable payload names.
 *    The hidden-module loaded state is kept in private preferences instead of
 *    the public ksu-live.stamp, so the stamp is removed too.
 *  - never reboots without consent; classify mirrors the runner's markers
 */
class Engine(
    private val context: Context,
    private val shell: IShellService,
) {
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private val statusLock = Any()
    private var serviceUpdate: ((Attempt) -> Unit)? = null
    fun observeService(callback: ((Attempt) -> Unit)?) { serviceUpdate = callback }
    private var update: ((Attempt) -> Unit)? = null
    private var lines = mutableListOf<String>()
    private val preferences = context.getSharedPreferences("runner", Context.MODE_PRIVATE)
    private var activeLog: String
        get() = preferences.getString("log", "")?.takeIf {
            it.matches(Regex("/sdcard/InfinityLock/infinitylock-run-[0-9-]+\\.log")) ||
                (it.startsWith(context.filesDir.absolutePath + "/logs/") && it.endsWith(".log"))
        }.orEmpty()
        set(value) { preferences.edit().putString("log", value).commit() }
    @Volatile private var state = Attempt()
    @Volatile private var attemptBoot = ""

    // ------------------------------------------------------------------ api

    /** Snapshot gates so the UI can show them before anything runs. */
    fun refreshGates(onDone: (Gates) -> Unit) {
        thread(isDaemon = true) {
            // Read the public stamp before cleanup: it is the only loaded-state
            // witness if the private preference was not written yet.
            val g = runCatching { readGates() }.getOrElse {
                Gates()
            }
            cleanupStaleArtifacts()
            cleanupIdleHelpers()
            main.post { onDone(g) }
        }
    }

    /** Register a UI callback that receives every state transition. */
    fun observe(callback: (Attempt) -> Unit) {
        update = callback
        callback(state)
    }

    fun stopObserving() { update = null }

    /** Consent-gated reboot; never automatic. */
    fun reboot(onDone: (Boolean, String) -> Unit) {
        thread(isDaemon = true) {
            val r = runCatching { exec("reboot") }
                .getOrElse { -1 to "reboot failed: ${it.message}" }
            // If the device actually reboots, this call rarely returns cleanly.
            main.post { onDone(r.first == 0, r.second.trim().ifEmpty { "reboot issued" }) }
        }
    }

    // --------------------------------------------------------------- gates

    private fun readGates(): Gates {
        val kernel = exec("uname -r").second.trim()
        val productVersion = exec("getprop ro.vivo.system.product.version").second.trim()
        val bootId = exec("cat /proc/sys/kernel/random/boot_id").second.trim()
        val supported = Target.SUPPORTED_FIRMWARE.any {
            it.kernel == kernel && it.productVersion == productVersion
        }
        val loaded = supported && (loadedForBoot(bootId) || ksuLoaded())
        if (loaded && bootId.isNotBlank()) {
            // Keep the hidden-module state in private storage so the public
            // ksu-live.stamp does not have to be retained after cleanup.
            preferences.edit().putString("loaded_boot", bootId).commit()
        }
        return Gates(
            kernel = kernel,
            productVersion = productVersion,
            ksuLoaded = loaded,
            parkedProcess = shell.processAlive("vvlogd"),
            attemptedThisBoot = bootId.isNotBlank() &&
                (preferences.getString("attempt_boot", "") == bootId || shell.pathExists(bootMarkerPath(bootId))),
            bootId = bootId,
        )
    }

    private fun bootMarkerPath(bootId: String): String = "${Target.WORK_DIR}/attempt-$bootId"

    private fun loadedForBoot(bootId: String): Boolean =
        bootId.isNotBlank() && preferences.getString("loaded_boot", "") == bootId

    private fun ksuLoaded(): Boolean = synchronized(statusLock) {
        // Stage only read-only status helpers before gates. Neither the
        // bootstrap nor the module loader is executed during this check.
        for (p in listOf(Payload.KSUQUERY, Payload.KSU_STATUS)) {
            check(ensurePayload(p)) {
                "Cannot stage verified KernelSU status helper ${p.remoteName}"
            }
        }
        shell.ksuModuleListed()
    }

    // ------------------------------------------------------------- attempt

    /** Run the single attempt. Enforces the fresh-boot rule itself. */
    fun runAttempt() {
        synchronized(lock) {
            if (state.busy) return
            state = state.copy(busy = true)
        }
        thread(isDaemon = true) {
            reset()
            try {
                // --- gates (mirror runner REFUSED paths) ---
                running { copy(phase = Phase.GATES, busy = true) }
                val gates = readGates()
                attemptBoot = gates.bootId
                when {
                    !gates.bootId.matches(Regex("[0-9a-fA-F-]{36}")) || gates.kernel.isEmpty() || !gates.firmwareMatch ->
                        return@thread finish(Outcome.REFUSED, "REFUSED: exact kernel or firmware mismatch")

                    gates.ksuLoaded || gates.parkedProcess ->
                        return@thread finish(
                            Outcome.REFUSED,
                            "REFUSED: requires a fresh boot with no loaded KernelSU or active exploit",
                        )

                    gates.attemptedThisBoot ->
                        return@thread finish(
                            Outcome.REFUSED,
                            "REFUSED: this boot already used its one attempt (fresh boot required)",
                        )

                    else -> log("gates ok; kernel=${gates.kernel}")
                }

                // Gates have read any public loaded-state stamp. A previous
                // attempt may have left staged names behind even though its
                // bootstrap is gone; clear them before re-staging.
                cleanupRemoteArtifacts()

                // --- staging: sha256-verified, mirrors ensure_binary ---
                running { copy(phase = Phase.STAGING) }
                for (p in Payload.entries) {
                    log("staging ${p.remoteName}")
                    if (!ensurePayload(p)) {
                        return@thread finish(
                            Outcome.REFUSED,
                            "staging failed; no exploit launched",
                            fatal = "verified staging failed for ${p.remoteName}",
                        )
                    }
                }
                exec("rm -f ${Target.REMOTE_DIR}/ksupatch_neuter ${Target.REMOTE_DIR}/ksupatch_skip ${Target.REMOTE_DIR}/hkd_base ${Target.REMOTE_DIR}/hkd_go ${Target.REMOTE_DIR}/hkd_open")
                log("all payloads sha256-verified; ksupatch markers cleared")

                // --- single detached launch, mirrors launch_attempt ---
                running { copy(phase = Phase.LAUNCHING) }
                log("launching one candidate-only attempt; this app never reboots the device")
                shell.mkdirs(Target.WORK_DIR, Target.MODE_0700)
                // Atomic per-boot reservation before launch, shared across app processes.
                val reserved = exec("mkdir ${bootMarkerPath(gates.bootId)}")
                if (reserved.first != 0) return@thread finish(Outcome.REFUSED, "This boot is already reserved; reboot before another attempt")
                check(preferences.edit().putString("attempt_boot", gates.bootId).commit()) {
                    "Cannot persist the current-boot attempt reservation"
                }
                val logPath = "/sdcard/InfinityLock/infinitylock-run-${java.text.SimpleDateFormat("yyyyMMdd-HHmmss-SSS", java.util.Locale.US).format(java.util.Date())}.log"
                val prepared = exec("mkdir -p /sdcard/InfinityLock && (set -C; : > $logPath)")
                if (prepared.first != 0) return@thread finish(Outcome.REFUSED, "Cannot create runner log on shared storage; no attempt launched")
                activeLog = logPath
                val debugFlag = if (context.getSharedPreferences("settings", Context.MODE_PRIVATE).getBoolean("debug_logging", false)) "--debug " else ""
                val launched = exec(
                    "sh ${Target.REMOTE_DIR}/run.sh $debugFlag${shellQuote(logPath)}",
                )
                if (launched.first != 0) return@thread finish(
                    Outcome.REFUSED,
                    "Launch failed; boot reservation retained for recovery",
                    fatal = launched.second.trim(),
                )
                log(launched.second.trim())

                // --- watch loop, mirrors the 10s × RUN_WAIT classify loop ---
                running { copy(phase = Phase.RUNNING) }
                var elapsed = 0
                var outcome = Outcome.NONE
                while (elapsed < Target.RUN_WAIT_S) {
                    Thread.sleep(Target.POLL_S * 1000L)
                    elapsed += Target.POLL_S
                    running { copy(elapsedS = elapsed) }
                    outcome = classify()
                    if (outcome != Outcome.NONE) break
                }

                when (outcome) {
                    Outcome.NONE -> {
                        // Window elapsed while still RUNNING: report, never force.
                        finish(
                            Outcome.WINDOW_ELAPSED,
                            "Attempt window elapsed; exploit may still work in the background. " +
                                "No reboot, retry, or kill was performed.",
                        )
                            }

                    else -> {
                        // The hkd handshake files are (re)written during the
                        // run, after run.sh's pre-launch cleanup; a stray
                        // hkd_go survived a real success (seen 2026-11-20).
                        // Clear them once the attempt reached a verdict and
                        // the exploit process is gone; never while RUNNING.
                        exec("rm -f ${Target.REMOTE_DIR}/hkd_base ${Target.REMOTE_DIR}/hkd_go ${Target.REMOTE_DIR}/hkd_open")
                        val success = outcome == Outcome.DONE || outcome == Outcome.MODULE_LOADED
                        finish(
                            outcome,
                            if (success) {
                                "Module detected; stopped without reboot. " +
                                    "Manager and probe behavior still require manual validation."
                            } else {
                                "Stopped: $outcome. No reboot, retry, or process kill was performed."
                            },
                        )
                    }
                }
            } catch (t: Throwable) {
                finish(Outcome.REFUSED, "attempt aborted: ${t.message ?: t.javaClass.simpleName}", fatal = t.toString())
            }
        }
    }

    private fun ensurePayload(p: Payload): Boolean = synchronized(statusLock) {
        val path = "${Target.REMOTE_DIR}/${p.remoteName}"
        fun remoteHash() = exec("sha256sum $path").second.trim().substringBefore(' ')
        // Do not overwrite a status executable that another query may use.
        remoteHash() == p.sha256 || (stage(p) >= 0 && remoteHash() == p.sha256)
    }

    /** Pipe asset → shell-writable target under /data/local/tmp. */
    private fun stage(p: Payload): Long {
        val (read, write) = ParcelFileDescriptor.createPipe()
        val writer = thread(isDaemon = true) {
            try {
                context.assets.open(p.asset).use { input ->
                    ParcelFileDescriptor.AutoCloseOutputStream(write).use { output -> input.copyTo(output) }
                }
            } finally { runCatching { write.close() } }
        }
        val written = try {
            shell.writeStream(read, Target.REMOTE_DIR, p.remoteName, Target.MODE_0755)
        } finally {
            read.close()
        }
        writer.join(15_000)
        return written
    }

    // ------------------------------------------------------------- cleanup

    /** Payload and runtime files that must not outlive a finished attempt. */
    private val cleanupNames: List<String> =
        Payload.entries.map { it.remoteName } + listOf(
            "iq.log",
            "hkd_base", "hkd_go", "hkd_open", "hkd_extras",
            "ksu_slide", "ksu-exposure-root.txt", "kernelsu-p.ko",
            "ksu-trace.log", "ksu_stage.sh", "kmsg-this-boot.txt",
            "ksu-live.stamp", "ksupatch_neuter", "ksupatch_skip", "tsud",
        )

    @Volatile private var staleCleanupDone = false

    /**
     * Remove staged payloads and runtime artifacts from /data/local/tmp.
     *
     * A parked vvlogd owns its inputs until the user-consented reboot, so
     * nothing is deleted while it is alive. The loaded-state marker is the
     * private loaded_boot preference, so the public ksu-live.stamp is removed
     * with the rest of the temporary surface.
     */
    private fun cleanupRemoteArtifacts(): Boolean = runCatching {
        synchronized(statusLock) {
            if (shell.processAlive("vvlogd")) {
                false
            } else {
                val files = cleanupNames.joinToString(" ") { "${Target.REMOTE_DIR}/$it" } +
                    " ${Target.REMOTE_DIR}/pstore*.bin"
                val filesCleared = exec("rm -f $files").first == 0
                val dirsCleared = exec(
                    "rm -rf ${Target.WORK_DIR} ${Target.REMOTE_DIR}/tempshell",
                ).first == 0
                filesCleared && dirsCleared
            }
        }
    }.getOrDefault(false)

    private fun cleanupStaleArtifacts() {
        if (staleCleanupDone || state.busy) return
        archiveStaleLogs()
        if (cleanupRemoteArtifacts()) staleCleanupDone = true
    }

    /** Status helpers are only needed around a gate check, not while idle. */
    private fun cleanupIdleHelpers() {
        if (state.busy) return
        if (runCatching { shell.processAlive("vvlogd") }.getOrDefault(true)) return
        runCatching {
            exec("rm -f ${Target.REMOTE_DIR}/ksuquery ${Target.REMOTE_DIR}/ksu-status.sh")
        }
    }

    private fun readLogText(path: String): String {
        if (path.isBlank()) return ""
        return if (path.startsWith(context.filesDir.absolutePath)) {
            runCatching { File(path).takeIf { it.isFile }?.readText().orEmpty() }
                .getOrDefault("")
                .takeLast(LOG_CAP)
        } else {
            runCatching { shell.readFile(path, LOG_CAP) }.getOrDefault("")
        }
    }

    /**
     * Move a public runner log into app-private storage and delete the public
     * copy. Public logs contain bootstrap and KernelSU markers, so they must
     * not remain on shared storage after the attempt is over.
     */
    private fun archiveRunnerLog(path: String): String? {
        if (path.isBlank() || path.startsWith(context.filesDir.absolutePath)) return null
        if (runCatching { shell.processAlive("vvlogd") }.getOrDefault(true)) return null
        val text = runCatching { shell.readFile(path, LOG_CAP) }.getOrDefault("")
        if (text.isEmpty()) return null
        val dir = File(context.filesDir, "logs")
        if (!dir.isDirectory && !dir.mkdirs()) return null
        val dest = File(dir, File(path).name)
        if (runCatching { dest.writeText(text) }.isFailure) return null
        val removed = runCatching { exec("rm -f ${shellQuote(path)}").first == 0 }
            .getOrDefault(false)
        return if (removed) dest.absolutePath else null
    }

    private fun archiveStaleLogs() {
        if (state.busy) return
        if (runCatching { shell.processAlive("vvlogd") }.getOrDefault(true)) return
        val listing = runCatching {
            exec("ls -1 /sdcard/InfinityLock/infinitylock-* 2>/dev/null").second
        }.getOrDefault("")
        for (path in listing.lineSequence().map { it.trim() }.filter {
            it.matches(
                Regex("/sdcard/InfinityLock/infinitylock-(run-[0-9-]+\\.log|exposure-[A-Za-z0-9._-]+\\.txt)"),
            )
        }) {
            val archived = archiveRunnerLog(path)
            if (archived != null) {
                if (activeLog == path) activeLog = archived
                log("runner log archived to app-private storage")
            }
        }
        runCatching { exec("rmdir /sdcard/InfinityLock 2>/dev/null || true") }
    }

    // ------------------------------------------------------------ classify

    /** Non-blocking status probe; emits the classifier result to the UI. */
    fun classifyNow(onOutcome: (Outcome, String) -> Unit) {
        thread(isDaemon = true) {
            val o = runCatching { classify() }.getOrDefault(Outcome.CRASH_INCOMPLETE)
            val note = describe(o)
            main.post { onOutcome(o, note) }
        }
    }

    /** Called on a background dispatcher; bounded tail of the actual runner output. */
    fun deviceLogSnapshot(): String = runCatching {
        readLogText(activeLog)
    }.getOrDefault("Runner log unavailable: shell disconnected")

    private fun classify(): Outcome {
        if (!shell.asBinder().isBinderAlive) return Outcome.CRASH_INCOMPLETE
        if (ksuLoaded()) return Outcome.MODULE_LOADED
        val text = readLogText(activeLog).replace("\r", "")
        return classifyLog(text) { shell.processAlive("vvlogd") }
    }

    /**
     * Pure classification — an exact mirror of the runner's classify() cases:
     * DONE markers, COMPLETE-NO-KSU, PARK-BURST / PARK-OTHER, then the
     * running-but-no-marker check that decides RUNNING vs PARK-OTHER.
     */
    fun classifyLog(text: String, alive: () -> Boolean): Outcome = when {
        text.contains("KSU_LOADED") ||
            text.contains("KernelSU Live") ||
            text.contains("EARLY MODULE LOAD SUCCEEDED") -> Outcome.DONE

        text.contains("ksu stage (finalize) worker") -> Outcome.COMPLETE_NO_KSU

        text.contains("burst miss -- parking") ||
            text.contains("[-] plant1 burst missed") -> Outcome.PARK_BURST

        text.contains("parking without reap") || text.contains("-- parking") -> Outcome.PARK_OTHER

        text.contains("[-] child euid is not 0") -> Outcome.PARK_OTHER

        text.isBlank() -> Outcome.NONE // RUNNING

        else -> if (alive()) Outcome.NONE else Outcome.PARK_OTHER
    }

    private fun describe(o: Outcome): String = when (o) {
        Outcome.MODULE_LOADED, Outcome.DONE ->
            "KernelSU detected. Verify Live state and Working status in Manager."
        Outcome.COMPLETE_NO_KSU ->
            "Run completed end-to-end (early-K + remaining slots + finalize) without loading: full evidence."
        Outcome.PARK_BURST ->
            "Burst missed — exploit parked. Only a reboot cleans it up."
        Outcome.PARK_OTHER ->
            "Exploit parked without load. Only a reboot cleans it up."
        Outcome.CRASH_INCOMPLETE ->
            "Shell connection lost mid-run; this boot is inconclusive and may contain a parked attempt."
        Outcome.WINDOW_ELAPSED ->
            "Attempt window elapsed; exploit may still work in the background."
        Outcome.REFUSED ->
            "Attempt refused by a safety gate; nothing was launched."
        Outcome.NONE -> "Still running or no terminal marker yet."
    }

    // ------------------------------------------------------------- helpers

    private fun exec(command: String): Pair<Int, String> =
        try {
            val r = shell.exec(command)
            r.exitCode to r.output
        } catch (t: Throwable) {
            -1 to (t.message ?: t.javaClass.simpleName)
        }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    // ------------------------------------------------------ state plumbing

    private fun reset() {
        synchronized(lock) { lines = mutableListOf() }
        state = Attempt(busy = true)
    }

    private fun log(text: String) {
        synchronized(lock) {
            val stamped = "[${timestamp()}] $text"
            lines.add(stamped)
            if (lines.size > 400) {
                lines = lines.takeLast(400).toMutableList()
            }
        }
        state = state.copy(lines = lockedLines())
        postState()
    }

    private fun lockedLines(): List<String> = synchronized(lock) { lines.toList() }

    private fun running(transform: Attempt.() -> Attempt) {
        state = transform(state)
        postState()
    }

    private fun finish(outcome: Outcome, detail: String, fatal: String? = null) {
        if (fatal != null) log("fatal: $fatal")
        state = state.copy(outcome = outcome, detail = detail, phase = Phase.FINISHED, busy = false)
        log(detail)
        if ((outcome == Outcome.DONE || outcome == Outcome.MODULE_LOADED) && attemptBoot.isNotBlank()) {
            preferences.edit().putString("loaded_boot", attemptBoot).commit()
        }
        if (outcome != Outcome.NONE &&
            outcome != Outcome.WINDOW_ELAPSED &&
            outcome != Outcome.PARK_BURST &&
            outcome != Outcome.PARK_OTHER
        ) {
            if (cleanupRemoteArtifacts()) {
                log("cleaned staged artifacts from ${Target.REMOTE_DIR}")
            } else if (runCatching { shell.processAlive("vvlogd") }.getOrDefault(false)) {
                log("cleanup deferred: parked bootstrap still owns its files")
            }
            val archived = archiveRunnerLog(activeLog)
            if (archived != null) {
                activeLog = archived
                log("runner log archived to app-private storage")
            }
        }
        postState()
    }

    private fun postState() {
        val snapshot = state
        val previous = update
        main.post { previous?.invoke(snapshot); serviceUpdate?.invoke(snapshot) }
    }

    private fun post(state: Attempt) {
        val previous = update
        main.post { previous?.invoke(state) }
    }

    private fun timestamp(): String = synchronized(lock) {
        java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US)
            .format(java.util.Date())
    }

    private companion object {
        const val LOG_CAP: Int = 256 * 1024
    }
}
