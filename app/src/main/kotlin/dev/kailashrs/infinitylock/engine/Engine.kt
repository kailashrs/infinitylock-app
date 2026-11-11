package dev.kailashrs.infinitylock.engine

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import dev.kailashrs.infinitylock.shell.IShellService
import kotlin.concurrent.thread

/** Result classifier outputs — same set as the runner's classify(). */
enum class Outcome {
    NONE, REFUSED, MODULE_LISTED, DONE, COMPLETE_NO_KSU,
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
    val kernelMatch: Boolean get() = kernel == Target.KERNEL
    val productVersionMatch: Boolean get() = productVersion == Target.PRODUCT_VERSION

    val allClear: Boolean
        get() = bootId.matches(Regex("[0-9a-fA-F-]{36}")) && kernelMatch && productVersionMatch &&
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
 *  - sha256-verified staging of the five payloads (no manager APK)
 *  - exactly ONE detached (setsid) launch attempt; the exploit survives the
 *    app being killed
 *  - park-don't-kill: this code never kills or reaps anything; a parked
 *    process is cleaned up only by a user-consented reboot
 *  - never reboots without consent; classify mirrors the runner's markers
 */
class Engine(
    private val context: Context,
    private val shell: IShellService,
) {
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()
    private var serviceUpdate: ((Attempt) -> Unit)? = null
    fun observeService(callback: ((Attempt) -> Unit)?) { serviceUpdate = callback }
    private var update: ((Attempt) -> Unit)? = null
    private var lines = mutableListOf<String>()
    private val preferences = context.getSharedPreferences("runner", Context.MODE_PRIVATE)
    private var activeLog: String
        get() = preferences.getString("log", "")?.takeIf {
            it.matches(Regex("/sdcard/InfinityLock/infinitylock-run-[0-9-]+\\.log"))
        }.orEmpty()
        set(value) { preferences.edit().putString("log", value).commit() }
    @Volatile private var state = Attempt()

    // ------------------------------------------------------------------ api

    /** Snapshot gates so the UI can show them before anything runs. */
    fun refreshGates(onDone: (Gates) -> Unit) {
        thread(isDaemon = true) {
            val g = runCatching { readGates() }.getOrElse {
                Gates()
            }
            main.post { onDone(g) }
        }
    }

    /** Register a UI callback that receives every state transition. */
    fun observe(callback: (Attempt) -> Unit) {
        update = callback
        callback(state)
    }

    fun stopObserving() { update = null }

    /** Consent-gated reboot: the ONLY cleanup this app ever performs. */
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
        return Gates(
            kernel = kernel,
            productVersion = productVersion,
            ksuLoaded = shell.ksuModuleListed(),
            parkedProcess = shell.processAlive("ic98260"),
            attemptedThisBoot = bootId.isNotBlank() && shell.pathExists(bootMarkerPath(bootId)),
            bootId = bootId,
        )
    }

    private fun bootMarkerPath(bootId: String): String = "${Target.WORK_DIR}/attempt-$bootId"

    // ------------------------------------------------------------- attempt

    /** Run the single attempt. Enforces the fresh-boot rule itself. */
    fun runAttempt() {
        synchronized(lock) {
            if (state.busy) return
            state = state.copy(busy = true)
        }
        thread(isDaemon = true) {
            reset()
            // Set once staging begins; the finally below cleans artifacts on
            // every exit path that follows, while pre-staging refusals
            // (nothing of ours on disk yet) skip cleanup entirely.
            var stagingStarted = false
            try {
                // --- gates (mirror runner REFUSED paths) ---
                running { copy(phase = Phase.GATES, busy = true) }
                val gates = readGates()
                when {
                    !gates.bootId.matches(Regex("[0-9a-fA-F-]{36}")) || gates.kernel.isEmpty() || !gates.kernelMatch || !gates.productVersionMatch ->
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

                // --- staging: sha256-verified, mirrors ensure_binary ---
                running { copy(phase = Phase.STAGING) }
                stagingStarted = true
                for (p in Payload.entries) {
                    log("staging ${p.remoteName}")
                    if (stage(p) < 0) {
                        return@thread finish(
                            Outcome.REFUSED,
                            "staging failed; no exploit launched",
                            fatal = "write failed for ${p.remoteName}",
                        )
                    }
                    val actual = exec("sha256sum ${Target.REMOTE_DIR}/${p.remoteName}")
                        .second.trim().substringBefore(' ')
                    if (actual != p.sha256) {
                        return@thread finish(
                            Outcome.REFUSED,
                            "staging failed; no exploit launched",
                            fatal = "hash mismatch: ${p.remoteName}",
                        )
                    }
                }
                exec("rm -f ${Target.REMOTE_DIR}/ksupatch_neuter ${Target.REMOTE_DIR}/ksupatch_skip")
                log("all payloads sha256-verified; ksupatch markers cleared")

                // --- single detached launch, mirrors launch_attempt ---
                running { copy(phase = Phase.LAUNCHING) }
                log("launching one candidate-only attempt; this app never reboots the device")
                shell.mkdirs(Target.WORK_DIR, Target.MODE_0700)
                // Atomic per-boot reservation before launch, shared across app processes.
                val reserved = exec("mkdir ${bootMarkerPath(gates.bootId)}")
                if (reserved.first != 0) return@thread finish(Outcome.REFUSED, "This boot is already reserved; reboot before another attempt")
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
                        collectShellExposureEvidence()
                        finish(
                            Outcome.WINDOW_ELAPSED,
                            "Attempt window elapsed; exploit may still work in the background. " +
                                "No reboot, retry, or kill was performed.",
                        )
                            }

                    else -> {
                        val success = outcome == Outcome.DONE || outcome == Outcome.MODULE_LISTED
                        collectShellExposureEvidence()
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
            } finally {
                // Every exit path after staging began removes the identifiable
                // artifacts this app and the runner leave under /data/local/tmp.
                if (stagingStarted) cleanStagedArtifacts()
            }
        }
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

    // ------------------------------------------------------------ classify

    /** Non-blocking status probe; emits the classifier result to the UI. */
    fun classifyNow(onOutcome: (Outcome, String) -> Unit) {
        thread(isDaemon = true) {
            val o = classify()
            val note = describe(o)
            main.post { onOutcome(o, note) }
        }
    }

    /** Called on a background dispatcher; bounded tail of the actual runner output. */
    fun deviceLogSnapshot(): String = runCatching {
        activeLog.takeIf { it.isNotEmpty() }?.let { shell.readFile(it, LOG_CAP) }.orEmpty()
    }.getOrDefault("Runner log unavailable: shell disconnected")

    /**
     * Post-run artifact cleanup. Removes everything this app staged and the
     * runner produced under /data/local/tmp so no identifiable artifacts
     * (exploit binaries, module images, stage/handshake files, liveness
     * stamp, evidence files) outlive the attempt. Safety rules:
     *  - never touches a live runner: the hkd_* handshake files are
     *    load-bearing while ic98260 is still working, so cleanup waits
     *    (bounded, 60s) for it to exit and skips with a log line otherwise;
     *    nothing is ever killed;
     *  - keeps the per-boot reservation under WORK_DIR, which is what
     *    prevents a second attempt on this boot;
     *  - removes ksud only when no ksud process is running;
     *  - removes the boot stamp, so later liveness re-checks report
     *    not-loaded after cleanup; KernelSU Manager remains the source of
     *    truth once an attempt has ended.
     */
    private fun cleanStagedArtifacts() {
        runCatching {
            var waits = 0
            while (waits < 12 && exec("pidof ic98260").second.trim().isNotEmpty()) {
                Thread.sleep(5_000)
                waits++
            }
            if (exec("pidof ic98260").second.trim().isNotEmpty()) {
                log("artifact cleanup skipped: runner still active")
                return
            }
            val ksudRunning = exec("pidof ksud").second.trim().isNotEmpty()
            val names = mutableListOf(
                "ic98260", "ksupatch", "insmodf", "ksuquery", "ksu_exposure_probe",
                "kernelsu.ko", "kernelsu-p.ko", "run.sh", "ksu_stage.sh", "ksu_slide",
                "ksu-live.stamp", "ksu-exposure-root.txt", "ksu-trace.log", "iq.log",
                "hkd_base", "hkd_go", "hkd_open", "hkd_extras",
                "ksupatch_neuter", "ksupatch_skip", "kmsg-this-boot.txt",
            )
            if (!ksudRunning) names.add("ksud")
            val targets = names.joinToString(" ") { "${Target.REMOTE_DIR}/$it" } +
                " ${Target.REMOTE_DIR}/pstore*.bin"
            exec("rm -f $targets")
            log("staged artifacts cleaned (${names.size} entries; ksud kept=$ksudRunning)")
        }
    }

    private fun classify(): Outcome {
        if (!shell.asBinder().isBinderAlive) return Outcome.CRASH_INCOMPLETE
        if (shell.ksuModuleListed()) return Outcome.MODULE_LISTED
        val text = activeLog.takeIf { it.isNotEmpty() }?.let { shell.readFile(it, LOG_CAP) }.orEmpty().replace("\r", "")
        return classifyLog(text) { shell.processAlive("ic98260") }
    }

    /**
     * Post-attempt evidence from this shell context. Note the identity
     * caveat: the runner inserts KernelSU with allow_shell=1, so the
     * Shizuku shell (uid 2000) is an AUTHORIZED caller of the gated fd
     * handshake — this matrix shows an authorized-shell view (a driver fd
     * and version here are expected), not unprivileged-app denial. The
     * stage also restores SELinux enforcing only after stamping liveness,
     * so enforcement is confirmed (bounded wait) first and its state is
     * recorded in the evidence header; a still-permissive system is
     * explicitly labeled transitional. Collection failures are non-fatal.
     */
    private fun collectShellExposureEvidence() {
        runCatching {
            var enforcing = false
            var waits = 0
            while (waits < 15) {
                if (exec("getenforce").second.trim().equals("Enforcing", ignoreCase = true)) {
                    enforcing = true
                    break
                }
                Thread.sleep(2_000)
                waits++
            }
            val transitional = if (enforcing) "" else " TRANSITIONAL"
            exec(
                "echo \"context=authorized_shell enforcement=\$(getenforce)$transitional\" " +
                    "> /sdcard/InfinityLock/infinitylock-exposure-shell.txt; " +
                    "/data/local/tmp/ksu_exposure_probe " +
                    ">> /sdcard/InfinityLock/infinitylock-exposure-shell.txt 2>&1",
            )
        }
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
        Outcome.MODULE_LISTED, Outcome.DONE ->
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
