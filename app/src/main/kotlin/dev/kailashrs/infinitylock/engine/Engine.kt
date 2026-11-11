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
            // True once run.sh launched the runner. Terminal-state helper:
            // cleans staged artifacts (when safe for this outcome) BEFORE
            // publishing the final state, so a follow-up attempt can never
            // race the cleanup, and the foreground service stays up until
            // the attempt lifecycle - including cleanup - is complete.
            var launchedOk = false
            fun finishCleaning(outcome: Outcome, message: String, fatal: String? = null) {
                val finalOutcome = cleanStagedArtifacts(outcome) { launchedOk }
                // Cleanup can release a parked runner whose finalize stage
                // then loads KernelSU; report that instead of the stale park.
                val finalMessage = if (finalOutcome == outcome) {
                    message
                } else {
                    "Module detected during cleanup; stopped without reboot. " +
                        "Manager and probe behavior still require manual validation."
                }
                finish(finalOutcome, finalMessage, fatal)
            }
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
                for (p in Payload.entries) {
                    log("staging ${p.remoteName}")
                    if (stage(p) < 0) {
                        return@thread finishCleaning(
                            Outcome.REFUSED,
                            "staging failed; no exploit launched",
                            fatal = "write failed for ${p.remoteName}",
                        )
                    }
                    val actual = exec("sha256sum ${Target.REMOTE_DIR}/${p.remoteName}")
                        .second.trim().substringBefore(' ')
                    if (actual != p.sha256) {
                        return@thread finishCleaning(
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
                if (reserved.first != 0) return@thread finishCleaning(Outcome.REFUSED, "This boot is already reserved; reboot before another attempt")
                val logPath = "/sdcard/InfinityLock/infinitylock-run-${java.text.SimpleDateFormat("yyyyMMdd-HHmmss-SSS", java.util.Locale.US).format(java.util.Date())}.log"
                val prepared = exec("mkdir -p /sdcard/InfinityLock && (set -C; : > $logPath)")
                if (prepared.first != 0) return@thread finishCleaning(Outcome.REFUSED, "Cannot create runner log on shared storage; no attempt launched")
                activeLog = logPath
                val debugFlag = if (context.getSharedPreferences("settings", Context.MODE_PRIVATE).getBoolean("debug_logging", false)) "--debug " else ""
                val launched = exec(
                    "sh ${Target.REMOTE_DIR}/run.sh $debugFlag${shellQuote(logPath)}",
                )
                if (launched.first != 0) return@thread finishCleaning(
                    Outcome.REFUSED,
                    "Launch failed; boot reservation retained for recovery",
                    fatal = launched.second.trim(),
                )
                launchedOk = true
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
                        finishCleaning(
                            Outcome.WINDOW_ELAPSED,
                            "Attempt window elapsed; exploit may still work in the background. " +
                                "No reboot, retry, or kill was performed.",
                        )
                            }

                    else -> {
                        val success = outcome == Outcome.DONE || outcome == Outcome.MODULE_LISTED
                        collectShellExposureEvidence()
                        finishCleaning(
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
                val detail = "attempt aborted: ${t.message ?: t.javaClass.simpleName}"
                if (launchedOk) {
                    // A runner may still be working after launch; never delete
                    // under it. Artifacts remain until the next boot.
                    finish(Outcome.CRASH_INCOMPLETE, detail, fatal = t.toString())
                } else {
                    // Nothing was launched, so the staged payloads are ours to
                    // remove.
                    finishCleaning(Outcome.REFUSED, detail, fatal = t.toString())
                }
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
     * stamp, evidence files) outlive the attempt.
     *
     * Completion is decided by the ATTEMPT OUTCOME, not process liveness:
     * the runner parks forever (pause()) even after success to hold its
     * credential pages, so a pidof wait would never terminate. Policy:
     *  - WINDOW_ELAPSED / CRASH_INCOMPLETE: the runner may still be working
     *    (or the shell is gone); cleanup is skipped and logged - artifacts
     *    remain until the next boot. Nothing is ever killed or reaped.
     *  - terminal outcomes (module live, parked, finalize-complete) and
     *    launch refusals: the runner either never started or has reached a
     *    terminal marker; a short grace after a real launch lets it flush
     *    its last log lines, then cleanup waits for proof that its child
     *    finished the post-handshake finalize stage before removing
     *    anything. If that proof never arrives, artifacts remain.
     *  - the per-boot reservation under WORK_DIR is KEPT: it is what
     *    prevents a second attempt on this boot.
     *  - ksud is removed only when no ksud process is running.
     *  - the boot stamp is removed, so later liveness re-checks report
     *    not-loaded; KernelSU Manager remains the source of truth once an
     *    attempt has ended.
     */
    private fun cleanStagedArtifacts(outcome: Outcome, launched: () -> Boolean): Outcome {
        var finalOutcome = outcome
        runCatching {
            when (outcome) {
                Outcome.WINDOW_ELAPSED, Outcome.CRASH_INCOMPLETE -> {
                    log("artifact cleanup skipped for $outcome: runner state uncertain; artifacts remain until reboot")
                    return@runCatching
                }
                else -> {}
            }
            val didLaunch = launched()
            // A refused launch can race with another runner that appeared
            // after the gates but before run.sh: its refusal leaves that
            // runner's payloads and handshake files in place. Never delete
            // shared artifacts we do not own.
            if (!didLaunch && shell.processAlive("ic98260")) {
                log("artifact cleanup skipped: another runner owns the staged files")
                return@runCatching
            }
            // The parked parent never touches files again, but a freshly
            // finished one may still be flushing its final log lines.
            if (didLaunch) Thread.sleep(10_000)
            // The privileged child runs a finalize stage (ksud late-load,
            // module verification, SELinux restore) after the hkd handshake
            // and may still hold the payloads. Wait for its terminal marker
            // before deleting anything, and fail closed if the log is
            // unreadable or the child does not confirm.
            if (didLaunch && shell.processAlive("ic98260")) {
                if (!awaitRunnerFileWorkDone()) {
                    log("artifact cleanup skipped: runner did not confirm file work finished; artifacts remain until reboot")
                    return@runCatching
                }
                // Releasing a parked child can let its finalize stage load
                // KernelSU. Classify now, while ksu-live.stamp still exists,
                // so the attempt reports what cleanup actually enabled.
                val refreshed = classify()
                if (refreshed == Outcome.MODULE_LISTED || refreshed == Outcome.DONE) {
                    if (refreshed != finalOutcome) {
                        log("outcome refreshed: $finalOutcome -> $refreshed after runner completed")
                    }
                    finalOutcome = refreshed
                }
            }
            val ksudRunning = exec("pidof ksud").second.trim().isNotEmpty()
            val names = mutableListOf(
                "ic98260", "ksupatch", "insmodf", "ksuquery", "ksu_exposure_probe",
                "kernelsu.ko", "kernelsu-p.ko", "run.sh", "ksu_stage.sh", "ksu_slide",
                "ksu-live.stamp", "ksu-exposure-root.txt", "ksu-trace.log", "iq.log",
                "hkd_base", "hkd_go", "hkd_go.tmp", "hkd_open", "hkd_extras",
                "ksupatch_neuter", "ksupatch_skip", "kmsg-this-boot.txt",
            )
            if (!ksudRunning) names.add("ksud")
            val targets = names.joinToString(" ") { "${Target.REMOTE_DIR}/$it" } +
                " ${Target.REMOTE_DIR}/pstore*.bin"
            val rm = exec("rm -f $targets")
            if (rm.first == 0) {
                log("staged artifacts cleaned (${names.size} entries; ksud kept=$ksudRunning)")
            } else {
                log("artifact cleanup FAILED rc=${rm.first}: ${rm.second.trim().take(200)}")
            }
        }
        return finalOutcome
    }

    /**
     * Wait until the runner can no longer touch the staged files.
     *
     * The privileged child runs a finalize stage (ksud late-load, module
     * verification, SELinux restore) after the hkd handshake and exits only
     * afterwards, so the handshake markers alone are not terminal. A
     * burst-miss park can also happen while that child is still polling
     * hkd_go for up to an hour; in that case the parent cannot send the
     * protocol's release marker and we send it instead.
     *
     * Returns true only when a terminal marker proves no more file work
     * remains. An unreadable or still-empty log is uncertain and returns
     * false, so the caller keeps the artifacts until reboot. A parked child
     * or a non-zero child exit is not enough on its own: the parent can
     * still be writing handshake files, or a detached stage worker can
     * survive the child.
     */
    private fun awaitRunnerFileWorkDone(): Boolean {
        val logPath = activeLog
        if (logPath.isEmpty()) return false

        fun snapshot(): String? =
            runCatching { shell.readFile(logPath, LOG_CAP) }.getOrNull()?.takeIf { it.isNotEmpty() }

        fun parentParked(text: String): Boolean =
            text.lineSequence().any { it.contains("parking without reap") && !it.contains("child:") }

        // Raw waitpid status in %#x form. The low seven bits are the signal
        // number: zero means the process exited on its own (any exit code),
        // which lets the shell reap its foreground helpers. Nonzero means it
        // was killed and could have left an orphan behind.
        fun statusOk(token: String): Boolean {
            val status = token.removePrefix("0x").toULongOrNull(16) ?: return false
            return (status and 0x7fUL) == 0UL
        }

        // A stage worker is setsid()-detached and a killed shell can leave a
        // helper behind. Only a worker that exited on its own proves it
        // reaped its foreground helpers.
        fun workersClean(text: String): Boolean =
            Regex("""ksu stage \(\S+\) worker exit=(\S+)""")
                .findAll(text).all { statusOk(it.groupValues[1]) }

        fun finalizeClean(text: String): Boolean {
            val status = Regex("""ksu stage \(finalize\) worker exit=(\S+)""")
                .findAll(text).lastOrNull()?.groupValues?.get(1) ?: return false
            if (!statusOk(status)) return false
            // run_ksu_stage_worker() logs the marker and then calls
            // module_listed(), which reads ksu-live.stamp. Wait for the
            // child's post-check daemon line before removing that stamp.
            return text.contains("[fake] KernelSU Live; stopping fallback daemon") ||
                text.contains("[fake] module not listed; fallback daemon")
        }

        fun childExitedCleanly(text: String): Boolean {
            val status = Regex("""\[\+\] child exit status=(\S+)""")
                .findAll(text).lastOrNull()?.groupValues?.get(1) ?: return false
            return statusOk(status)
        }

        fun finished(text: String): Boolean =
            // A clean child exit means the child was not killed; a worker
            // that was killed keeps the artifacts.
            (childExitedCleanly(text) && workersClean(text)) ||
                (text.contains("[+] done") && workersClean(text)) ||
                // A parent park ends the handshake; releasing the child with
                // END lets it run finalize, whose completed worker is its
                // last file work. An earlier killed worker still keeps the
                // artifacts.
                (parentParked(text) && workersClean(text) && finalizeClean(text)) ||
                // A burst miss before the child is armed leaves it blocked.
                (text.contains("burst miss") && !text.contains("hkd:"))

        var text = snapshot() ?: return false
        if (finished(text)) return true

        // The child unlinks hkd_go even after a zero-byte read, so a
        // truncate-then-write marker can be lost. Publish it with rename(2)
        // and republish on later polls until the log confirms receipt.
        fun releaseParkedParent(now: String) {
            if (!parentParked(now)) return
            exec(
                "printf END > ${Target.REMOTE_DIR}/hkd_go.tmp && " +
                    "mv -f ${Target.REMOTE_DIR}/hkd_go.tmp ${Target.REMOTE_DIR}/hkd_go",
            )
        }
        releaseParkedParent(text)

        val deadline = System.currentTimeMillis() + 180_000
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(500)
            text = snapshot() ?: continue
            if (finished(text)) return true
            releaseParkedParent(text)
        }
        return false
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
