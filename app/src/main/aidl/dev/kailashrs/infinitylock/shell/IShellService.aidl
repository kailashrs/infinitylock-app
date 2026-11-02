package dev.kailashrs.infinitylock.shell;

import android.os.ParcelFileDescriptor;
import dev.kailashrs.infinitylock.shell.ExecResult;

/**
 * Privileged primitives exposed by the Shizuku user service.
 *
 * The service runs inside the Shizuku server process, so it executes with the
 * same uid/secontext as ADB (shell, uid 2000) or root (uid 0) — exactly the
 * context the validated pd2454 runner assumes. All exploitation decision logic
 * (gates, staging order, classify) lives in the app; this interface only
 * provides syscall-shaped primitives.
 */
interface IShellService {

    // Reserved by the Shizuku server. Must not be re-numbered.
    void destroy() = 16777114;

    void exit() = 1;

    // ---- user methods ----

    /** Run `/system/bin/sh -c <command>` with merged stdout+stderr. */
    ExecResult exec(in String command) = 2;

    /** Cheap, dependency-free "is the parked exploit process alive" check (pgrep -f). */
    boolean processAlive(in String pattern) = 3;

    /** Whether the KernelSU module is listed in /proc/modules. */
    boolean ksuModuleListed() = 4;

    /**
     * Stream a file from the app (parcelable pipe) into `dir/name`, created with
     * `mode` (posix bits, e.g. 0755 = 493). Returns bytes written, or -1 on failure.
     */
    long writeStream(in ParcelFileDescriptor pfd, in String dir, in String name, in int mode) = 5;

    /** Read at most maxBytes of a file as UTF-8; "" if missing. */
    String readFile(in String path, in int maxBytes) = 6;

    /** Write text content to dir/name with mode. */
    void writeFile(in String dir, in String name, in int mode, in String content) = 7;

    boolean pathExists(in String path) = 8;

    void mkdirs(in String dir, in int mode) = 9;
}
