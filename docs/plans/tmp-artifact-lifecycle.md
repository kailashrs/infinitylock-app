# `/data/local/tmp` artifact lifecycle

## Why it is used

Shizuku runs the shell service as UID 2000. Before root, the only path that is
both shell-writable and `exec`-capable is `/data/local/tmp`; app-private
storage is not writable by the shell service and is not a valid payload
location.

## Current lifecycle (rc.8)

| Phase | On-disk state |
|---|---|
| Idle | No staged payloads. Status helpers are staged only around a gate check and deleted when no `vvlogd` is running. |
| Attempt running | Payloads, `ksu_stage.sh`, `ksu_slide`, `kernelsu-p.ko`, trace/crash files and handshake files are present. |
| Terminal verdict, no `vvlogd` | The staged payloads, runtime artifacts, `hkd_*`, `pstore*.bin`, `ksu_stage.sh`, `ksu_slide`, `kernelsu-p.ko`, `tempshell/`, `.infinitylock/` and `ksu-live.stamp` are removed. Runner logs are moved to app-private storage and the public copy is deleted. |
| Parked `vvlogd` | Files stay until the consented reboot; the next app start after reboot removes them. The parked process name remains visible in `/proc` until reboot. |

The loaded-state marker for a hidden module is the private `loaded_boot`
preference, not the public stamp. The one-attempt rule is the private
`attempt_boot` preference.

## Remaining exposure

1. During an active attempt the full staged set exists in `/data/local/tmp`. A
   concurrent scanner can enumerate it.
2. A parked `vvlogd` leaves both the files and the process name until reboot.
3. If the runner takes its fallback root-provider path it mounts a tmpfs at
   `/apex/com.android.virt/bin` and copies a `su` binary there. That mount is
   root-managed, visible in mountinfo, and persists until reboot.
4. App-private logs and preferences are not reachable by ordinary apps, but
   root can read them.

## Options for not persisting at all

1. **Randomized work directory + unlink the bootstrap immediately.** Stage
   under a per-attempt random directory, start `vvlogd` from it, wait until
   `/proc/<pid>/exe` confirms the exec, then unlink the bootstrap. The process
   keeps the inode; a scanner no longer sees the binary. The remaining payload
   files still stay until the verdict/cleanup.
2. **Root-only tmpfs for the post-root payloads.** After `vvlogd` obtains root,
   mount a small tmpfs, move `ksupatch`/`insmodf`/`kernelsu.ko`/`ksud` into it,
   update `ksu_stage.sh`, unlink the originals, run the stage, then unmount and
   remove the directory. The bootstrap and its initial log still touch
   `/data/local/tmp` briefly.
3. **Pathless execution with memfd/`execveat` and `finit_module` fds.** Refactor
   the runner so binaries and the module are passed as file descriptors and
   never get a filesystem path. This removes the staged-path exposure but is a
   substantial runner change.
4. **Remove or retire the APEX `su` fallback.** Either drop the fallback when
   the module load path is sufficient, or `umount` the tmpfs and stop the
   daemon after a successful module load. This needs a payload change and a
   fallback-root test.

## Recommendation

Implement option 1 first (small `run.sh` change, no kernel work). Then pair it
with option 2 so the post-root payload set is captured in a tmpfs. Keep option
3 as the long-term target and treat the APEX fallback as a separate hardening
item. Until then, a parked attempt is cleaned by the consented reboot followed
by the next app start.
