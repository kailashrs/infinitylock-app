# InfinityLock

InfinityLock attempts to gain temporary root on the supported Vivo X200 Ultra
(PD2454) by exploiting CVE-2026-98260, then loads KernelSU. It requires Shizuku
to run the exploit with shell access and the official KernelSU Manager to be
installed for KernelSU's manager and `ksud` integration.

## What it does

1. Checks that the device's kernel and firmware match the supported build.
2. Runs the POSIX CPU timer race to obtain a privileged shell for this boot.
3. Uses the shell to discover the current boot's kernel slide, bind the matched
   KernelSU module's private function imports, and insert it with flags zero.
4. Shows the runner's live `iq.log` in Diagnostics.

Root is temporary and the module stays pinned until reboot. Each boot permits
one attempt. A failed attempt can leave parked exploit processes; do not kill or
reap them. Reboot to recover. The attempt can also crash or restart the phone.

Auto-root is optional. When enabled, InfinityLock starts at boot, waits for
Shizuku, then makes one checked attempt. It does not retry or reboot the phone.

## Supported device and software

- Device: Vivo X200 Ultra, model V2454A, product PD2454.
- OS: OriginOS 7, software version `PD2454B_A_17.2.10.6.W10`
  (`ro.vivo.os.version` reports `17.0`), based on Android 17.
- Firmware check: `ro.vivo.system.product.version` must be `PD2454_A_17.2.10.6.W10`.
- Kernel: `6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k`.

The app refuses other kernel or firmware builds. A listed module alone does not
confirm that KernelSU is Live or that Manager can grant root. Verify its status
in KernelSU Manager after the attempt.

The manager library, timer bootstrap, function binder, insertion helper, and
KernelSU module are built from pinned sources by `build-payload.sh` and GitHub
Actions. The app does not store those generated binaries in the repository.
Payload sources: [PD2454 KernelSU runner](https://github.com/kailashrs/pd2454-kernelsu-runner/tree/hardening-validation)
and [your KernelSU fork](https://github.com/kailashrs/KernelSU/tree/codex/pd2454-hardening).

Since 1.1.0-rc.2 the payload uses the anti-fingerprinting module profile
(`CONFIG_KSU_QUIET=y CONFIG_KSU_HIDE_MODULE=y
CONFIG_KSU_HIDE_SELINUX_ORACLE=y`): routine module logging is compiled out,
the module unlinks itself from `/proc/modules` and kallsyms after init, the
supercall fd handshake answers only authorized callers, and the app_zygote
selinuxfs policy oracles are closed (`compute_av` is denied and a
`sel_write_context` kprobe rejects `ksu`/`ksu_*` contexts from non-root
callers) so an isolated detector process cannot test for KernelSU's SELinux
types or AVC rules. Because a hidden module no longer appears in
`/proc/modules`, liveness is verified through the gated-supercall probe
(`ksuquery`) and a boot-scoped
`ksu-live.stamp`; the unprivileged `ksu_exposure_probe` matrix is collected
as attempt evidence.

After each attempt the app removes the artifacts it and the runner leave
under `/data/local/tmp` (exploit binaries, module images, stage and
handshake files, the liveness stamp, evidence files). Cleanup is driven by
the attempt outcome - the runner parks forever even after success, so
process liveness is not a completion signal: terminal outcomes (module
loaded, parked, finalize-complete) and launch refusals clean up after a
short grace, while WINDOW_ELAPSED and crashed attempts skip cleanup (the
runner may still be working; nothing is ever killed or reaped) and leave
artifacts until the next boot. The per-boot attempt reservation is kept;
KernelSU Manager remains the source of truth for module status once an
attempt has ended.

Debug logging is off by default. Enable it from the menu to add separate kernel/crash snapshots and trace files on the next attempt. The runner log is always retained.
