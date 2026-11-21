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

A completed or refused attempt does not leave the staged payload names behind:
InfinityLock deletes the verified payloads, `ksu_stage.sh`, `ksu_slide`,
`kernelsu-p.ko`, trace/crash files, the `hkd_*` handshake files, `tempshell/`,
and the `.infinitylock` reservation once no `vvlogd` bootstrap is alive, and
again on every app start. A parked attempt keeps its files until the
user-consented reboot; the next app start after that removes the leftovers.
The boot-scoped `ksu-live.stamp` is kept only while it matches the current
boot, because the hidden-module gate needs it; a stamp from an earlier boot is
removed. The app's private `attempt_boot` preference keeps the one-attempt
rule even when temporary markers are gone.

Auto-root is optional. When enabled, InfinityLock starts at boot, waits for
Shizuku, then makes one checked attempt. It does not retry or reboot the phone.

## Never write to protected partitions

A temporary root shell is not permission to modify the system. On this device
the system partitions (`system`, `system_ext`, `vendor`, `product`, `odm`) and
the boot chain (`boot`, `init_boot`, `vbmeta`, `vbmeta_system`) are
write-protected and verified. Do not:

- remount any of them read-write, including `adb remount` or
  `mount -o rw,remount /` — a successful remount can allow subsequent
  commands to modify them;
- `dd`, `cp`, or flash an image into them, or patch files inside them
  (`build.prop`, init scripts, framework jars, APKs on `/system`);
- disable dm-verity, vbmeta verification, or verified boot to make a write stick.

Modifying a verified partition can cause AVB or dm-verity checks to fail and
prevent the device from booting. Use the root shell to run tools and inspect
the system, not to edit partitions. If any guide tells you to rw-remount a
partition on this phone, ignore it.

## Supported device and software

- Device: Vivo X200 Ultra, model V2454A, product PD2454.
- OS: OriginOS 7 / Android 17. Accepted exact product-version/kernel pairs:
  - `PD2454_A_17.2.13.3.W10` with `6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k`.
  - `PD2454_A_17.2.12.0.W10` with `6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k`.
  - `PD2454_A_17.2.11.5.W10` with `6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k`.
  - `PD2454_A_17.2.10.6.W10` with `6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k`.

The app refuses other kernel or firmware builds. A listed module alone does not
confirm that KernelSU is Live or that Manager can grant root. Verify its status
in KernelSU Manager after the attempt.

The manager library, timer bootstrap, function binder, insertion helper, and
KernelSU module are built from pinned sources by `build-payload.sh` and GitHub
Actions. The app does not store those generated binaries in the repository.
Payload sources: [PD2454 KernelSU runner](https://github.com/kailashrs/pd2454-kernelsu-runner)
and [the hardening branch of your KernelSU fork](https://github.com/kailashrs/KernelSU/tree/codex/pd2454-hardening).

The KernelSU source pin is `2dcd43b767ecfdc4dd082a57847f9fa82750d3cb`,
which keeps the quiet `allow_shell` notice and the removed hot-path printk
calls from `8b6585c`, and adds the `/proc/<pid>/attr/current` half of the
SELinux context oracle filter. ThreatCast's `app_zygote` preload asks the
kernel whether KernelSU's SELinux types exist by writing candidate contexts
and distinguishing `EINVAL` (type absent) from `EPERM` (type present); the
new filter collapses the KernelSU cases to `EINVAL`
(`docs/plans/selinux-context-oracle.md` in the fork). The earlier
checked-in carry patch stays retired, and `docs/plans/anti-timing-side-channel.md`
records why the syscall-hook timing channel is not the trigger.
`KSU_QUIET`, `KSU_HIDE_MODULE`, and `KSU_HIDE_SELINUX_ORACLE` are enabled.
Each built APK contains `payload/provenance.json` with the source commits,
patch digest, build options, and hashes of all staged payloads.

Loaded-state checks accept a live module-list entry or a successful root-side
`ksuquery`, under either the stock or the binder-renamed module identity. When Shizuku runs as UID 2000, the gated query is unavailable;
the check instead accepts the current-boot `ksu-live.stamp` written by the
runner after its root-side query succeeds. Stale stamps and modules still
initializing are not accepted as successful loads. The same check runs in
the final native launch gate. The query and status helpers are staged and
hash-verified before status checks; no bootstrap runs during a status refresh.
If the current-boot stamp is manually deleted, an unprivileged service loses
that loaded-state evidence. A bounded `su -c ksuquery` can recover visibility
when shell already has root access; denied or unavailable root access does not
count as successful detection. The app also saves its attempt's boot UUID in
private preferences, so deleting temporary markers does not enable a second
attempt from the same app installation in that boot.

The raw slide is written to `/data/local/tmp/ksu_slide` during an attempt and
removed by the post-verdict/next-start cleanup. It is never rewritten by staging
or status checks, and its presence never counts as loaded-state evidence. The
slide still belongs to one boot and one kernel. Awgpatch needs no
hardening-specific change; its separate slide record must still match the
running boot and kernel before loading the VPN module.

Debug logging is off by default. Enable it from the menu to add separate kernel/crash snapshots and trace files on the next attempt. The runner log is always retained.
