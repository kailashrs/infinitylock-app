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
- OS: OriginOS 7 / Android 17. Accepted exact product-version/kernel pairs:
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

The KernelSU source pin is `91b4edce51466818541060758a573378b9e260b9`,
with the checked-in `native/patches/quiet-shell-init.patch` applied before
compilation. This patch makes the routine `allow_shell` initialization message
an informational log, so quiet mode removes it while genuine alerts remain.
`KSU_QUIET`, `KSU_HIDE_MODULE`, and `KSU_HIDE_SELINUX_ORACLE` are enabled.
Each built APK contains `payload/provenance.json` with the source commits,
patch digest, build options, and hashes of all staged payloads.

Loaded-state checks accept a live module-list entry or a successful root-side
`ksuquery`. When Shizuku runs as UID 2000, the gated query is unavailable;
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

The raw slide remains at `/data/local/tmp/ksu_slide`. Neither staging nor status
checks delete or rewrite it, and its presence never counts as loaded-state
evidence. The slide still belongs to one boot and one kernel. Awgpatch needs
no hardening-specific change; its separate slide record must still match the
running boot and kernel before loading the VPN module.

Debug logging is off by default. Enable it from the menu to add separate kernel/crash snapshots and trace files on the next attempt. The runner log is always retained.
