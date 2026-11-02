#!/system/bin/sh
# InfinityLock's on-device, one-attempt entrypoint. The host runner owns
# parameterized multi-boot retries because its ADB controller reconnects.
set -eu

LOG_PATH=${1:?usage: run.sh <runner-log-path>}
case "$LOG_PATH" in
    /sdcard/InfinityLock/infinitylock-run-*.log) ;;
    *) echo 'invalid runner log path' >&2; exit 2 ;;
esac
KERNEL=6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
FINGERPRINT=vivo/PD2454/PD2454:17/CP2A.260605.016_V000L1/261030013318:user/release-keys
WORK=/data/local/tmp/.infinitylock
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
case "$BOOT" in ????????-????-????-????-????????????) ;; *) echo 'REFUSED invalid boot ID'; exit 2;; esac
[ "$(uname -r 2>/dev/null || true)" = "$KERNEL" ] || { echo 'REFUSED kernel mismatch'; exit 2; }
[ "$(getprop ro.build.fingerprint 2>/dev/null || true)" = "$FINGERPRINT" ] || { echo 'REFUSED firmware mismatch'; exit 2; }
if grep -q '^kernelsu ' /proc/modules 2>/dev/null || pidof ic98260 >/dev/null 2>&1; then
    echo 'REFUSED KernelSU or runner already present; clean boot required'
    exit 2
fi
mkdir -p "$WORK" || { echo 'REFUSED cannot create per-boot guard'; exit 2; }
mkdir "$WORK/attempt-$BOOT" 2>/dev/null || { echo 'REFUSED attempt already reserved this boot'; exit 2; }
[ -x /data/local/tmp/ic98260 ] && [ -x /data/local/tmp/ksupatch ] &&
[ -x /data/local/tmp/insmodf ] && [ -s /data/local/tmp/kernelsu.ko ] || {
    echo 'REFUSED staged payload missing'
    exit 2
}
mkdir -p /sdcard/InfinityLock || { echo 'REFUSED cannot create log folder'; exit 2; }
touch "$LOG_PATH" || { echo 'REFUSED cannot open runner log'; exit 2; }
rm -f /data/local/tmp/hkd_base /data/local/tmp/hkd_go /data/local/tmp/hkd_open
setsid /data/local/tmp/ic98260 fake >>"$LOG_PATH" 2>&1 </dev/null &
PID=$!
echo "RUNNER_STARTED pid=$PID boot=$BOOT log=$LOG_PATH"
