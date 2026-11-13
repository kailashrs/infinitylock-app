#!/system/bin/sh
# InfinityLock's on-device, one-attempt entrypoint. The host runner owns
# parameterized multi-boot retries because its ADB controller reconnects.
set -eu

DEBUG=0
if [ "${1:-}" = --debug ]; then DEBUG=1; shift; fi
LOG_PATH=${1:?usage: run.sh [--debug] <runner-log-path>}
case "$LOG_PATH" in
    /sdcard/InfinityLock/infinitylock-run-*.log) ;;
    *) echo 'invalid runner log path' >&2; exit 2 ;;
esac
# Accepted (kernel release, vivo product version) pairs, newest first.
# A mixed pair (e.g. new kernel on old firmware) must still refuse.
KERNEL=
PRODUCT_VERSION=
FW_OK=0
for PAIR in \
    '6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k;PD2454_A_17.2.12.0.W10' \
    '6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k;PD2454_A_17.2.11.5.W10' \
    '6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k;PD2454_A_17.2.10.6.W10'
do
    K=${PAIR%%;*}
    V=${PAIR#*;}
    if [ "$(uname -r 2>/dev/null || true)" = "$K" ] &&
       [ "$(getprop ro.vivo.system.product.version 2>/dev/null || true)" = "$V" ]
    then
        FW_OK=1
        break
    fi
done
[ "$FW_OK" = 1 ] || { echo 'REFUSED exact kernel or firmware mismatch'; exit 2; }
WORK=/data/local/tmp/.infinitylock
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
case "$BOOT" in ????????-????-????-????-????????????) ;; *) echo 'REFUSED invalid boot ID'; exit 2;; esac
[ -x /data/local/tmp/ksu-status.sh ] || { echo 'REFUSED loaded-state helper missing'; exit 2; }
status=0
sh /data/local/tmp/ksu-status.sh || status=$?
[ "$status" -le 1 ] || { echo 'REFUSED loaded state unavailable'; exit 2; }
if [ "$status" -eq 0 ] || pidof ic98260 >/dev/null 2>&1; then
    echo 'REFUSED KernelSU or runner already present; clean boot required'
    exit 2
fi
# Engine atomically reserves this boot before invoking the app runner.
[ -d "$WORK/attempt-$BOOT" ] || { echo 'REFUSED boot was not reserved by InfinityLock'; exit 2; }
[ -x /data/local/tmp/ic98260 ] && [ -x /data/local/tmp/ksupatch ] &&
[ -x /data/local/tmp/insmodf ] && [ -s /data/local/tmp/kernelsu.ko ] || {
    echo 'REFUSED staged payload missing'
    exit 2
}
mkdir -p /sdcard/InfinityLock || { echo 'REFUSED cannot create log folder'; exit 2; }
touch "$LOG_PATH" || { echo 'REFUSED cannot open runner log'; exit 2; }
rm -f /data/local/tmp/hkd_base /data/local/tmp/hkd_go /data/local/tmp/hkd_open
KSU_RUNNER_DEBUG=$DEBUG setsid /data/local/tmp/ic98260 fake >>"$LOG_PATH" 2>&1 </dev/null &
PID=$!
echo "RUNNER_STARTED pid=$PID boot=$BOOT log=$LOG_PATH"
