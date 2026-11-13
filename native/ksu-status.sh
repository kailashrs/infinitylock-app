#!/system/bin/sh
# Read-only loaded-state check, shared by the app and final launch gate.
# UID 2000 cannot use GET_INFO under hardening. The root-side runner writes
# ksu-live.stamp only after its gated ksuquery succeeds.
set -u

if grep -q '^kernelsu .* Live ' /proc/modules 2>/dev/null; then
    exit 0
fi
# A visible module still initializing/going away is not an absent module.
if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
    exit 2
fi

if [ "$(id -u)" = 0 ] && [ -x /data/local/tmp/ksuquery ]; then
    result=$(/data/local/tmp/ksuquery 2>/dev/null) || exit 2
    printf '%s\n' "$result" | grep -q '^KSU_VERSION=[1-9][0-9]* .*uid=0$' || exit 2
    exit 0
fi

boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || exit 2
case "$boot" in
    ????????-????-????-????-????????????) ;;
    *) exit 2 ;;
esac
stamp=$(cat /data/local/tmp/ksu-live.stamp 2>/dev/null || true)
[ "$stamp" = "$boot" ] && exit 0

# Recover loaded-state visibility after temporary files were cleaned, if
# shell already has su access. Only this short-lived read-only probe can
# time out; no bootstrap process is signalled or launched here.
if [ -x /data/local/tmp/ksuquery ]; then
    result=$(timeout 3 su -c /data/local/tmp/ksuquery </dev/null 2>/dev/null) || exit 1
    printf '%s\n' "$result" | grep -q '^KSU_VERSION=[1-9][0-9]* .*uid=0$' && exit 0
fi
exit 1
