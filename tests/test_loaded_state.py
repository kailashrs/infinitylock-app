"""Replay the real status/launch scripts against isolated proc/payload fixtures."""
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BOOT = "01234567-89ab-cdef-0123-456789abcdef"

with tempfile.TemporaryDirectory(prefix="infinitylock-status-") as temp:
    base = Path(temp)
    remote = base / "remote"
    remote.mkdir()
    mocks = base / "bin"
    mocks.mkdir()
    modules = base / "modules"
    boot = base / "boot_id"
    boot.write_text(BOOT + "\n")
    calls = base / "calls"

    def executable(path, text):
        path.write_text("#!/bin/sh\n" + text)
        path.chmod(0o755)

    executable(mocks / "id", 'echo "$TEST_UID"\n')
    executable(mocks / "timeout", 'shift\nexec "$@"\n')
    executable(mocks / "su", 'echo su >> "$TEST_CALLS"\n[ "$SU_RC" = 0 ] || exit 1\nprintf "%s\\n" "$QUERY_REPLY"\n')
    executable(remote / "ksuquery", 'echo query >> "$TEST_CALLS"\n[ "$QUERY_RC" = 0 ] || exit 1\nprintf "%s\\n" "$QUERY_REPLY"\n')
    status = (ROOT / "native/ksu-status.sh").read_text()
    status = status.replace("/proc/modules", str(modules))
    status = status.replace("/proc/sys/kernel/random/boot_id", str(boot))
    status = status.replace("/data/local/tmp", str(remote))
    (remote / "ksu-status.sh").write_text(status)
    (remote / "ksu-status.sh").chmod(0o755)
    env = os.environ | {
        "PATH": str(mocks) + os.pathsep + os.environ["PATH"],
        "TEST_UID": "2000", "TEST_CALLS": str(calls),
        "QUERY_RC": "0", "SU_RC": "1", "QUERY_REPLY": "KSU_VERSION=32680 flags=0x5 features=1 uapi=5 uid=0",
    }

    def check(label, listed, stamp, uid, expected, **extra):
        modules.write_text(listed)
        marker = remote / "ksu-live.stamp"
        if stamp is None:
            marker.unlink(missing_ok=True)
        else:
            marker.write_text(stamp + "\n")
        calls.write_text("")
        result = subprocess.run(["sh", str(remote / "ksu-status.sh")], env=env | {"TEST_UID": uid} | extra)
        assert result.returncode == expected, (label, result.returncode)
        if uid == "2000":
            assert "query" not in calls.read_text().splitlines(), "unprivileged status must not directly query the gated ioctl"
        print("PASS:", label)

    check("visible live module", "kernelsu 100 0 - Live 0\n", None, "2000", 0)
    check("initializing is inconclusive and blocks another load", "kernelsu 100 0 - Loading 0\n", None, "2000", 2)
    check("hidden current-boot module", "", BOOT, "2000", 0)
    check("stale stamp refused", "", "11234567-89ab-cdef-0123-456789abcdef", "2000", 1)
    check("missing stamp is not success", "", None, "2000", 1)
    check("existing root grant recovers a cleaned stamp", "", None, "2000", 0, SU_RC="0")
    check("root supercall succeeds without stamp", "", None, "0", 0)
    check("root ioctl failure is inconclusive despite stamp", "", BOOT, "0", 2, QUERY_RC="1")
    check("zero version is inconclusive", "", None, "0", 2, QUERY_REPLY="KSU_VERSION=0 flags=0 features=0 uapi=0 uid=0")
    boot.write_text("\n")
    check("missing boot identity is inconclusive", "", "", "2000", 2)
    boot.write_text(BOOT + "\n")

    # Exercise the final pre-launch gate too, with no real exploit execution.
    executable(mocks / "uname", 'echo 6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k\n')
    executable(mocks / "getprop", 'echo PD2454_A_17.2.11.5.W10\n')
    executable(mocks / "pidof", 'exit 1\n')
    executable(mocks / "setsid", 'touch "$TEST_LAUNCH"\n')
    for name in ("ic98260", "ksupatch", "insmodf", "kernelsu.ko"):
        executable(remote / name, "exit 99\n")
    (remote / ".infinitylock" / ("attempt-" + BOOT)).mkdir(parents=True)
    slide = remote / "ksu_slide"
    slide.write_text("1706400000\n")
    shared = base / "shared"
    launcher = (ROOT / "native/run.sh").read_text()
    launcher = launcher.replace("/data/local/tmp", str(remote)).replace("/proc/sys/kernel/random/boot_id", str(boot))
    launcher = launcher.replace("/sdcard/InfinityLock", str(shared))
    launch_script = base / "run.sh"
    launch_script.write_text(launcher)
    launch_flag = base / "launched"
    launch_env = env | {"TEST_LAUNCH": str(launch_flag)}
    (remote / "ksu-live.stamp").write_text(BOOT + "\n")
    result = subprocess.run(["sh", str(launch_script), str(shared / "infinitylock-run-test.log")], env=launch_env, capture_output=True, text=True)
    assert result.returncode == 2 and "already present" in result.stdout, result
    assert not launch_flag.exists()
    (remote / "ksu-live.stamp").unlink()
    result = subprocess.run(["sh", str(launch_script), str(shared / "infinitylock-run-test.log")], env=launch_env, capture_output=True, text=True)
    assert result.returncode == 0, result
    for _ in range(20):
        if launch_flag.exists():
            break
        time.sleep(0.025)
    assert launch_flag.exists()
    assert slide.read_text() == "1706400000\n", "slide was changed or removed"
    print("PASS: native gate refuses hidden loaded modules, permits an absent module and preserves the slide")
