"""Compile the actual allow_shell call site with the real logging header."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
match = re.search(r'if \(allow_shell\) \{\s*(pr_\w+\("shell is allowed at init!"\);)\s*\}', (root / "kernel/core/init.c").read_text())
assert match, "allow_shell call site missing"
with tempfile.TemporaryDirectory(prefix="ksu-quiet-init-") as temp:
    work = Path(temp)
    (work / "linux").mkdir()
    (work / "linux/printk.h").write_text('''#include <stdio.h>
#define pr_fmt(fmt) fmt
#define pr_info(fmt, ...) printf(pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) printf(pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...) printf(pr_fmt(fmt), ##__VA_ARGS__)
#define no_printk(...) do { if (0) printf(__VA_ARGS__); } while (0)
''')
    source = work / "test.c"
    source.write_text('#include "' + str(root / "kernel/include/klog.h") + '"\nint main(void) { ' + match[1] + ' pr_alert("genuine failure\\n"); }\n')
    for quiet in (False, True):
        exe = work / ("quiet" if quiet else "normal")
        command = [os.environ.get("CC", "clang"), "-O2", "-I" + str(work)]
        if quiet:
            command.append("-DCONFIG_KSU_QUIET=1")
        subprocess.run(command + [str(source), "-o", str(exe)], check=True)
        output = subprocess.check_output([str(exe)], text=True)
        assert "genuine failure" in output
        assert ("shell is allowed at init!" in output) == (not quiet)
        if quiet:
            assert b"shell is allowed at init!" not in exe.read_bytes()
print("PASS: quiet init drops the routine shell message and its string; genuine alerts remain")
