"""Reject a built payload that omitted the requested hardening features."""
import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("module", type=Path)
parser.add_argument("--nm", required=True)
args = parser.parse_args()
data = args.module.read_bytes()
assert data[:6] == b"\x7fELF\x02\x01", "expected ELF64 little-endian module"
symbols = subprocess.check_output([args.nm, str(args.module)], text=True)
for name in ("ksu_selinux_oracle_init", "ksu_sel_write_context_pre", "reboot_handler_pre"):
    assert name in symbols, f"missing hardening function: {name}"
assert b"hide: module list symbols unresolved" in data, "module-hiding code absent"
assert b"shell is allowed at init!" not in data, "routine shell message still present"
assert b"welcome to KernelSU version" not in data, "quiet-mode boot banner still present"
assert b"prepare cred failed!" in data, "genuine error diagnostic missing"
for marker in (b"ksu_no_text_poke=1", b"ksu_self_resolved_data=1"):
    assert marker in data, f"missing compatibility marker: {marker!r}"
print("PASS: built module contains hardening/compatibility code and omits routine log strings")
