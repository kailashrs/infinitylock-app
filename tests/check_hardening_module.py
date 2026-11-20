"""Reject a built payload that omitted the requested hardening features,
or whose binder rename names collide with real device modules."""
import argparse
import re
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("module", type=Path)
parser.add_argument("--nm", required=True)
parser.add_argument("--census", type=Path,
                    default=Path(__file__).parent / "device_modules.txt")
parser.add_argument("--rename-header", type=Path,
                    help="runner src/ksrename.h; enables the name-conflict guard")
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
if args.rename_header:
    header = args.rename_header.read_text()

    def defval(name):
        m = re.search(rf'#define\s+{name}\s+"([^"]+)"', header)
        assert m, f"{name} missing from {args.rename_header.name}"
        return m.group(1)

    module_name = defval("KS_RENAME_MODULE")
    tokens = {defval("KS_RENAME_PFX_NEW"), defval("KS_RENAME_TOKEN_NEW")}
    census = {line.strip() for line in args.census.read_text().splitlines()
              if line.strip() and not line.startswith("#")}
    assert module_name not in census, \
        f"rename module name {module_name!r} collides with a real device module"
    clashes = [c for c in census if c.startswith(module_name + "_")
               or c.endswith("_" + module_name)]
    assert not clashes, \
        f"rename module name {module_name!r} clashes with device modules: {clashes[:3]}"
    for tok in tokens:
        prefixed = [c for c in census if c.startswith(tok)]
        assert not prefixed, \
            f"rename token {tok!r} prefixes device modules: {prefixed[:3]}"
    print(f"PASS: rename names ({module_name}, {sorted(tokens)}) have no "
          f"collisions in {len(census)} device module names")
print("PASS: built module contains hardening/compatibility code and omits routine log strings")
