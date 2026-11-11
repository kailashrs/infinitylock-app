#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
RUNNER_REF=${RUNNER_REF:-cb5143d890de5237afe4ceb109c42d91bd006dd3}
KERNELSU_REF=${KERNELSU_REF:-3beaf03789f5926fd262ad3b92d7821d651caee4}
DDK_IMAGE=${DDK_IMAGE:-ghcr.io/ylarod/ddk-min@sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2}
MANAGER_URL=https://github.com/tiann/KernelSU/releases/download/v3.3.1/KernelSU_v3.3.1_32680-release.apk
MANAGER_SHA256=b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450
KSUD_SHA256=4f7d5fd65631915ea579ff406bd9cbe58217f2c91dac6527f5b2f28ad4508171
: "${NDK:?Set NDK to an installed Android NDK r29}"
case "$(uname -s)" in Darwin) NDK_HOST=darwin-x86_64;; Linux) NDK_HOST=linux-x86_64;; *) exit 1;; esac
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$NDK_HOST/bin"
CC="$TOOLCHAIN/aarch64-linux-android35-clang"
STRIP="$TOOLCHAIN/llvm-strip"
[ -x "$CC" ] && [ -x "$STRIP" ] || { echo "NDK r29 toolchain missing: $TOOLCHAIN" >&2; exit 1; }
WORK=$(mktemp -d)
trap 'python3 -c "import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" "$WORK"' EXIT
mkdir -p "$WORK/payload"
git clone --quiet https://github.com/kailashrs/pd2454-kernelsu-runner.git "$WORK/runner"
git -C "$WORK/runner" checkout --quiet "$RUNNER_REF"
git clone --quiet https://github.com/kailashrs/KernelSU.git "$WORK/kernelsu"
git -C "$WORK/kernelsu" checkout --quiet "$KERNELSU_REF"
python3 "$WORK/runner/tests/test_child_logging.py"
python3 "$WORK/runner/tests/test_debug_logging.py"
"$CC" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -no-pie -Wall -Wextra \
  -I"$WORK/runner/src/timer" "$WORK/runner/src/timer/timer.c" -o "$WORK/payload/ic98260" -pthread \
  -Wl,--gc-sections -Wl,-z,norelro
"$CC" -O2 -static -Wall -Wextra "$WORK/runner/src/ksupatch.c" -o "$WORK/payload/ksupatch"
"$CC" -O2 -static -Wall -Wextra "$WORK/runner/src/insmodf.c" -o "$WORK/payload/insmodf"
# Hidden-module profile helpers: root-side gated-supercall liveness probe and
# the unprivileged visibility matrix collected as attempt evidence.
"$CC" -O2 -static -Wall -Wextra "$WORK/runner/src/ksuquery.c" -o "$WORK/payload/ksuquery"
"$CC" -O2 -static -Wall -Wextra "$WORK/runner/src/ksu_exposure_probe.c" -o "$WORK/payload/ksu_exposure_probe"
for binary in ic98260 ksupatch insmodf ksuquery ksu_exposure_probe; do "$STRIP" "$WORK/payload/$binary"; done
curl --fail --location --silent --show-error "$MANAGER_URL" -o "$WORK/manager.apk"
echo "$MANAGER_SHA256  $WORK/manager.apk" | shasum -a 256 -c -
unzip -p "$WORK/manager.apk" lib/arm64-v8a/libksud.so > "$WORK/payload/ksud"
echo "$KSUD_SHA256  $WORK/payload/ksud" | shasum -a 256 -c -
docker run --rm --platform linux/amd64 -v "$WORK:/build" "$DDK_IMAGE" /bin/bash -lc '
set -euo pipefail
KDIR=/opt/ddk/kdir/android15-6.6
TARGET=6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
echo "$TARGET" > "$KDIR/include/config/kernel.release"
echo "#define UTS_RELEASE \"$TARGET\"" > "$KDIR/include/generated/utsrelease.h"
make -C "$KDIR" M=/build/kernelsu/kernel ARCH=arm64 LLVM=1 CONFIG_KSU=m CONFIG_KSU_NO_TEXT_POKE=y CONFIG_KSU_SELF_RESOLVED_DATA=y CONFIG_KSU_QUIET=y CONFIG_KSU_HIDE_MODULE=y KSU_GIT_VERSION_VALID=1 KSU_GIT_VERSION=2680 GIT=/bin/false KBUILD_MODPOST_WARN=1 KSU_NEW_DCACHE_FLUSH=1 -j2 modules
llvm-strip --strip-debug /build/kernelsu/kernel/kernelsu.ko -o /build/payload/kernelsu.ko
'
# Check that the freshly built module still satisfies the pinned binder's ELF,
# ABI and symbol guards before generating an APK from it.
clang -O1 -g -fsanitize=address,undefined -Wall -Wextra "$WORK/runner/src/ksupatch.c" -o "$WORK/ksupatch-host"
python3 "$WORK/runner/tests/test_binder.py" "$WORK/payload/kernelsu.ko" "$WORK/ksupatch-host"
mkdir -p "$SCRIPT_DIR/app/src/main/assets/payload"
install -m 0644 "$SCRIPT_DIR/native/run.sh" "$WORK/payload/run.sh"
for binary in ic98260 ksupatch insmodf ksuquery ksu_exposure_probe ksud kernelsu.ko run.sh; do
  install -m 0644 "$WORK/payload/$binary" "$SCRIPT_DIR/app/src/main/assets/payload/$binary"
done
python3 - "$SCRIPT_DIR" "$WORK/payload" <<'PY2'
from pathlib import Path
import hashlib,re,sys
root,built=Path(sys.argv[1]),Path(sys.argv[2])
manifest=root/'app/src/main/kotlin/dev/kailashrs/infinitylock/engine/Payload.kt'
text=manifest.read_text()
plain='enum class Payload(val asset: String, val remoteName: String)'
with_hash='enum class Payload(val asset: String, val remoteName: String, val sha256: String)'
if text.count(plain) == 1:
    text=text.replace(plain, with_hash, 1)
elif text.count(with_hash) != 1:
    raise SystemExit('Unexpected Payload enum declaration')
for name in ('ic98260','ksupatch','insmodf','ksuquery','ksu_exposure_probe','kernelsu.ko','ksud','run.sh'):
    digest=hashlib.sha256((built/name).read_bytes()).hexdigest()
    pattern = r'("payload/' + re.escape(name) + r'",\s*"' + re.escape(name) + r'")(?:,\s*"[0-9a-f]{64}")?'
    text,count=re.subn(pattern,lambda match: match.group(1) + ', "' + digest + '"',text)
    if count != 1: raise SystemExit(f'Payload.kt entry missing or duplicated: {name}')
manifest.write_text(text)
for name in ('ic98260','ksupatch','insmodf','ksuquery','ksu_exposure_probe','kernelsu.ko','ksud','run.sh'):
    print(name,hashlib.sha256((built/name).read_bytes()).hexdigest())
PY2
