#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
RUNNER_REF=${RUNNER_REF:-ba4479514181459e035aba808da8579c86915503}
KERNELSU_REF=${KERNELSU_REF:-1dfdad51b824d701310f74b9eba5d69a63a9f50b}
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
"$CC" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -no-pie -Wall -Wextra \
  -I"$WORK/runner/src/timer" "$WORK/runner/src/timer/timer.c" -o "$WORK/payload/ic98260" -pthread \
  -Wl,--gc-sections -Wl,-z,norelro
"$CC" -O2 -static -Wall -Wextra "$WORK/runner/src/ksupatch.c" -o "$WORK/payload/ksupatch"
"$CC" -O2 -static -Wall -Wextra "$WORK/runner/src/insmodf.c" -o "$WORK/payload/insmodf"
for binary in ic98260 ksupatch insmodf; do "$STRIP" "$WORK/payload/$binary"; done
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
make -C "$KDIR" M=/build/kernelsu/kernel ARCH=arm64 LLVM=1 CONFIG_KSU=m CONFIG_KSU_NO_TEXT_POKE=y CONFIG_KSU_SELF_RESOLVED_DATA=y KSU_GIT_VERSION_VALID=1 KSU_GIT_VERSION=2680 GIT=/bin/false KBUILD_MODPOST_WARN=1 KSU_NEW_DCACHE_FLUSH=1 -j2 modules
llvm-strip --strip-debug /build/kernelsu/kernel/kernelsu.ko -o /build/payload/kernelsu.ko
'
mkdir -p "$SCRIPT_DIR/app/src/main/assets/payload"
install -m 0644 "$SCRIPT_DIR/native/run.sh" "$WORK/payload/run.sh"
for binary in ic98260 ksupatch insmodf ksud kernelsu.ko run.sh; do
  install -m 0644 "$WORK/payload/$binary" "$SCRIPT_DIR/app/src/main/assets/payload/$binary"
done
python3 - "$SCRIPT_DIR" "$WORK/payload" <<'PY2'
from pathlib import Path
import hashlib,re,sys
root,built=Path(sys.argv[1]),Path(sys.argv[2])
manifest=root/'app/src/main/kotlin/dev/kailashrs/infinitylock/engine/Payload.kt'
text=manifest.read_text()
for name in ('ic98260','ksupatch','insmodf','kernelsu.ko','ksud','run.sh'):
    digest=hashlib.sha256((built/name).read_bytes()).hexdigest()
    pattern=rf'("payload/{re.escape(name)}", "{re.escape(name)}",\s*")[0-9a-f]{{64}}(")'
    text,count=re.subn(pattern,rf'\g<1>{digest}\g<2>',text,count=1)
    if count != 1: raise SystemExit(f'Payload.kt entry missing or duplicated: {name}')
manifest.write_text(text)
for name in ('ic98260','ksupatch','insmodf','kernelsu.ko','ksud','run.sh'):
    print(name,hashlib.sha256((built/name).read_bytes()).hexdigest())
PY2
