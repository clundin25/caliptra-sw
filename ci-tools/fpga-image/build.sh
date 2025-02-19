#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates an SD card disk image that will boot on
# a zcu104 Zynq FPGA dev board, and be ready to accept GHA runner
# jitconfig passed in over UART by fpga-boss.

set -e
set -x

export OUT_DIR=out2

mkdir -p ${OUT_DIR}
SYSTEM_IMAGE="5a0f3d04034923c5f04371a656b7e948dcd9894b3ca4ad2fe8a1d52139124e6c"
if ! (echo "${SYSTEM_IMAGE} ${OUT_DIR}/image.img.xz" | sha256sum -c); then
  curl -o ${OUT_DIR}/image.img.xz -L "https://people.canonical.com/~platform/images/xilinx/versal-ubuntu-22.04/iot-limerick-versal-classic-server-2204-x02-20230315-48.img.xz"
  if ! (echo "${SYSTEM_IMAGE} ${OUT_DIR}/image.img.xz" | sha256sum -c); then
    echo "Downloaded image file did not match expected sha256sum".
    exit 1
  fi
fi

scp ${OUT_DIR}/image.img.xz ${OUT_DIR}/work-image.img.xz
(rm ${OUT_DIR}/work-image.img || true)
(xz -d ${OUT_DIR}/work-image.img.xz || true)

LOOPBACK_DEV="$(losetup --show -Pf ${OUT_DIR}/work-image.img)"

(rm -r ${OUT_DIR}/bootfs || true)
mkdir -p ${OUT_DIR}/bootfs

mount "${LOOPBACK_DEV}p1" ${OUT_DIR}/bootfs

function cleanup1 {
  umount ${OUT_DIR}/bootfs
  losetup -d ${LOOPBACK_DEV}
}
trap cleanup1 EXIT

cp /usr/local/google/home/clundin/boot1900.bin ${OUT_DIR}/bootfs/boot1900.bin
umount ${OUT_DIR}/bootfs

(rm -r ${OUT_DIR}/rootfs || true)
mkdir -p ${OUT_DIR}/rootfs
mount "${LOOPBACK_DEV}p2" ${OUT_DIR}/rootfs

function cleanup2 {
  umount ${OUT_DIR}/rootfs
  losetup -d ${LOOPBACK_DEV}
}
trap cleanup2 EXIT

mkdir -p ${OUT_DIR}/rootfs/etc/sudoers.d/
echo "runner ALL=(ALL) NOPASSWD:ALL" > ${OUT_DIR}/rootfs/etc/sudoers.d/runner
ls ${OUT_DIR}/rootfs
chroot ${OUT_DIR}/rootfs useradd runner --shell /bin/bash --create-home
chroot ${OUT_DIR}/rootfs bash -c 'echo kernel.softlockup_panic = 1 >> /etc/sysctl.conf'
chroot ${OUT_DIR}/rootfs bash -c 'echo kernel.softlockup_all_cpu_backtrace = 1 >> /etc/sysctl.conf'
chroot ${OUT_DIR}/rootfs bash -c 'echo kernel.panic_print = 127 >> /etc/sysctl.conf'
chroot ${OUT_DIR}/rootfs bash -c 'echo kernel.sysrq = 1 >> /etc/sysctl.conf'

echo Retrieving latest GHA runner version
RUNNER_VERSION="$(curl https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name[1:]')"
echo Using runner version ${RUNNER_VERSION}
trap - EXIT
(cd ${OUT_DIR}/rootfs/home/runner && curl -O -L "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz")
chroot ${OUT_DIR}/rootfs bash -c "su runner -c \"cd /home/runner && tar xvzf actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz && rm -f actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz\""

#su $SUDO_USER -c "
#CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=\"aarch64-linux-gnu-gcc\" \
#CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS=\"-C link-arg=--sysroot=$PWD/${OUT_DIR}/rootfs\" \
#~/.cargo/bin/cargo install cargo-nextest@0.9.64 \
#--locked \
#--no-default-features \
#--features=default-no-update \
#--target=aarch64-unknown-linux-gnu \
#--root /tmp/cargo-nextest"
#
#cp /tmp/cargo-nextest/bin/cargo-nextest ${OUT_DIR}/rootfs/usr/bin/

cp startup-script.sh ${OUT_DIR}/rootfs/usr/bin/
chroot ${OUT_DIR}/rootfs chmod 755 /usr/bin/startup-script.sh
cp startup-script.service ${OUT_DIR}/rootfs/etc/systemd/system/
chroot ${OUT_DIR}/rootfs systemctl enable startup-script.service

umount ${OUT_DIR}/rootfs
losetup -d ${LOOPBACK_DEV}

xz ${OUT_DIR}/work-image.img
