#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates an SD card disk image that will boot on
# a zcu104 Zynq FPGA dev board, and be ready to accept GHA runner
# jitconfig passed in over UART by fpga-boss.

set -e
set -x

mkdir -p out
SYSTEM_BOOT_SHA256="5a22eac02deb38825ed5df260e394753f440d546a34b9ed30ac096eb3aed2eb5"
if ! (echo "${SYSTEM_BOOT_SHA256} out/system-boot.tar.gz" | sha256sum -c); then
  curl -o out/system-boot.tar.gz https://people.canonical.com/~platform/images/xilinx/versal-ubuntu-22.04/iot-limerick-versal-classic-server-2204-x02-20230315-48-system-boot.tar.gz
  if ! (echo "${SYSTEM_BOOT_SHA256} out/system-boot.tar.gz" | sha256sum -c); then
    echo "Downloaded system-boot file did not match expected sha256sum".
    exit 1
  fi
fi

# Build the rootfs
ROOT_FS_SHA256="198281b2d2541a63b6ff0f52d65a60b7715492747efe60576c80760813af823a"
if ! (echo "${ROOT_FS_SHA256} out/rootfs.tar.gz" | sha256sum -c); then
  curl -o out/rootfs.tar.gz "https://people.canonical.com/~platform/images/xilinx/versal-ubuntu-22.04/iot-limerick-versal-classic-server-2204-x02-20230315-48-rootfs.tar.gz"
  if ! (echo "${ROOT_FS_SHA256} out/rootfs.tar.gz" | sha256sum -c); then
    echo "Downloaded rootfs file did not match expected sha256sum".
    exit 1
  fi
fi

(rm -rf out/rootfs || true)
mkdir -p out/rootfs
tar xvzf out/rootfs.tar.gz -C out/rootfs

echo "runner ALL=(ALL) NOPASSWD:ALL" > out/rootfs/etc/sudoers.d/runner
chroot out/rootfs useradd runner --shell /bin/bash --create-home
chroot out/rootfs bash -c 'echo kernel.softlockup_panic = 1 >> /etc/sysctl.conf'
chroot out/rootfs bash -c 'echo kernel.softlockup_all_cpu_backtrace = 1 >> /etc/sysctl.conf'
chroot out/rootfs mkdir /mnt/root_base
chroot out/rootfs mkdir /mnt/root_overlay
chroot out/rootfs mkdir /mnt/new_root
chroot out/rootfs bash -c 'echo kernel.panic_print = 127 >> /etc/sysctl.conf'
chroot out/rootfs bash -c 'echo kernel.sysrq = 1 >> /etc/sysctl.conf'
echo Retrieving latest GHA runner version
RUNNER_VERSION="$(curl https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name[1:]')"
echo Using runner version ${RUNNER_VERSION}
trap - EXIT
(cd out/rootfs/home/runner && curl -O -L "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz")
chroot out/rootfs bash -c "su runner -c \"cd /home/runner && tar xvzf actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz && rm -f actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz\""

su $SUDO_USER -c "
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=\"aarch64-linux-gnu-gcc\" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS=\"-C link-arg=--sysroot=$PWD/out/rootfs\" \
~/.cargo/bin/cargo install cargo-nextest@0.9.64 \
--locked \
--no-default-features \
--features=default-no-update \
--target=aarch64-unknown-linux-gnu \
--root /tmp/cargo-nextest"

cp /tmp/cargo-nextest/bin/cargo-nextest out/rootfs/usr/bin/

cp startup-script.sh out/rootfs/usr/bin/
chroot out/rootfs chmod 755 /usr/bin/startup-script.sh
cp startup-script.service out/rootfs/etc/systemd/system/
chroot out/rootfs systemctl enable startup-script.service

# Build a squashed filesystem from the rootfs
rm out/rootfs.sqsh || true
sudo mksquashfs out/rootfs out/rootfs.sqsh -comp zstd
# TODO: Doubled this size due to tar saying that it ran out of space. Verify this works and maybe trim it down.
bootfs_blocks="$((125000 * 2))"
rootfs_bytes="$(stat --printf="%s" out/rootfs.sqsh)"
rootfs_blocks="$((($rootfs_bytes + 512) / 512))"
persistfs_blocks=14680064

# Allocate the disk image
fallocate -l $(((2048 + 8 + $bootfs_blocks + $rootfs_blocks + $persistfs_blocks) * 512)) out/image.img

# Partition the disk image
cat <<EOF | sfdisk out/image.img
label: dos
label-id: 0x4effe30a
device: image.img
unit: sectors
sector-size: 512

p1 : start=2048, size=${bootfs_blocks}, type=c, bootable
p2 : start=$((2048 + $bootfs_blocks)), size=8, type=83
p3 : start=$((2048 + 8 + $bootfs_blocks)), size=${rootfs_blocks}, type=83
p4 : start=$((2048 + 8 + $bootfs_blocks + $rootfs_blocks)), size=${persistfs_blocks}, type=83
EOF
truncate -s $(((2048 + 8 + $bootfs_blocks + $rootfs_blocks) * 512)) out/image.img


LOOPBACK_DEV="$(losetup --show -Pf out/image.img)"
function cleanup1 {
  losetup -d ${LOOPBACK_DEV}
}
trap cleanup1 EXIT

# Format bootfs partition (kernel + bootloader stages)
mkfs -t vfat "${LOOPBACK_DEV}p1"

# Mount bootfs partition (from image) for modification
mkdir -p out/bootfs
mount "${LOOPBACK_DEV}p1" out/bootfs

function cleanup2 {
  umount out/bootfs
  cleanup1
}
trap cleanup2 EXIT

# Write bootfs contents
tar xvzf out/system-boot.tar.gz -C out/bootfs

# Replace the u-boot boot script with our own
rm out/bootfs/boot.scr.uimg
mkimage -T script -n "boot script" -C none -d boot.scr out/bootfs/boot.scr.uimg
cp /usr/local/google/home/clundin/boot1900.bin out/bootfs/boot1900.bin
umount out/bootfs
trap cleanup1 EXIT

# Write the rootfs squashed filesystem to the image partition
dd if=out/rootfs.sqsh of="${LOOPBACK_DEV}p3"

# Write a sentinel value to the configuration partition
echo CONFIG_PARTITION > "${LOOPBACK_DEV}p2"
