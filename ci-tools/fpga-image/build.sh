#!/bin/bash
# Licensed under the Apache-2.0 license

# This script generates an SD card disk image that will boot on
# a zcu104 Zynq FPGA dev board, and be ready to accept GHA runner
# jitconfig passed in over UART by fpga-boss.

set -e
set -x

mkdir -p out

curl -L "https://github.com/clundin25/caliptra-sw/releases/download/release_v20241005_0/vck190-kernel-random-mac-with-correct-bitstream.tar.gz" -o out/system-boot.tar.gz
# curl -L "https://github.com/clundin25/caliptra-sw/releases/download/release_v20241005_0/vck190-kernel-correct-bitstream.tar.gz" -o out/system-boot.tar.gz
# curl -L "https://github.com/clundin25/caliptra-sw/releases/download/release_v20241005_0/vck190-kernel-with-correct-bitstream.tar.gz" -o out/system-boot.tar.gz
# curl -L "https://github.com/clundin25/caliptra-sw/releases/download/release_v20241005_0/vck190-kernel-with-squashfs-fs.tar.gz" -o out/system-boot.tar.gz
curl -L "https://github.com/clundin25/caliptra-sw/releases/download/release_v20241005_0/io-module.ko" -o out/io-module.ko
#scp /usr/local/google/home/clundin/vck190-kernel-with-rw-root.tar.gz out/system-boot.tar.gz
# scp /usr/local/google/home/clundin/vck190-kernel-with-rw-root.gz out/system-boot.tar.gz
# scp /usr/local/google/home/clundin/vck190-kernel-with-squashfs.gz out/system-boot.tar.gz
#scp /usr/local/google/home/clundin/vck190-bootfs.tar.gz out/system-boot.tar.gz
#scp /usr/local/google/home/clundin/vck190-kernel-initrd.tar.gz out/system-boot.tar.gz

# SYSTEM_BOOT_SHA256="5a22eac02deb38825ed5df260e394753f440d546a34b9ed30ac096eb3aed2eb5"
# if ! (echo "${SYSTEM_BOOT_SHA256} out/system-boot.tar.gz" | sha256sum -c); then
#   curl -o out/system-boot.tar.gz https://people.canonical.com/~platform/images/xilinx/versal-ubuntu-22.04/iot-limerick-versal-classic-server-2204-x02-20230315-48-system-boot.tar.gz
#   if ! (echo "${SYSTEM_BOOT_SHA256} out/system-boot.tar.gz" | sha256sum -c); then
#     echo "Downloaded system-boot file did not match expected sha256sum".
#     exit 1
#   fi
# fi

# export SKIP_DEBOOTSTRAP=1
# Build the rootfs
if [[ -z "${SKIP_DEBOOTSTRAP}" ]]; then
  (rm -rf out/rootfs || true)
  mkdir -p out/rootfs
  debootstrap --include git,curl,ca-certificates,locales,libicu72,sudo,vmtouch,fping,rdnssd,dbus,systemd-timesyncd,libboost-regex1.74.0,openocd,gdb-multiarch,squashfs-tools --arch arm64 --foreign bookworm out/rootfs
  chroot out/rootfs /debootstrap/debootstrap --second-stage
  chroot out/rootfs useradd runner --shell /bin/bash --create-home

  # Jobs need to act as root to install an FPGA bitstream. We don't care
  # if they mess up the rootfs because it's going to be re-flashed after the job
  # terminates anyways.
  echo "runner ALL=(ALL) NOPASSWD:ALL" > out/rootfs/etc/sudoers.d/runner

  chroot out/rootfs mkdir /mnt/root_base
  chroot out/rootfs mkdir /mnt/root_overlay
  chroot out/rootfs mkdir /mnt/new_root

  chroot out/rootfs bash -c 'echo caliptra-fpga > /etc/hostname'
  chroot out/rootfs bash -c 'echo auto end0 > /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo allow-hotplug end0 >> /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo iface end0 inet6 auto >> /etc/network/interfaces'
  chroot out/rootfs bash -c 'echo nameserver 2001:4860:4860::6464 > /etc/resolv.conf'
  chroot out/rootfs bash -c 'echo nameserver 2001:4860:4860::64 >> /etc/resolv.conf'
  chroot out/rootfs bash -c 'echo kernel.softlockup_panic = 1 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo kernel.softlockup_all_cpu_backtrace = 1 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo kernel.panic_print = 127 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo kernel.sysrq = 1 >> /etc/sysctl.conf'
  chroot out/rootfs bash -c 'echo "[Time]" > /etc/systemd/timesyncd.conf'
  chroot out/rootfs bash -c 'echo "NTP=time.google.com" >> /etc/systemd/timesyncd.conf'

  # Comment this line out if you don't trust folks with physical access to the
  # uart
  # chroot out/rootfs bash -c 'echo root:password | chpasswd'
  #

  echo Retrieving latest GHA runner version
  RUNNER_VERSION="$(curl https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name[1:]')"
  echo Using runner version ${RUNNER_VERSION}
  trap - EXIT
  (cd out/rootfs/home/runner && curl -O -L "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz")
  chroot out/rootfs bash -c "su runner -c \"cd /home/runner && tar xvzf actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz && rm -f actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz\""
fi

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
# chroot out/rootfs bash -c 'ldd -v /usr/bin/cargo-nextest'
# chroot out/rootfs bash -c 'ld -v'

chroot out/rootfs bash -c 'echo ::1 caliptra-fpga >> /etc/hosts'
cp startup-script.sh out/rootfs/usr/bin/
chroot out/rootfs systemctl set-default multi-user.target
chroot out/rootfs chmod 755 /usr/bin/startup-script.sh
cp startup-script.service out/rootfs/etc/systemd/system/
chroot out/rootfs systemctl enable startup-script.service
cp out/io-module.ko out/rootfs/home/runner/io-module.ko

(rm -r out/image.img || true)

bootfs_blocks="$((80000 * 4))"
rootfs_bytes="$(du -sb out/rootfs | awk '{print $1}')"
rootfs_bytes_padded=$((rootfs_bytes * 125 / 100))
# rootfs_blocks="$(( (rootfs_bytes_padded + 511) / 512 ))"
rootfs_blocks="$(((1024 * 1024 * 1024 * 4) / 512))"

# Allocate the disk image
# fallocate -l $(((2048 + $bootfs_blocks + $rootfs_blocks) * 512)) out/image.img
fallocate  -l $(((2048 + $bootfs_blocks + $rootfs_blocks) * 512)) out/image.img

# Partition the disk image
cat <<EOF | sfdisk out/image.img
label: dos
label-id: 0x4effe30a
device: image.img
unit: sectors
sector-size: 512

p1 : start=2048, size=${bootfs_blocks}, type=c, bootable
p2 : start=$((2048 + $bootfs_blocks)), size=$rootfs_blocks, type=83
EOF

# Partition the disk image
cat <<EOF | sfdisk out/image.img
label: dos
label-id: 0x4effe30a
device: image.img
unit: sectors
sector-size: 512

p1 : start=2048, size=${bootfs_blocks}, type=c, bootable
p2 : start=$((2048 + $bootfs_blocks)), size=$rootfs_blocks, type=83
EOF


LOOPBACK_DEV="$(losetup --show -Pf out/image.img)"
function cleanup {
  if mountpoint -q out/rootfs_mount; then
    umount out/rootfs_mount
  fi
  if mountpoint -q out/bootfs; then
    umount out/bootfs
  fi
  if [ -n "${LOOPBACK_DEV}" ]; then
    losetup -d "${LOOPBACK_DEV}"
  fi
}
trap cleanup EXIT

# Format bootfs partition (kernel + bootloader stages)
mkfs -t vfat "${LOOPBACK_DEV}p1"

# Mount bootfs partition (from image) for modification
mkdir -p out/bootfs
mount "${LOOPBACK_DEV}p1" out/bootfs

# Write bootfs contents
tar -xvf out/system-boot.tar.gz -C out/bootfs --no-same-owner

# Replace the u-boot boot script with our own
# rm out/bootfs/boot.scr
# mkimage -T script -n "boot script" -C none -d boot.scr out/bootfs/boot.scr.uimg

umount out/bootfs

# Format and write the rootfs to the second partition
echo "Formatting rootfs partition as ext4..."
mkfs.ext4 "${LOOPBACK_DEV}p2"

echo "Mounting ext4 rootfs partition..."
mkdir -p out/rootfs_mount
mount "${LOOPBACK_DEV}p2" out/rootfs_mount

echo "Copying rootfs contents..."
cp -a out/rootfs/. out/rootfs_mount/

echo "Unmounting rootfs partition..."
umount out/rootfs_mount

echo "Script finished successfully. Image created at out/image.img"
