#!/bin/bash

# Licensed under the Apache-2.0 license
#
# Startup script that is executed against the zcu104 UART. fpga-boss will
# connect to this UART (via on-board FTDI chip) and send commands.

# Stop spewing kernel noise to the UART
echo 3 > /proc/sys/kernel/printk

# The VCK-190 image currently always has the same MAC. Do this for now until 
# a better option is found.
ip link set dev end0 down
macchanger -r end0 || true
ip link set dev end0 up

if [[ -f "/etc/no_overlayfs" ]]; then
    echo "Running in development mode (no overlayfs)."
    systemctl start resize-rootfs
    insmod /home/runner/io-module.ko
    login -f root
else
    insmod /home/runner/io-module.ko

    HOST="google.com"
    while ! ping -c 1 "$HOST" &> /dev/null; do
      echo "Connection to $HOST failed. Retrying in 1 second..."
      sleep 1
    done

    # Update time.
    timedatectl set-ntp true
    systemctl restart systemd-timesyncd

    sleep 15s

    function runner_jitconfig() {
      echo "Executing GHA runner"
      su runner -c "/home/runner/run.sh --jitconfig \"${cmd_array[1]}\""
      echo "GHA runner complete"
    }

    # Emit a sentinel that tells fpga-boss (listening via UART)
    # that we are ready for input.
    echo "36668aa492b1c83cdd3ade8466a0153d --- Command input"
    echo Available commands:
    echo "  runner-jitconfig <base64>"
    echo "  login"
    read -e -p "> " cmd

    cmd_array=($cmd)
    if [[ "${cmd}" == "login" ]]; then
        login -f root
    elif [[ "${cmd_array[0]}" == "runner-jitconfig" ]]; then
        runner_jitconfig
    else
        echo "Unknown command ${cmd}"
    fi
    # Emit a sentinel that tells fpga-boss (listening via UART)
    # that we are done and can be reset.
    echo "3297327285280f1ffb8b57222e0a5033 --- ACTION IS COMPLETE"

    # Run a root shell that can be used to debug any problems while the artifacts
    # are still in the filesystem.
    login -f root
    shutdown -h now
fi