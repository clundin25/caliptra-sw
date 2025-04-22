# Caliptra fpga-boss

A utility for flashing, resetting, and communicating over UART with zcu104 FPGA
boards used for testing Caliptra firmware.

## What do I need to use this?

You need:

* A linux host with USB. A cheap SBC like a Raspberry PI works well.
* A [Xilinx zcu104 FPGA dev board](https://www.xilinx.com/products/boards-and-kits/zcu104.html), with the FTDI/JTAG USB port plugged into the linux host.
* An FPGA SD image built from [../fpga-image](../fpga-image)

To use the flashing feature, you will need

* An [SDWire](https://wiki.tizen.org/SDWire) SD mux or compatible clone.

## How do I determine the `--zcu104` parameter for my hardware?

This is the USB port path to the FTDI chip on the ZCU104 dev board, which will
remain the consistent whenever the device is plugged into this port. To discover
the value:

```sh
sudo dmesg | grep 'idVendor=0403, idProduct=6011'
[1349669.647027] usb 1-14.3: New USB device found, idVendor=0403, idProduct=6011, bcdDevice= 8.00 
```

In this case, the USB path is `1-14.3`.


## How do I determine the `--sdwire` parameter for my hardware?

This is the USB port path of the USB hub built into the SDWire0 (SDWire contains
a hub connected to a FTDI chip and SD USB controller chip).

```sh
$ sudo dmesg | grep 'idVendor=04e8, idProduct=6001'
[1349552.217882] usb 1-14.6.2: New USB device found, idVendor=04e8, idProduct=6001, bcdDevice=10.00
```

The shell snippet above finds the port path of the FTDI chip. To get the port path of
the hub, remove the '.2' suffix. For example, `1-14.6.2` becomes `--sdwire=1-14.6`.

## What is the `--boss_ftdi` argument for?

fpga-boss can also be used with a FTDI
[C232HM-DDHS](https://ftdichip.com/products/c232hm-ddhsl-0-2/) cable for
control of a Raspberry Pi with the `console` subcommand, (and the `flash`
subcommand if you have an SDWire plugged into the PI's SD slot). To use:

* C232HM-DDHS black wire should be plugged into Raspberry PI GPIO pin 6 (Ground)
* C232HM-DDHS yellow wire should be plugged into Raspberry PI GPIO pin 8 (UART TXD)
* C232HM-DDHS orange wire should be plugged into Raspberry PI GPIO pin 10 (UART RXD)
* C232HM-DDHS green wire can be plugged into the RUN pin of J2 (for reset control)

## Can you give me an example of how I might use fpga-boss?

Start by generating an image (or download one pre-built by the [fpga-image workflow](../../.github/workflows/fpga-image.yml).

```sh
$ sudo apt-get -y install debootstrap binfmt-support qemu-user-static u-boot-tool
$ cd ci-tools/fpga-image
$ sudo bash build.sh
```

### To flash the image to the SD card and take the FPGA out of reset:

```
$ cd ci-tools/fpga-boss
$ cargo run -- --zcu104 1-14.3 --sdwire 1-14.6 flash ../fpga-image/out/image.img
Block device associated with 1-14.2.1 is /dev/sda
Flashing ../fpga-image/out/image.img to /dev/sda
Waiting for attached sd card to be noticed by OS
```

If you run into permission-denied errors, you may need to tweak your udev rules
to make the above USB devices accessible to your user. Alternately, run
fpga-boss as root.

### To observe the UART output of the now booting FPGA:

```
$ cargo run -- --zcu104 1-14.3 --sdwire 1-14.2  console
To exit terminal type Ctrl-T then Q


U-Boot 2020.01 (May 14 2021 - 10:06:32 +0000)

Model: ZynqMP ZCU104 RevC
Board: Xilinx ZynqMP
<snip>
```

## How is fpga-boss used for Caliptra CI?

We have four zcu104 boards connected to a Raspberry pi running four instances of
`fpga-boss serve`:

```
# fpga-boss --zcu104 x-x.x --sdwire x-x.x serve image.img -- /path/to/rtool receive_jitconfig
```

The serve subcommand runs in a loop that does the following:

* Ensure that the sd card contains contains image.img, flashing if necessary.
* Take the zcu104 out of reset, monitoring its boot over UART.
* Once the zcu104 has booted, invoke the provided shell command
  `path/to/rtool receive_jitconfig`, and read the
  [jitconfig](https://docs.github.com/en/rest/actions/self-hosted-runners#create-configuration-for-a-just-in-time-runner-for-an-organization) from
  stdout.
* Talk to the zcu104 over UART and ask it to invoke the GHA runner
  with the provided jitconfig.
* Monitor the UART, waiting for the GHA runner to terminate after it
  runs a single job.
* Put the FPGA back into reset, and go back to step 1.

![Photo of FPGA Farm](./images/fpga-farm.jpg)

![Block Diagram](./../github-runner/images/caliptra-github-ci.svg)

# Raspberry PI Setup Instructions

## RPI Setup

1. Install Rust
1. Install fpga-boss and cred-tool.
    - `cargo install --git https://github.com/chipsalliance/caliptra-sw.git caliptra-fpga-boss --branch main`
    - `cargo install --git https://github.com/clundin25/cred-tool.git`
        - TODO(clundin): Maybe just install the binaries to `/usr/bin`
1. Download the latest FPGA image from [GitHub](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga-image.yml). This job is scheduled to run once a week.
    - In the following examples, the image is stored in `$HOME/zcu-scripts/zcu104.img` for the Raspberry PI user.
1. Get a GitHub Application private key for the CI. This is used to sign JWTs used by the FPGA runners.
    - The template below stores this file at `/etc/secrets/caliptra-gce-ci-github-private-key-pem/prod`.

## UDEV rules

Add UDEV rules for the hardware that is involved to avoid running the CI as root.

Here is an example from my RPI:

```
runner@caliptrarpi:~/zcu104-scripts $ cat /etc/udev/rules.d/99-fpga.rules
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6011", OWNER="runner", GROUP="runner"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="04e8", ATTRS{idProduct}=="6001", OWNER="runner", GROUP="runner"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="2640", OWNER="runner", GROUP="runner"
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0424", ATTRS{idProduct}=="4050", OWNER="runner", GROUP="runner"
```

These rules are for the FTDI / SDWIRE USB hosts, as well as the SD Cards that I use. You may have different vendors and products.

## FPGA Bash Script Template

This is a template bash script used to manage each FPGA. 

The following placeholders are populated in subsequent sections:
* `ZCU_FTDI`
* `ZCU_SDWIRE`
* `IDENTIFIER`
* `LOCATION`

```
#!/bin/bash

ZCU_FTDI="" # TODO: Update me!
ZCU_SDWIRE="" # TODO: Update me!
IDENTIFIER="" # TODO: Update me!
LOCATION="" # TODO: Update me!
IMAGE="$HOME/zcu104-scripts/zcu104.img"

$HOME/.cargo/bin/caliptra-fpga-boss --zcu104 $ZCU_FTDI --sdwire $ZCU_SDWIRE serve $IMAGE -- $HOME/.cargo/bin/cred-tool --stage prod --fpga-target zcu104 --fpga-identifier $IDENTIFIER --location $LOCATION --key-path /etc/secrets/caliptra-gce-ci-github-private-key-pem/prod
```

### Populating ZCU_FTDI

This is alternatively documented above in "How do I determine the `--zcu104` parameter for my hardware?". We will use a different method because we will most likely be connecting multiple FPGAs.

First, open a terminal window with `dmesg -w` on the Raspberry PI. I recommend using tmux so we don't have to tab back and forth between the script and dmesg.

Plug in a micro-usb cable to the FPGA serial port and to your Raspberry PI. You should see a log like this:

```
[ 1360.519412] usbserial: USB Serial support registered for FTDI USB Serial Device
[ 1360.519630] ftdi_sio 1-1.1.3:1.0: FTDI USB Serial Device converter detected
[ 1360.519783] usb 1-1.1.3: Detected FT4232H
[ 1360.520694] usb 1-1.1.3: FTDI USB Serial Device converter now attached to ttyUSB0
```

Based on the above log, we would set the `ZCU_FTDI` variable to `1-1.1.3`. This is the USB path to the device.

### Populating ZCU_SDWIRE

This is alternatively documented above in "How do I determine the `--sdwire` parameter for my hardware?". We will use a different method because we will most likely be connecting multiple FPGAs.

First, open a terminal window with `dmesg -w` on the Raspberry PI. I recommend using tmux so we don't have to tab back and forth between the script and dmesg.

Plug in the SDWire. You should see a log like this:

```
[ 1266.724822] usb-storage 1-1.1.4.1:1.0: USB Mass Storage device detected
[ 1266.725524] scsi host0: usb-storage 1-1.1.4.1:1.0
[ 1266.803147] usb 1-1.1.4.2: new full-speed USB device number 6 using xhci_hcd
[ 1266.908861] usb 1-1.1.4.2: New USB device found, idVendor=04e8, idProduct=6001, bcdDevice=10.00
[ 1266.908892] usb 1-1.1.4.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 1266.908906] usb 1-1.1.4.2: Product: sd-wire
[ 1266.908918] usb 1-1.1.4.2: Manufacturer: SRPOL
[ 1266.908928] usb 1-1.1.4.2: SerialNumber: bdgrd_sdwirec_593
```

Based on the above log, we would set the `ZCU_SDWIRE` variable to `1-1.1.4`. This is the USB path to the device.

### Populating IDENTIFIER

This is a unique string or number to differentiate co-located FPGAs.

In Kirkland, each FPGA is assigned an incrementing number, e.g. 1, 2, 3, 4, etc.

### Populating Location

This identifies where the FPGAs are located. For Kirkland we use "kir", in Sunnyvale we use "svl".
Other companies should also include the company name in this field.

### Saving the bash script

I recommend saving the bash file to `$HOME/zcu104-scripts/zcu-$IDENTIFIER.sh` to help differentiate between FPGAs.

### Testing the script

Run the bash script to see if everything works. A successful run will end with the following output:

```
Apr 21 16:55:26 caliptrarpi bash[2201]: UART: Executing GHA runner
Apr 21 16:55:37 caliptrarpi bash[2201]: UART:
Apr 21 16:55:37 caliptrarpi bash[2201]: UART: √ Connected to GitHub
Apr 21 16:55:37 caliptrarpi bash[2201]: UART:
Apr 21 16:55:38 caliptrarpi bash[2201]: UART: Current runner version: '2.323.0'
Apr 21 16:55:38 caliptrarpi bash[2201]: UART: 2025-04-21 23:55:37Z: Listening for Jobs
```


## Managing the FPGA with systemd

I recommend wrapping the FPGA scripts with systemd for easier management.

Here is a template:

```
[Unit]
Description=ZCU-0 Service
After=network.target sshd.service
Wants=network.target

[Service]
User=runner
Type=simple
Restart=on-failure
RestartSec=15s
StartLimitInterval=60m
StartLimitBurst=3
ExecStart=/usr/bin/bash /home/runner/zcu104-scripts/zcu-0.sh

[Install]
WantedBy=multi-user.target
```

TODO(clundin): Tweak the retry parameters to happen over a longer time period (Maybe 24 hours?).

## Starting the FPGA service

```
$ sudo systemctl enable zcu-0 # We want the FPGA service to start when the RPI is rebooted.
$ sudo systemctl start zcu-0
$ journalctl -u zcu-0 -f # Monitor the FPGA to make sure everything is working.
```
