#!/bin/bash

set -eux
ssh ocp-host -t 'git clone https://github.com/chipsalliance/caliptra-sw --branch=main-2.x --depth=1'
