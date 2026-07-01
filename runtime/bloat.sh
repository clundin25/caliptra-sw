#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z $1 ]; then
    echo "Usage:"
    echo "./bloat.sh [revision]"
    echo "Where [revision] has to be one of the revisions under /hw (rev-latest, rev-2_1, ...)."
    exit 1
fi
export CALIPTRA_HW_REV=$1

cargo bloat \
  --locked \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --no-default-features \
  --features=emu,fips_self_test,riscv \
  -p caliptra-runtime \
  -n 200 \
  --bin=caliptra-runtime
  # Uncomment this line to see code size by crate
  #--crates \
