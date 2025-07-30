FROM debian:bookworm
RUN apt update && apt install git curl make gcc-aarch64-linux-gnu
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
RUN rustup target add riscv32imc-unknown-none-elf && rustup target add aarch64-linux-gnu-gcc

