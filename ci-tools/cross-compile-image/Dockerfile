FROM debian:bookworm
RUN apt update && apt install git curl make gcc-aarch64-linux-gnu -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add riscv32imc-unknown-none-elf && rustup target add aarch64-unknown-linux-gnu

