FROM lukemathwalker/cargo-chef:latest-rust-1.91.1-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    clang-tools-14 \
    git \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    libudev-dev \
    && apt-get clean

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN make build-release

FROM golang:1.21.0 as tendermint-builder
WORKDIR /app

RUN git clone -b v0.37.16 --single-branch https://github.com/cometbft/cometbft.git && cd cometbft && make build

FROM debian:bookworm-slim AS runtime
ENV NAMADA_LOG_COLOR=false

RUN apt-get update && apt-get install libcurl4-openssl-dev libudev-dev -y && apt-get clean

RUN useradd --create-home namada
USER namada

COPY --from=builder --chmod=0755 /app/target/release/namada /usr/local/bin
COPY --from=builder --chmod=0755 /app/target/release/namadan /usr/local/bin
COPY --from=builder --chmod=0755 /app/target/release/namadaw /usr/local/bin
COPY --from=builder --chmod=0755 /app/target/release/namadac /usr/local/bin
COPY --from=tendermint-builder --chmod=0755 /app/cometbft/build/cometbft /usr/local/bin

EXPOSE 26656
EXPOSE 26660
EXPOSE 26659
EXPOSE 26657

ENTRYPOINT ["/usr/local/bin/namada"]
CMD ["--help"]
