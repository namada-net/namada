# Namada

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
![CI Status](https://github.com/namada-net/namada/actions/workflows/ci.yml/badge.svg?branch=main)

## Overview

[Namada](http://namada.net) is a Proof-of-Stake L1 for multichain asset-agnostic data protection. Namada uses CometBFT
consensus and enables multi-asset shielded transfers for any native
or non-native asset. Namada features full IBC protocol support, a modern proof-of-stake
system with cubic slashing, and a
stake-weighted on-chain governance mechanism. Users of Namada's MASP (Multi-Asset Shielded Pool) are rewarded for their contributions to the shielded set in
the form of native protocol tokens. A multi-asset shielded transfer
wallet is provided in order to facilitate safe user
interaction with the protocol.

* Blogpost: [Introducing Namada: Multichain Asset-agnostic Data Protection](https://namada.net/blog/introducing-namada-multichain-asset-agnostic-data-protection)

## 📓 Docs

* [User guides](https://docs.namada.net/)
* [Specs](https://specs.namada.net/)
* Rust docs can be built with `cargo doc --open` (add `--no-deps` to only build docs for local crates)

## Warning

> Here lay dragons: this codebase is still experimental, try at your own risk!

## 💾 Installing

There is a single command to build and install Namada executables from source (the node, the client and the wallet). This command will also verify that a compatible version of [CometBFT](#dependencies) is available and if not, attempt to install it. Note that currently at least 16GB RAM is needed to build from source.

```shell
make install
```

After installation, the main `namada` executable will be available on path.

To find how to use it, check out the [User Guide section of the docs](https://docs.namada.net/users).

For more detailed instructions and more install options, see the [Install
section](https://docs.namada.net/introduction/install) of the User
Guide.

## ⚙️ Development

```shell
# Build the provided validity predicate and transaction wasm modules
make build-wasm-scripts-docker
```

### Before submitting a PR, please make sure to run the following

```shell
# Format the code
make fmt

# Lint the code
make clippy
```

## 🧾 Logging

To change the log level, set `NAMADA_LOG` environment variable to one of:

* `error`
* `warn`
* `info`
* `debug`
* `trace`

The default is set to `info` for all the modules, except for CometBFT ABCI, which has a lot of `debug` logging.

For more fine-grained logging levels settings, please refer to the [tracing subscriber docs](https://docs.rs/tracing-subscriber/0.2.18/tracing_subscriber/struct.EnvFilter.html#directives) for more information.

To switch on logging in tests that use `#[test]` macro from `test_log::test`, use `RUST_LOG` with e.g. `RUST_LOG=info cargo test -- --nocapture`.

## How to contribute

Please see the [contributing page](./CONTRIBUTING.md).

### Dependencies

The ledger currently requires [CometBFT v0.37.16](https://github.com/cometbft/cometbft/releases/tag/v0.37.16) is installed and available on path. This can be achieved through following [these instructions](https://github.com/cometbft/cometbft/blob/main/docs/tutorials/install.md).

#### Hermes

We maintain a fork of [hermes](https://github.com/heliaxdev/hermes) that adds support for Namada.

Compatibility table with Namada:

| Namada binaries | Hermes |
| ----------- | ----------- |
| v101.0.0 | [1.13.0](https://github.com/informalsystems/hermes/releases/tag/v1.13.0) |
| v1.1.1 | [1.11.0](https://github.com/informalsystems/hermes/releases/tag/v1.11.0) |
| v1.1.0 | [1.10.5-namada-beta18](https://github.com/heliaxdev/hermes/releases/tag/v1.10.5-namada-beta18) |
| v1.0.0 | [1.10.4-namada-beta17-rc2](https://github.com/heliaxdev/hermes/releases/tag/v1.10.4-namada-beta17-rc2) |
