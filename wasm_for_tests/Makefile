cargo := $(env) cargo
rustup := $(env) rustup
# Nightly build is currently used for rustfmt and clippy.
nightly := $(shell cat ../rust-nightly-version)

# All the wasms that can be built from this source, switched via Cargo features
# Wasms can be added via the Cargo.toml `[features]` list.
wasms := tx_fail
wasms += tx_fail_event
wasms += tx_infinite_guest_gas
wasms += tx_infinite_host_gas
wasms += tx_invalid_data
wasms += tx_memory_limit
wasms += tx_no_op
wasms += tx_no_op_event
wasms += tx_proposal_code
wasms += tx_proposal_ibc_token_inflation
wasms += tx_proposal_ibc_unlimited_channel
wasms += tx_proposal_masp_reward
wasms += tx_proposal_token_gas
wasms += tx_read_storage_key
wasms += tx_write
wasms += vp_always_false
wasms += vp_always_true
wasms += vp_eval
wasms += vp_infinite_guest_gas
wasms += vp_infinite_host_gas
wasms += vp_memory_limit
wasms += vp_read_storage_key
wasms += vp_verify_signature


# Build all wasms in release mode
all:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --release --target wasm32-unknown-unknown --target-dir 'target'
	cp target/wasm32-unknown-unknown/release/*.wasm .

release-unwind:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --features debug-panic-hook --profile release_unwind --target wasm32-unknown-unknown --target-dir 'target'
	cp target/wasm32-unknown-unknown/release_unwind/*.wasm .

debug:
	RUSTFLAGS='-C link-arg=-s' $(cargo) build --target wasm32-unknown-unknown --target-dir 'target'
	cp target/wasm32-unknown-unknown/debug/*.wasm .

check:
	$(cargo) +$(nightly) check --workspace --target wasm32-unknown-unknown

clippy:
	$(cargo) +$(nightly) clippy --all-targets --workspace -- -D warnings --check-cfg 'cfg(fuzzing)'

clippy-fix:
	$(cargo) +$(nightly) clippy --fix -Z unstable-options --workspace --allow-dirty --allow-staged

fmt:
	$(cargo) +$(nightly) fmt

fmt-check:
	$(cargo) +$(nightly) fmt --check

clean:
	$(cargo) clean

deps:
	$(rustup) target add wasm32-unknown-unknown

.PHONY: all debug check clippy clippy-fix fmt fmt-check clean deps
