#!/usr/bin/env bash

canister="asymmetric_identity_certifier"
canister_root="src/$canister"

cargo build --manifest-path="Cargo.toml" \
    --target wasm32-unknown-unknown \
    --release --package "$canister"

candid-extractor "target/wasm32-unknown-unknown/release/$canister.wasm" > "src/$canister.did"
