#!/bin/bash
# rebuild the whole thing
make -j16
cd apps/synthetic
cargo clean
cargo build --release
cd ../..
./sync.sh
