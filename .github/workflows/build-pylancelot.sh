#!/bin/sh

curl https://sh.rustup.rs | sh -s -- -y;
rustup set profile minimal;
rustup toolchain install nightly;
rustup override set nightly;
cd ./pylancelot;
maturin --release --strip;
cd ../;
ls -R target;
