#!/bin/bash

curl https://sh.rustup.rs | sh -s -- -y;
export PATH="$PATH:~/.cargo/bin/";
rustup set profile minimal;
rustup toolchain install nightly;
rustup override set nightly;
cd ./pylancelot;
/opt/python/cp38-cp38m/bin/pip install --upgrade pip maturin
/opt/python/cp38-cp38m/bin/maturin --release --strip;
cd ../;
ls -R target;
