#!/bin/bash

curl https://sh.rustup.rs | sh -s -- -y;
export PATH="$PATH:~/.cargo/bin/";
rustup set profile minimal;
rustup toolchain install nightly;
rustup override set nightly;
cd ./pylancelot;
ls /opt/python;
/opt/python/cp38-cp38/bin/pip install --upgrade pip maturin
/opt/python/cp38-cp38/bin/maturin build --release --strip;
cd ../;
ls -R target;
