# CMake toolchain file for building the bundled Zydis C library
# for the wasm32-unknown-unknown Rust target using clang.
#
# usage:
#
#     CMAKE_TOOLCHAIN_FILE=$(pwd)/wasm32-toolchain.cmake \
#       cargo build -p lancelot --target wasm32-unknown-unknown
#
# see the "WebAssembly" section in README.md for details.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET wasm32-unknown-unknown)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_COMPILER_TARGET wasm32-unknown-unknown)
# don't try to link an executable during cmake's compiler sanity checks,
# since there's no wasm libc/crt to link against here.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
