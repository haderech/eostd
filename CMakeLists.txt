cmake_minimum_required(VERSION 3.5)

project(sio4)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(sio4 STATIC
   src/xxhash.cpp
   src/sha256.cpp
   src/drbg.cpp
)

target_include_directories(sio4 PUBLIC include)

add_subdirectory(lib)
