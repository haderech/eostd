cmake_minimum_required(VERSION 3.5)

project(eostd)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(eostd STATIC
   src/xxhash.cpp
   src/sha256.cpp
   src/drbg.cpp
)

target_include_directories(eostd PUBLIC include)

add_subdirectory(lib)
