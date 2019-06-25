cmake_minimum_required(VERSION 3.5)

project(eoslib)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_library(eoslib STATIC
   src/crypto.cpp
)

target_include_directories(eoslib PUBLIC include)

add_subdirectory(lib)
