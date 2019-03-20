cmake_minimum_required(VERSION 3.5)

project(eosio-xt)

add_library(eosio-xt STATIC
   src/crypto.cpp
)

target_include_directories(eosio-xt PUBLIC include)

add_subdirectory(libraries)
