# EOSTD

EOSTD (EOSIO Standard Library) is an alternative implementation of contract library.

## Prerequisites

This requires [eoscc](https://github.com/b1ockchain/eoscc) v1.6.3 or higher.

## How to use

Add below lines to your `CMakeLists.txt` when building smart contract.

``` cmake
add_subdirectory(${CMAKE_SOURCE_DIR}/../eostd ${CMAKE_BINARY_DIR}/../eostd)

# option 1: make specific target link library
target_link_libraries(YOUR_CONTRACT_TARGET eostd)

# option 2: make all targets link library
link_libraries(eostd)
```
