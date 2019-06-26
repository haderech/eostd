# LiBSiO<sub>4</sub>

Lithium Borosilicate is a collection of open source libraries for EOSIO smart contract.

## Prerequisites

This requires [eosio.cdt](https://github.com/EOSIO/eosio.cdt) v1.6.1 or higher. `eosio-ar` is not installed by default, so you need to create symbolic link. 

__Ubuntu__

``` console
$ sudo ln -s /usr/opt/eosio.cdt/1.6.1/bin/eosio-ar /usr/bin/eosio-ar
```

__macOS__

``` console
$ sudo ln -s /usr/local/Cellar/eosio.cdt/1.6.1/bin/eosio-ar /usr/local/bin/eosio-ar
```

## How to use

Add below lines to your `CMakeLists.txt` when building smart contract.

``` cmake
add_subdirectory(${CMAKE_SOURCE_DIR}/../libsio4 ${CMAKE_BINARY_DIR}/../libsio4)

# option 1: make specific target link library
target_link_libraries(YOUR_CONTRACT_TARGET sio4)

# option 2: make all targets link library
link_libraries(sio4)
```

## Nota bene

Formerly __EOSLib__ used namespace `eosio`, but __LiBSiO<sub>4</sub>__ uses namespace `sio4` to avoid conflict. You may need to add `using namespace sio4;` for convenience.
