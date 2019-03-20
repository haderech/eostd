/**
 * @file
 */
#pragma once

#include <cstdint>

namespace eosio {

   /**
    * Hashes `data` using fasthash32.
    * @brief Hashes `data` using fasthash32.
    *
    * @param data - Data you want to hash
    * @param length - Data length
    * @param seed - Hash seed
    * @return uint32_t - Computed value
    */
   uint32_t fasthash32(const char* data, uint32_t length, uint32_t seed);

   /**
    * Hashes `data` using fasthash64.
    * @brief Hashes `data` using fasthash64.
    *
    * @param data - Data you want to hash
    * @param length - Data length
    * @param seed - Hash seed
    * @return uint64_t - Computed value
    */
   uint64_t fasthash64(const char* data, uint32_t length, uint64_t seed);
}
