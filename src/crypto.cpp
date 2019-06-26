#include <sio4/crypto.hpp>
#include "xxHash/xxhash.h"

uint32_t sio4::xxh32(const char* data, uint32_t length, uint32_t seed) {
   return ::XXH32(data, length, seed);
}

uint64_t sio4::xxh64(const char* data, uint32_t length, uint64_t seed) {
   return ::XXH64(data, length, seed);
}
