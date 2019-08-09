#pragma once

#include <eosio/check.hpp>
#include <cstring>
#include "sha256.hpp"
#include "../bytes.hpp"

namespace sio4 {

using namespace eosio;

class hash_drbg {
public:
   static constexpr unsigned int security_strength = 128 / 8;
   static constexpr unsigned int seed_length = 440 / 8;
   static constexpr unsigned int min_entropy_length = 128 / 8;
   static constexpr unsigned int max_entropy_length = std::numeric_limits<unsigned int>::max();
   static constexpr unsigned int min_nonce_length = 0;
   static constexpr unsigned int max_nonce_length = std::numeric_limits<unsigned int>::max();
   static constexpr unsigned int min_additional_length = 0;
   static constexpr unsigned int max_additional_length = std::numeric_limits<unsigned int>::max();
   static constexpr unsigned int min_personalization_length = 0;
   static constexpr unsigned int max_personalization_length = std::numeric_limits<unsigned int>::max();
   static constexpr unsigned int max_bytes_per_request = 65536;
   static constexpr unsigned int max_request_before_reseed = std::numeric_limits<unsigned int>::max();

   hash_drbg(const byte* entropy = nullptr, size_t entropy_length = 0, const byte* nonce = nullptr, size_t nonce_length = 0,
      const byte* personalization = nullptr, size_t personalization_length = 0);

   void incorporate_entropy(const byte* input, size_t length);
   void incorporate_entropy(const byte* entropy, size_t entropy_length, const byte* additional, size_t additional_length);
   void generate_block(byte* output, size_t size);
   void generate_block(const byte* additional, size_t additional_length, byte* output, size_t size);

protected:
   void drbg_instantiate(const byte* entropy, size_t entropy_length, const byte* nonce, size_t nonce_length,
      const byte* personalization, size_t personalization_length);
   void drbg_reseed(const byte* entropy, size_t entropy_length, const byte* additional, size_t additional_length);
   void hash_generate(const byte* additional, size_t additional_length, byte* output, size_t size);
   void hash_update(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2, const byte* input3, size_t inlen3,
      const byte* input4, size_t inlen4, byte* output, size_t outlen);

private:
   sha256 m_hash;
   bytes m_c, m_v, m_temp;
   uint64_t m_reseed;

   inline void incremental_counter_by_one(byte* inout, unsigned int size) {
      assert(inout != nullptr);

      unsigned int carry = 1;
      while (carry && size != 0) {
         carry = ! ++inout[size-1];
         size--;
      }
   }

   inline uint32_t byte_reverse(uint32_t value) {
      value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
      value = (value << 16) | (value >> 16);
      return value;
   }
};

}
