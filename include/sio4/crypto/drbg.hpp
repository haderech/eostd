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

   hash_drbg(const bytes& entropy = bytes(), const bytes& nonce = bytes(), const bytes& personalization = bytes());

   void generate_block(bytes& output, size_t size);
   void generate_block(const bytes& additional, bytes& output, size_t size);

protected:
   void drbg_instantiate(const bytes& entropy, const bytes& nonce, const bytes& personalization);
   void drbg_reseed(const bytes entropy, const bytes additional);
   void hash_generate(const bytes& additional, bytes& output, size_t size);
   void hash_update(const bytes& input1, const bytes& input2, const bytes& input3, const bytes& input4, bytes& output, size_t outlen);

private:
   sha256 m_hash;
   bytes m_c, m_v, m_temp;
   uint64_t m_reseed;

   inline void incremental_counter_by_one(bytes& inout, unsigned int size) {
      unsigned int carry = 1;
      while (carry && size != 0) {
         carry = ! ++inout[size-1];
         size--;
      }
   }

   inline bytes byte_reverse(uint32_t value) {
      value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
      value = (value << 16) | (value >> 16);
      return {(byte*)&value, (byte*)&value + sizeof(uint32_t)};
   }
};

}
