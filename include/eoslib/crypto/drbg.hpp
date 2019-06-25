#pragma once

#include <eoslib/types.hpp>
#include <eosio/check.hpp>
#include <cstring>

#include "PicoSHA2/picosha2.h"

namespace eosio {

class hash_drbg {
public:
   using HASH = picosha2::hash256_one_by_one;

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
   static constexpr unsigned int digest_size = 256 / 8; // SHA256

   hash_drbg(const bytes& entropy = bytes(), const bytes& nonce = bytes(), const bytes& personalization = bytes()) {
      m_c.resize(seed_length);
      m_v.resize(seed_length);

      std::memset(m_c.data(), 0x00, m_c.size());
      std::memset(m_v.data(), 0x00, m_v.size());

      if (!entropy.empty()) {
         drbg_instantiate(entropy, nonce, personalization);
      }
   }

   void generate_block(bytes& output, size_t size) {
      hash_generate(bytes(), output, size);
   }

   void generate_block(const bytes& additional, bytes& output, size_t size) {
      hash_generate(additional, output, size);
   }

protected:
   void drbg_instantiate(const bytes& entropy, const bytes& nonce, const bytes& personalization) {
      check(entropy.size() >= min_entropy_length, "Insufficient entropy during instantiate");
      assert(entropy.size() <= max_entropy_length);
      assert(nonce.size() <= max_nonce_length);
      assert(personalization.size() <= max_personalization_length);

      const bytes zero = { 0 };
      const bytes null = bytes();

      bytes t1, t2;

      hash_update(entropy, nonce, personalization, null, t1, seed_length);
      hash_update(zero, t1, null, null, t2, seed_length);

      m_v = t1;
      m_c = t2;
      m_reseed = 1;
   }

   void drbg_reseed(const bytes entropy, const bytes additional) {
      check(entropy.size() >= min_entropy_length, "Insufficient entropy during reseed");
      assert(entropy.size() <= max_entropy_length);
      assert(additional.size() <= max_additional_length);

      const bytes zero = { 0 };
      const bytes one = { 1 };
      const bytes null = bytes();

      bytes t1, t2;
      t1.resize(seed_length);
      t2.resize(seed_length);

      hash_update(one, m_v, entropy, additional, t1, t1.size());
      hash_update(zero, t1, null, null, t2, t2.size());

      m_v = t1;
      m_c = t2;
      m_reseed = 1;
   }

   void hash_generate(const bytes& additional, bytes& output, size_t size) {
      // Step 1
      check(static_cast<uint64_t>(m_reseed) < static_cast<uint64_t>(max_request_before_reseed), "Reseed required");
      check(size <= max_bytes_per_request, "Request size exceeds limit");
      assert(additional.size() <= max_additional_length);

      // Step 2
      if (!additional.empty()) {
         const bytes two = { 2 };

         m_hash.process(two.begin(), two.end());
         m_hash.process(m_v.begin(), m_v.end());
         m_hash.process(additional.begin(), additional.end());

         m_temp = truncated_final(m_hash, digest_size);

         assert(seed_length >= digest_size);
         int carry = 0;
         int j = digest_size - 1;
         int i = seed_length - 1;

         while (j >= 0) {
            carry = m_v[i] + m_temp[j] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--;
            j--;
            carry >>= 8;
         }
         while (i >= 0) {
            carry = m_v[i] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--;
            carry >>= 8;
         }
      }

      // Step 3
      m_temp.assign(m_v.begin(), m_v.end());
      while (size) {
         m_hash.process(m_temp.begin(), m_temp.end());
         size_t count = std::min(size, (size_t)digest_size);
         auto out = truncated_final(m_hash, count);
         incremental_counter_by_one(m_temp, static_cast<unsigned int>(m_temp.size()));
         size -= count;
         output.insert(output.end(), out.begin(), out.end());
      }

      // Steps 4-7
      {
         const bytes three = { 3 };
         m_temp.assign(digest_size, 0);

         m_hash.process(three.begin(), three.end());
         m_hash.process(m_v.begin(), m_v.end());
         m_temp = truncated_final(m_hash, digest_size);

         assert(seed_length >= digest_size);
         assert(digest_size >= sizeof(m_reseed));

         int carry = 0;
         int k = sizeof(m_reseed) - 1;
         int j = digest_size - 1;
         int i = seed_length - 1;

         while (k >= 0) {
            carry = m_v[i] + m_c[i] + m_temp[j] + (m_reseed & 0xFF << (sizeof(uint64_t)-k-1)) + carry;
            m_v[i] = static_cast<byte>(carry);
            i--;
            j--;
            k--;
            carry >>= 8;
         }
         while (j >= 0) {
            carry = m_v[i] + m_c[i] + m_temp[j] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--;
            j--;
            carry >>= 8;
         }
         while (i >= 0) {
            carry = m_v[i] + m_c[i] + carry;
            m_v[i] = static_cast<byte>(carry);
            i--;
            carry >>= 8;
         }
      }
   }

   void hash_update(const bytes& input1, const bytes& input2, const bytes& input3, const bytes& input4, bytes& output, size_t outlen) {
      bytes counter = { 1 };
      bytes bits = byte_reverse(static_cast<uint32_t>(outlen * 8));

      while (outlen) {
         m_hash.process(counter.begin(), counter.end());
         m_hash.process(bits.begin(), bits.end());

         if (!input1.empty())
            m_hash.process(input1.begin(), input1.end());
         if (!input2.empty())
            m_hash.process(input2.begin(), input2.end());
         if (!input3.empty())
            m_hash.process(input3.begin(), input3.end());
         if (!input4.empty())
            m_hash.process(input4.begin(), input4.end());

         size_t count = std::min(outlen, (size_t)digest_size);
         auto out = truncated_final(m_hash, count);
         output.insert(output.end(), out.begin(), out.end());
         outlen -= count;
         counter[0]++;
      }
   }

private:
   HASH m_hash;
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

   bytes truncated_final(HASH& hasher, size_t outlen) {
      bytes out;
      out.resize(digest_size);

      hasher.finish();
      hasher.get_hash_bytes(out.begin(), out.end());
      hasher.init();

      if (outlen < hash_drbg::digest_size)
         out.resize(outlen);

      return out;
   }
};

}
