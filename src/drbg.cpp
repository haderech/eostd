#include <sio4/crypto/drbg.hpp>

namespace sio4 {

hash_drbg::hash_drbg(const byte* entropy, size_t entropy_length, const byte* nonce, size_t nonce_length, const byte* personalization, size_t personalization_length)
: m_c(seed_length), m_v(seed_length), m_reseed(0) {
   std::memset(m_c.data(), 0x00, m_c.size());
   std::memset(m_v.data(), 0x00, m_v.size());

   if (entropy != nullptr && entropy_length != 0) {
      drbg_instantiate(entropy, entropy_length, nonce, nonce_length, personalization, personalization_length);
   }
}

void hash_drbg::incorporate_entropy(const byte* input, size_t length) {
   return drbg_reseed(input, length, nullptr, 0);
}

void hash_drbg::incorporate_entropy(const byte* entropy, size_t entropy_length, const byte* additional, size_t additional_length) {
   return drbg_reseed(entropy, entropy_length, additional, additional_length);
}

void hash_drbg::generate_block(byte* output, size_t size) {
   hash_generate(nullptr, 0, output, size);
}

void hash_drbg::generate_block(const byte* additional, size_t additional_length, byte* output, size_t size) {
   hash_generate(additional, additional_length, output, size);
}

void hash_drbg::drbg_instantiate(const byte* entropy, size_t entropy_length, const byte* nonce, size_t nonce_length, const byte* personalization, size_t personalization_length) {
   check(entropy_length >= min_entropy_length, "Insufficient entropy during instantiate");
   assert(entropy_length <= max_entropy_length);
   assert(nonce_length <= max_nonce_length);
   assert(personalization_length <= max_personalization_length);

   const byte zero = 0;

   bytes t1(seed_length), t2(seed_length);

   hash_update(entropy, entropy_length, nonce, nonce_length, personalization, personalization_length, nullptr, 0, t1.data(), t1.size());
   hash_update(&zero, 1, t1.data(), t1.size(), nullptr, 0, nullptr, 0, t2.data(), t2.size());

   m_v = t1;
   m_c = t2;
   m_reseed = 1;
}

void hash_drbg::drbg_reseed(const byte* entropy, size_t entropy_length, const byte* additional, size_t additional_length) {
   check(entropy_length >= min_entropy_length, "Insufficient entropy during reseed");
   assert(entropy_length <= max_entropy_length);
   assert(additional_length <= max_additional_length);

   const byte zero = 0;
   const byte one = 1;

   bytes t1(seed_length), t2(seed_length);

   hash_update(&one, 1, m_v.data(), m_v.size(), entropy, entropy_length, additional, additional_length, t1.data(), t1.size());
   hash_update(&zero, 1, t1.data(), t1.size(), nullptr, 0, nullptr, 0, t2.data(), t2.size());

   m_v = t1;
   m_c = t2;
   m_reseed = 1;
}

void hash_drbg::hash_generate(const byte* additional, size_t additional_length, byte* output, size_t size) {
   // Step 1
   check(static_cast<uint64_t>(m_reseed) < static_cast<uint64_t>(max_request_before_reseed), "Reseed required");
   check(size <= max_bytes_per_request, "Request size exceeds limit");
   assert(additional_length <= max_additional_length);

   // Step 2
   if (additional && additional_length) {
      const byte two = 2;
      m_temp.assign(sha256::digest_size, 0);

      m_hash.update(&two, 1);
      m_hash.update(m_v.data(), m_v.size());
      m_hash.update(additional, additional_length);
      m_hash.final(m_temp.data());

      assert(seed_length >= sha256::digest_size);
      int carry = 0;
      int j = sha256::digest_size - 1;
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
      m_hash.update(m_temp.data(), m_temp.size());
      size_t count = std::min(size, (size_t)sha256::digest_size);
      m_hash.truncated_final(output, count);

      incremental_counter_by_one(m_temp.data(), static_cast<unsigned int>(m_temp.size()));
      size -= count;
      output+= count;
   }

   // Steps 4-7
   {
      const byte three = 3;
      m_temp.assign(sha256::digest_size, 0);

      m_hash.update(&three, 1);
      m_hash.update(m_v.data(), m_v.size());
      m_hash.final(m_temp.data());

      assert(seed_length >= sha256::digest_size);
      assert(sha256::digest_size >= sizeof(m_reseed));

      int carry = 0;
      int k = sizeof(m_reseed) - 1;
      int j = sha256::digest_size - 1;
      int i = seed_length - 1;

      while (k >= 0) {
         carry = m_v[i] + m_c[i] + m_temp[j] + ((m_reseed >> (sizeof(uint64_t)-k-1)) & 0xFF) + carry;
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

   m_reseed++;
}

void hash_drbg::hash_update(const byte* input1, size_t inlen1, const byte* input2, size_t inlen2, const byte* input3, size_t inlen3, const byte* input4, size_t inlen4, byte* output, size_t outlen) {
   byte counter = 1;
   uint32_t bits = byte_reverse(static_cast<uint32_t>(outlen * 8));

   while (outlen) {
      m_hash.update(&counter, 1);
      m_hash.update(reinterpret_cast<const byte*>(&bits), 4);

      if (input1 && inlen1)
         m_hash.update(input1, inlen1);
      if (input2 && inlen2)
         m_hash.update(input2, inlen2);
      if (input3 && inlen3)
         m_hash.update(input3, inlen3);
      if (input4 && inlen4)
         m_hash.update(input4, inlen4);

      size_t count = std::min(outlen, (size_t)sha256::digest_size);
      m_hash.truncated_final(output, count);

      output += count;
      outlen -= count;
      counter++;
   }
}

}
