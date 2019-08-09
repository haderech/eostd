#include <sio4/crypto/drbg.hpp>

namespace sio4 {

hash_drbg::hash_drbg(const bytes& entropy, const bytes& nonce, const bytes& personalization)
: m_c(seed_length), m_v(seed_length), m_reseed(0) {
   std::memset(m_c.data(), 0x00, m_c.size());
   std::memset(m_v.data(), 0x00, m_v.size());

   if (!entropy.empty()) {
      drbg_instantiate(entropy, nonce, personalization);
   }
}

void hash_drbg::generate_block(bytes& output, size_t size) {
   hash_generate(bytes(), output, size);
}

void hash_drbg::generate_block(const bytes& additional, bytes& output, size_t size) {
   hash_generate(additional, output, size);
}

void hash_drbg::drbg_instantiate(const bytes& entropy, const bytes& nonce, const bytes& personalization) {
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

void hash_drbg::drbg_reseed(const bytes entropy, const bytes additional) {
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

void hash_drbg::hash_generate(const bytes& additional, bytes& output, size_t size) {
   // Step 1
   check(static_cast<uint64_t>(m_reseed) < static_cast<uint64_t>(max_request_before_reseed), "Reseed required");
   check(size <= max_bytes_per_request, "Request size exceeds limit");
   assert(additional.size() <= max_additional_length);

   // Step 2
   if (!additional.empty()) {
      const bytes two = { 2 };

      m_hash.update(two);
      m_hash.update(m_v);
      m_hash.update(additional);
      m_hash.final(m_temp);

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
   output.resize(0);
   m_temp.assign(m_v.begin(), m_v.end());
   while (size) {
      m_hash.update(m_temp);
      size_t count = std::min(size, (size_t)sha256::digest_size);

      bytes out;
      m_hash.truncated_final(out, count);

      incremental_counter_by_one(m_temp, static_cast<unsigned int>(m_temp.size()));
      size -= count;
      output.insert(output.end(), out.begin(), out.end());
   }

   // Steps 4-7
   {
      const bytes three = { 3 };
      m_temp.assign(sha256::digest_size, 0);

      m_hash.update(three);
      m_hash.update(m_v);
      m_hash.final(m_temp);

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

void hash_drbg::hash_update(const bytes& input1, const bytes& input2, const bytes& input3, const bytes& input4, bytes& output, size_t outlen) {
   bytes counter = { 1 };
   bytes bits = byte_reverse(static_cast<uint32_t>(outlen * 8));

   while (outlen) {
      m_hash.update(counter);
      m_hash.update(bits);

      if (!input1.empty())
         m_hash.update(input1);
      if (!input2.empty())
         m_hash.update(input2);
      if (!input3.empty())
         m_hash.update(input3);
      if (!input4.empty())
         m_hash.update(input4);

      size_t count = std::min(outlen, (size_t)sha256::digest_size);

      bytes out;
      m_hash.truncated_final(out, count);
      output.insert(output.end(), out.begin(), out.end());
      outlen -= count;
      counter[0]++;
   }
}

}
