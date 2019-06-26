#include <sio4/crypto/sha256.hpp>
#include <eosio/check.hpp>
#include "PicoSHA2/picosha2.h"

namespace sio4 {

using namespace picosha2;

sha256::sha256() {
   init();
}

void sha256::init() {
   buffer_.clear();
   std::fill(data_length_digits_, data_length_digits_ + 4, 0);
   std::copy(detail::initial_message_digest,
             detail::initial_message_digest + 8, h_);
}

void sha256::update(const bytes& input) {
   auto first = input.begin();
   auto last = input.end();
   add_to_data_length(static_cast<word_t>(std::distance(first, last)));
   std::copy(first, last, std::back_inserter(buffer_));
   std::size_t i = 0;
   for (; i + 64 <= buffer_.size(); i += 64) {
      detail::hash256_block(h_, buffer_.begin() + i,
                            buffer_.begin() + i + 64);
   }
   buffer_.erase(buffer_.begin(), buffer_.begin() + i);
}

void sha256::final(bytes& digest) {
   byte_t temp[64];
   std::fill(temp, temp + 64, 0);
   std::size_t remains = buffer_.size();
   std::copy(buffer_.begin(), buffer_.end(), temp);
   temp[remains] = 0x80;

   if (remains > 55) {
      std::fill(temp + remains + 1, temp + 64, 0);
      detail::hash256_block(h_, temp, temp + 64);
      std::fill(temp, temp + 64 - 4, 0);
   } else {
      std::fill(temp + remains + 1, temp + 64 - 4, 0);
   }

   write_data_bit_length(&(temp[56]));
   detail::hash256_block(h_, temp, temp + 64);

   digest.resize(digest_size);
   get_hash_bytes(digest.begin(), digest.end());

   init();
}

void sha256::truncated_final(bytes& digest, size_t size) {
   eosio::check(size <= digest_size, "Invalid digest size");
   final(digest);

   if (size < digest_size) {
      digest.resize(size);
   }
}

template <typename OutIter>
void sha256::get_hash_bytes(OutIter first, OutIter last) const {
   for (const word_t* iter = h_; iter != h_ + 8; ++iter) {
      for (std::size_t i = 0; i < 4 && first != last; ++i) {
         *(first++) = detail::mask_8bit(
            static_cast<byte_t>((*iter >> (24 - 8 * i))));
      }
   }
}

void sha256::add_to_data_length(word_t n) {
   word_t carry = 0;
   data_length_digits_[0] += n;
   for (std::size_t i = 0; i < 4; ++i) {
      data_length_digits_[i] += carry;
      if (data_length_digits_[i] >= 65536u) {
         carry = data_length_digits_[i] >> 16;
            data_length_digits_[i] &= 65535u;
      } else {
         break;
      }
   }
}

void sha256::write_data_bit_length(byte_t* begin) {
   word_t data_bit_length_digits[4];
   std::copy(data_length_digits_, data_length_digits_ + 4,
             data_bit_length_digits);

   // convert byte length to bit length (multiply 8 or shift 3 times left)
   word_t carry = 0;
   for (std::size_t i = 0; i < 4; ++i) {
      word_t before_val = data_bit_length_digits[i];
      data_bit_length_digits[i] <<= 3;
      data_bit_length_digits[i] |= carry;
      data_bit_length_digits[i] &= 65535u;
      carry = (before_val >> (16 - 3)) & 65535u;
   }

   // write data_bit_length
   for (int i = 3; i >= 0; --i) {
      (*begin++) = static_cast<byte_t>(data_bit_length_digits[i] >> 8);
      (*begin++) = static_cast<byte_t>(data_bit_length_digits[i]);
   }
}

}
