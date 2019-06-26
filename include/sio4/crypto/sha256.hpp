#pragma once

#include <vector>
#include <cstdint>

namespace sio4 {

class sha256 {
public:
   using bytes = std::vector<int8_t>;
   using byte_t = uint8_t;
   using word_t = uint32_t;

   static constexpr unsigned int digest_size = 256 / 8; // SHA256

   sha256();

   void init();
   void update(const bytes& input);
   void final(bytes& digest);
   void truncated_final(bytes& digest, size_t size);

private:
   std::vector<byte_t> buffer_;
   word_t data_length_digits_[4];  // as 64bit integer (16bit x 4 integer)
   word_t h_[8];

   template <typename OutIter>
   void get_hash_bytes(OutIter first, OutIter last) const;
   void add_to_data_length(word_t n);
   void write_data_bit_length(byte_t* begin);
};

}
