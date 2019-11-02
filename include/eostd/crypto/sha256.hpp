#pragma once

#include <memory>
#include "../bytes.hpp"

namespace eostd {

class sha256_impl;

class sha256 {
public:
   static constexpr unsigned int digest_size = 256 / 8; // SHA256

   sha256();

   void init();
   void update(const byte* input, size_t length);
   void final(byte* digest);
   void truncated_final(byte* digest, size_t size);

private:
   std::shared_ptr<sha256_impl> my;
};

}
