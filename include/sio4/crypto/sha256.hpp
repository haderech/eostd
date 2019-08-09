#pragma once

#include <memory>
#include "../bytes.hpp"

namespace sio4 {

class sha256_impl;

class sha256 {
public:
   static constexpr unsigned int digest_size = 256 / 8; // SHA256

   sha256();

   void init();
   void update(const bytes& input);
   void final(bytes& digest);
   void truncated_final(bytes& digest, size_t size);

private:
   std::shared_ptr<sha256_impl> my;
};

}
