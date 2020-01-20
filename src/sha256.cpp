#include <eostd/crypto/sha256.hpp>
#include <eosio/check.hpp>
#include "sha256/sha256.h"

namespace eostd {

class sha256_impl {
public:
   sha256_impl() {
      init();
   }

   void init() {
      SHA256Init(&context);
   }

   void update(const uint8_t* input, size_t length) {
      SHA256Update(&context, input, length);
   }

   void final(uint8_t digest[SHA256_DIGEST_LENGTH]) {
      SHA256Final(&context, digest);
   }

private:
   SHA256CTX context;
};


sha256::sha256(): my(std::make_shared<sha256_impl>()) {
}

void sha256::init() {
   my->init();
}

void sha256::update(const byte* input, size_t length) {
   my->update(input, length);
}

void sha256::final(byte* digest) {
   my->final(digest);
   my->init();
}

void sha256::truncated_final(byte* digest, size_t size) {
   eosio::check(size <= digest_size, "Invalid digest size");

   byte output[SHA256_DIGEST_LENGTH];
   final(output);

   std::memcpy(digest, output, size);
}

}
