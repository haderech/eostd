#include <sio4/crypto/sha256.hpp>
#include <eosio/check.hpp>
#include "sha256/sha256.h"

namespace sio4 {

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

void sha256::update(const bytes& input) {
   my->update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

void sha256::final(bytes& digest) {
   my->final(reinterpret_cast<uint8_t*>(digest.data()));
   my->init();
}

void sha256::truncated_final(bytes& digest, size_t size) {
   eosio::check(size <= digest_size, "Invalid digest size");

   digest.resize(SHA256_DIGEST_LENGTH);
   final(digest);

   if (size < digest_size) {
      digest.resize(size);
   }
}

}
