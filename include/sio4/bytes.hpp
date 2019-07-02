#pragma once

#include <eosio/datastream.hpp>

namespace sio4 {

struct bytes : std::vector<int8_t> {
   template<typename T>
   T as() { return eosio::unpack<T>(*this); }
};

}
