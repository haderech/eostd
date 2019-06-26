#pragma once

#include <eosio/print.hpp>

namespace sio4 {

template<typename... Args>
inline void dlog(Args&&... args) {
#ifndef NDEBUG
   eosio::print(std::forward<Args>(args)...);
#endif
}

} /// namespace sio4
