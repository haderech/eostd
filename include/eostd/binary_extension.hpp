#pragma once

#include <eosio/binary_extension.hpp>

namespace eostd {

template<typename T>
class binary_extension : public eosio::binary_extension<T> {
};

}

namespace eosio {

template<typename DataStream, typename T>
inline DataStream& operator<<(DataStream& ds, const eostd::binary_extension<T>& be) {
   if (be) {
      ds << be.value_or();
   }
   return ds;
}

template<typename DataStream, typename T>
inline DataStream& operator>>(DataStream& ds, eostd::binary_extension<T>& be) {
   if (ds.remaining()) {
      T val;
      ds >> val;
      be.emplace(val);
   }
   return ds;
}

}
