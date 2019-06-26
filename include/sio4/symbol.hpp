#pragma once

#include <eosio/symbol.hpp>

namespace sio4 {

   struct extended_symbol_code {

      constexpr extended_symbol_code() = default;

      constexpr explicit extended_symbol_code( uint128_t raw )
      : code(raw), contract(raw >> 64)
      {}

      constexpr explicit extended_symbol_code( symbol_code s, name c )
      : code(s), contract(c)
      {}

      constexpr explicit extended_symbol_code( std::string_view str )
      : code(0), contract(0)
      {
         auto at_pos = str.find('@');
         if (at_pos == std::string_view::npos) {
            eosio::check(false, "extended symbol should contain '@'");
         }
         code = symbol_code(str.substr(0, at_pos));
         contract = name(str.substr(at_pos+1));
      }

      constexpr uint128_t raw()const { return (uint128_t)contract.value << 64 | code.raw(); }

      constexpr explicit operator bool()const { return !code.raw() && !contract.value; }

      std::string to_string()const {
         return code.to_string() + "@" + contract.to_string();
      }

      inline void print()const {
         auto str = to_string();
         if (str.size())
            printl(str.data(), str.size());
      }

      friend constexpr bool operator == ( const extended_symbol_code& a, const extended_symbol_code& b ) {
         return std::tie(a.code, a.contract) == std::tie(b.code, b.contract);
      }

      friend constexpr bool operator != ( const extended_symbol_code& a, const extended_symbol_code& b ) {
         return std::tie(a.code, a.contract) != std::tie(b.code, b.contract);
      }

      friend constexpr bool operator < ( const extended_symbol_code& a, const extended_symbol_code& b ) {
         return std::tie(a.code, a.contract) < std::tie(b.code, b.contract);
      }

      symbol_code code; ///< symbol code
      name contract; ///< the token contract hosting the symbol

      EOSLIB_SERIALIZE(extended_symbol_code, (code)(contract))
   };

}
