#pragma once

#include <vendor.h>

// note: hs stands for 'hash_string'.
namespace hash {

    // [fnv1a32 & fnv1a64] runtime and compile-time variants.
    // 
    // algorithm:
    // hash: = FNV_offset_basis
    // 
    // for each byte_of_data to be hashed do
    // hash : = hash XOR byte_of_data
    // hash : = hash × FNV_prime
    //
    // return hash
    //
    // source code was taken (and slightly modified) from:
    // https://gist.github.com/ruby0x1/81308642d0325fd386237cfa3b44785c.

    // a little compile-time trick which allowing to insert fnv1a-string in whatever place.
    #define hs_fnv1a32(string) []{ constexpr auto str = hash::fnv1a32_ct(string); return str; }()
    #define hs_fnv1a64(string) []{ constexpr auto str = hash::fnv1a64_ct(string); return str; }()

    static inline const auto fnv1a32_rt(const char* data, const uint32_t length) {

        uint32_t hash = 0x811c9dc5, prime = 0x1000193;
        for (uint32_t element_id = 0; element_id < length; ++element_id) {

            uint8_t value = data[element_id];

            hash = hash ^ value;
            hash *= prime;

        }

        return hash;
    }

    static inline constexpr uint32_t fnv1a32_ct(const char* const string, const uint32_t hash = 0x811c9dc5) noexcept {
        return (string[0] == '\0') ? hash : fnv1a32_ct(&string[1], (hash ^ uint32_t((uint8_t)string[0])) * 0x1000193);
    }

    static inline const auto fnv1a64_rt(const char* data, const uint64_t length) {

        uint64_t hash = 0xcbf29ce484222325, prime = 0x100000001b3;
        for (uint64_t element_id = 0; element_id < length; ++element_id) {

            uint8_t value = data[element_id];

            hash = hash ^ value;
            hash *= prime;

        }

        return hash;
    }

    static inline constexpr uint64_t fnv1a64_ct(const char* const string, const uint64_t hash = 0xcbf29ce484222325) noexcept {
        return (string[0] == '\0') ? hash : fnv1a64_ct(&string[1], (hash ^ uint64_t((uint8_t)string[0])) * 0x100000001b3);
    }

}