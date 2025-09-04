#pragma once

#include <vendor.h>
#include <hash.hpp>
#include <os/nt.hpp>

namespace memscan {

	#define generate_signature(code, mask) []{ constexpr memscan::codesig_t result(code, mask); return result; }()
	#define generate_signature_ref(code, mask) []{ constexpr memscan::codesig_t result(code, mask, 0, true); return result; }()
	#define generate_signature_ex(code, mask, shift, ref) []{ constexpr memscan::codesig_t result(code, mask, shift, ref); return result; }()


	//
	// code:'\x48\x8B\x03\x48\x00'
	//         ^                ^
	//         |                |
	//         |                |
	//         ^                |
	// mask: '[x]xxxx[?]'       |
	//                ^         |
	//                |         |
	//                > - - - - ^
	//

	struct codesig_t {

		const char* code;
		const char* mask;

		uint64_t shift = 0; // shift from the dst.

		// there is actually two types of xref's that currently supported (without disasm, x64, todo?)
		// 1. call/jmp to some function. (5 bytes total)
		// 2. reference to some global variable. (cmp/mov which is 7 bytes total)
		bool is_xref = false;

		// hash of signature for external purposes.
		uint64_t hash = 0;

		// compile-time hash computation.
		constexpr codesig_t(const char* code, const char* mask, uint64_t shift = 0, bool xref = false) {

			this->code = code;
			this->mask = mask;
			this->shift = shift;
			this->is_xref = xref;

			// skip first 5 bytes since they include '\x00', we can't rely on that and make non-collision hash.
			if (xref) {
				this->hash = (hash::fnv1a64_ct(&code[5]) + xref) * hash::fnv1a64_ct(mask);
			} else {
				this->hash = (hash::fnv1a64_ct(code) + xref) * hash::fnv1a64_ct(mask);
			}

		}

		// currently used for internal purposes, but not limited to be extended.
		static inline auto generate_hash(codesig_t& instance) {

			// mask length is equals to code length.
			auto length = strlen(instance.mask);
			
			if (length) {
				instance.hash = (hash::fnv1a64_rt(instance.code, length) + instance.is_xref) * hash::fnv1a64_rt(instance.mask, length);
			}

			return instance.hash;
		}

	};

	static bool lookup_mask(uint8_t* base, uint8_t* pattern, uint8_t* mask) {

		for (; *mask; ++base, ++pattern, ++mask) {

			// shifting from one index to another, until end of the mask.
			if (*mask == 'x' && *base != *pattern) {
				return false;
			}

		}

		return true;
	}

	template <typename T>
	static inline uint8_t* lookup_code(T memory, uint64_t size, codesig_t signature) {

		// for doing memory lookup by index we actually need accessing to only one byte value.
		auto base = reinterpret_cast <uint8_t*> (memory);

		for (uint64_t index = 0; index <= size - strlen(signature.mask); ++index) {

			// basically, base + index;
			uint8_t* address = &base[index];

			// check if it's fits.
			// 
			// todo: change casts.
			if (memscan::lookup_mask(address, (uint8_t*) signature.code, (uint8_t*) signature.mask)) {

				// todo: length-based disassembler for xrefs. 
				// (currently i see no sense in that)
				if (signature.is_xref) {

					// call / jmp.
					if (*address == 0xE8 || *address == 0xE9) {
						address += *reinterpret_cast <int32_t*> (address + 0x1) + 0x5;
					}

					// cmp / mov.
					else if (*address == 0x80 || *address == 0x81 || *address == 0xC6) {
						address += *reinterpret_cast <int32_t*> (address + 0x2) + 0x7;
					}

				}

				return address + signature.shift;
			}

		}

		return 0;
	}

	// os-depend function, be aware.
	template <typename T>
	static inline auto lookup_library_code(T memory, codesig_t signature) {

		// we're using platform headers only to parse important library elements,
		// such as VA of section and it's size.
		using namespace os;

		// we're still playing with bytes and calling 'lookup_code' function.
		// so, need to cast.
		auto base = reinterpret_cast <uint8_t*> (memory);

		// value to be stored. (we can use auto since already give it type)
		uint8_t* result = 0;

#ifdef _WIN // not sure about 32-bits, tests?

		auto sections = nt::get_first_section(base);		
		for (uint16_t index = 0; index < nt::get_nt_headers(base)->file.number_of_sections; index++) {

			// let's check if we can even read that, and if it's contains code.
			if ((sections[index].characts & 0x00000020) && (sections[index].characts & 0x20000000) && !(sections[index].characts & 0x2000000)) {

				result = memscan::lookup_code(base + sections[index].va, sections[index].raw_size, signature);

				// did we found something?
				if (result) {
					break;
				}

			}

		}

		if (!result) {
			__debugbreak();
		}

#endif
		return result;
	}

}