#pragma once

#include <vendor.h>
#include <hash.hpp>
#include <memscan.hpp>
#include <singleton.hpp>

#include <map>
#include <utility>

// [MEMORY.HPP] -> todo: nix, mac.
namespace telegram::memory {

	// https://en.wikipedia.org/wiki/X86_calling_conventions.
	// https://en.wikipedia.org/wiki/Calling_convention.
	enum class e_func_conv {

		k_fastcall,
		k_stdcall,
		k_cdecl,
		k_thiscall,
		k_vectorcall

	};

	class c_memory_util : public c_singleton <c_memory_util> {

	public:

		c_memory_util() {

#ifdef _WIN
			m_image = reinterpret_cast <uintptr_t> (GetModuleHandleA("Telegram.exe"));
#endif

		}

		// returns base address of 'Telegram' module in the memory.
		inline auto get_image() {
			return m_image;
		}

		// basically, if this signature going to be searched only once, 
		// we don't need to emplace it into map.
		inline auto search(memscan::codesig_t sig) {
			return reinterpret_cast <uintptr_t> (memscan::lookup_library_code(m_image, sig));
		}

		inline auto search_cache_or_create(const memscan::codesig_t sig) {

			// doing cached search to avoid spending of a resources.
			if (m_signature_cache.contains(sig.hash)) {
				return m_signature_cache.at(sig.hash);
			}

			// shit happens.
			auto result = reinterpret_cast <uintptr_t> (memscan::lookup_library_code(m_image, sig));
			m_signature_cache.emplace(sig.hash, result);

			return result;
		}

		// just like that:
		// call <function_return_type> (signature, arg1, arg2, arg3, ...)
		template <typename T, e_func_conv conv = e_func_conv::k_fastcall, typename... Args>
		inline T call(memscan::codesig_t sig, Args... args) noexcept {
			return call <T, conv> (search_cache_or_create(sig), std::forward <Args> (args)...);
		}

		template <typename T, e_func_conv conv = e_func_conv::k_fastcall, typename... Args>
		inline T call(uintptr_t dest, Args... args) noexcept {

			switch (conv) {

				default: {
					assert("unknown call-convention was passed.");
				}; break;

#ifdef _WIN

				case e_func_conv::k_fastcall: {
					using fastcall_func_t = T (*__fastcall) (Args...);
					return reinterpret_cast <fastcall_func_t> (dest) (std::forward <Args>(args)...);
				};

				case e_func_conv::k_stdcall: {
					using stdcall_func_t = T (*__stdcall) (Args...);
					return reinterpret_cast <stdcall_func_t> (dest) (std::forward <Args>(args)...);
				};

				case e_func_conv::k_cdecl: {
					using cdecl_func_t = T (*__cdecl) (Args...);
					return reinterpret_cast <cdecl_func_t> (dest) (std::forward <Args>(args)...);
				};

				case e_func_conv::k_thiscall: {
					using thiscall_func_t = T (*__thiscall) (Args...);
					return reinterpret_cast <thiscall_func_t> (dest) (std::forward <Args>(args)...);
				};

				case e_func_conv::k_vectorcall: {
					using vectorcall_func_t = T (*__vectorcall) (Args...);
					return reinterpret_cast <vectorcall_func_t> (dest) (std::forward <Args>(args)...);
				};

#endif

			}

			// should never hit that.
			__debugbreak();
		}

	private:

		uintptr_t m_image;
		std::map <uint64_t, uintptr_t> m_signature_cache;

	};

}