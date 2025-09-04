#pragma once

#include <vendor.h>
#include <singleton.hpp>

#ifdef _WIN
#include <MinHook.h> // todo: replace it.
#endif

// at the moment only MinHook version for Windows is written.
// todo: nix, mac.
namespace hooks {

	enum class e_status {

		// general.
		k_success,
		k_not_created,
		k_already_created,
		k_already_enabled,
		k_already_disabled,
		k_invalid_function,

		// internal.
		k_intern_memory_alloc,
		k_intern_memory_protect,

	};

	class c_engine : public c_singleton <c_engine> {

	public:

		inline void init() {

			if (!m_ready.load()) {

#ifdef _WIN
				
				// there is no sense to control init stage of minhook since it's just have two states:
				// - waiting for the init.
				// - already init'ed.

				MH_Initialize();
#endif
				// now we can work.
				m_ready.store(true);
			}

		}

		template <typename T, typename T1>
		inline auto create(T source, T1 replacement) -> std::pair <e_status, uintptr_t> {

			// since sometimes we just don't want to be busy with initing hook engine.
			if (!m_ready.load()) {
				this->init();
			}

			// returning trampoline and status so developer can track current status,
			// and have the address to call, to have an original prologue of the function.
			uintptr_t trampoline = 0;
			auto status = e_status::k_success;

#ifdef _WIN
			status = this->from_library_status(MH_CreateHook(reinterpret_cast <LPVOID> (source), reinterpret_cast <LPVOID> (replacement), reinterpret_cast <LPVOID*> (&trampoline)));
#endif

			return std::make_pair(status, trampoline);
		}

		// misc.
		template <typename T>
		inline auto enable(T source) -> e_status {

			auto status = e_status::k_success;

#ifdef _WIN

			status = from_library_status(MH_EnableHook(reinterpret_cast <LPVOID> (source)));

#endif

			return status;
		}

		template <typename T>
		inline auto disable(T source) -> e_status {

			auto status = e_status::k_success;

#ifdef _WIN
			status = from_library_status(MH_DisableHook(reinterpret_cast <LPVOID> (source)));
#endif

			return status;
		}

		template <typename T>
		inline auto remove(T source) -> e_status {

			auto status = e_status::k_success;

#ifdef _WIN
			status = from_library_status(MH_RemoveHook(reinterpret_cast <LPVOID> (source)));
#endif

			return status;
		}

	private:

		// convert a library status to local status.
		inline auto from_library_status(uint64_t lib_status) -> e_status {


#ifdef _WIN 

			// currently, a minhook for windows since it's pretty universal and supports both of x86/x64.
			// https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L38.
			switch (lib_status) {

				default: {
					assert("windows: unknown error in hooking engine!");
				}; break;

				case MH_OK: return e_status::k_success;

				case MH_ERROR_ALREADY_CREATED: return e_status::k_already_created;
				case MH_ERROR_NOT_CREATED: return e_status::k_not_created;
				case MH_ERROR_ENABLED: return e_status::k_already_enabled;
				case MH_ERROR_DISABLED: return e_status::k_already_disabled;

				case MH_ERROR_NOT_EXECUTABLE:
				case MH_ERROR_UNSUPPORTED_FUNCTION: return e_status::k_invalid_function;

				case MH_ERROR_MEMORY_ALLOC: return e_status::k_intern_memory_alloc;
				case MH_ERROR_MEMORY_PROTECT: return e_status::k_intern_memory_protect;

			}

#endif

		}

	private:

		// is hook engine ready to create hooks?
		std::atomic_bool m_ready = false;

	};

}