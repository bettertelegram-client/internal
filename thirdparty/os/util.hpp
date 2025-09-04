#pragma once

#include <vendor.h>
#include <cstdlib>
#include <array>

// todo: mac & nix.
namespace os {

	template <typename T>
	static inline bool validate_address(T address) {

		// let's convert types so we can compare it as an integer on different kind of platform/arch's.
		auto value = (uintptr_t)address;

		// first 64kb is an unaccessible, so, we just skipping it.
		bool is_valid = (value > 0xFA00 && value < 0x7fffffffffff);

		// idea behind this check is actually pretty primitive:
		// - "let's check if page even exist in memory by checking it's protection flags."

		// todo: mprotect for the nix.
		if (is_valid) {

#ifdef _WIN // since we're using WinAPI there is no need to check for structure alignments and offsets. (64/32 bit)
			MEMORY_BASIC_INFORMATION info;
			if (VirtualQuery(reinterpret_cast <LPCVOID>(address), &info, sizeof(info))) {
				is_valid = !(info.Protect & PAGE_NOACCESS) && !(info.Protect & PAGE_GUARD);
			}
#endif

		}

		return is_valid;
	}

	template <typename T = uint8_t, size_t set_size = 0, typename T1, typename... Args>
	static inline bool write_execute(T1 address, Args... args) {

		// each write function will be unique because array is get created at the compile-time.
		constexpr size_t arguments_count = set_size ? set_size : sizeof...(Args);
		constexpr size_t arguments_size = sizeof(T) * arguments_count;

		// validating target address firstly...
		if (validate_address <T1>(address)) {

#ifdef _WIN

			// let's change the protection to RWX so we can write target bytes.
			DWORD old_protect = 0;

			// by default windows will automatically align count to 4KB, or to page size.
			// we don't have to call 'VirtualQuery' each time for it.
			if (!VirtualProtect(reinterpret_cast <LPVOID> (address), arguments_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
				return false; // as documentation says "If the function succeeds, the return value is nonzero.".
			}

#endif

			// copy bytes from va_args to the buffer.
			std::array <T, arguments_count> buffer = { args... };

			// point of using memset/memcpy is extra simple at the moment.
			// 
			// i don't see any other rational fast variants to avoid threat-race for the target address,
			// since at the moment i'm not handling application threads. (e.g freezing/etc)
			//
			// so, in the end of times, it's just a question of speed against other threads.
			if constexpr (set_size > 0) {
				std::memset(reinterpret_cast <void*> (address), buffer.at(0), arguments_size);
			}
			else {
				std::memcpy(reinterpret_cast <void*> (address), buffer.data(), arguments_size);
			}

			// anyway, now we need change protect to the previous state.
#ifdef _WIN

			// i don't really a big sense to add some checks for result validity of this function.
			// anyway, our task is done, even if we can't return old page protection, we're still successing.
			DWORD new_protect = 0;
			VirtualProtect(reinterpret_cast <LPVOID> (address), arguments_size, old_protect, &new_protect);

#endif

			return true;
		}

		return false;
	}

	static inline bool confirm_box(QString title, QString text) {

#ifdef _WIN
		return MessageBoxA(0, text.toLocal8Bit().data(), title.toLocal8Bit().data(), MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON1 | MB_TASKMODAL) == IDYES;
#endif

	}

}