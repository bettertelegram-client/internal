#pragma once

#include <vendor.h>
#include <cwchar>

namespace formatter {

	// single-byte variant. (ascii)
	template <typename... Args>
	static inline std::string to_string(std::string string, Args... args) {

		// extra space for '\0'.
		auto size = static_cast <size_t> (std::snprintf(nullptr, 0, string.c_str(), args...) + 1);

		std::unique_ptr <char[]> buffer(new char[size]);
		std::snprintf(buffer.get(), size, string.c_str(), args...);

		return std::string(buffer.get(), buffer.get() + size - 1);
	}

	// multi-byte variant. (utf-8)
	template <typename... Args>
	static inline std::wstring to_wide(std::wstring string, Args... args) {

		// extra space for '\0'.
		auto size = static_cast <size_t> (std::swprintf(nullptr, 0, string.c_str(), args...) + 2);

		std::unique_ptr <wchar_t[]> buffer(new wchar_t[size]);
		std::swprintf(buffer.get(), size, string.c_str(), args...);

		return std::wstring(buffer.get(), buffer.get() + size - 2);
	};

}