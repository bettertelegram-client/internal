#pragma once

#include <vendor.h>
#include <formatter.hpp>

#include <fstream>
#include <filesystem>
#include <atomic>

namespace output {

	struct bt_plugin_conf {
		std::atomic<int> otr{0};
		std::atomic<int> ghost{0};
		std::atomic<int> purge{0};

		bool is_plugin_enabled(std::string_view name) const {
			return true;

			if (name == "otr") return otr.load() != 0;
			if (name == "ghost") return ghost.load() != 0;
			if (name == "purge") return purge.load() != 0;
			return false;
		}
	};

	inline bt_plugin_conf g_bt_plugin_conf;

	static inline void alloc_console() {
		return;

		// allocating console.
#ifdef _WIN
		// https://learn.microsoft.com/ru-ru/windows/console/allocconsole.
		AllocConsole();
#endif

		// redirect application output to our stream.
		// https://en.cppreference.com/w/c/io/freopen. (basically, a universal thing)
		FILE* file = nullptr;
		freopen_s(&file, "CONOUT$", "w", stdout);

		// utf-8 support.
#ifdef _WIN
		SetConsoleOutputCP(65001);
#endif

	}

	// single-byte variant. (ascii)
	template <typename... Args>
	static inline void to_console(std::string value, Args... args) {
		return;
		printf("[BetterTelegram] %s\n", formatter::to_string(value, std::forward <Args> (args)...).c_str());
	}

	// multi-byte variant. (utf-8)
	template <typename... Args>
	static inline void to_console(std::wstring value, Args... args) {
		return;
		wprintf(L"[BetterTelegram] %s\n", formatter::to_wide(value, std::forward <Args>(args)...).c_str());
	}

	static inline void create_log(std::string out_path, std::string line, std::string folder_path = "") {
		return;

		// will be only in function scope.
		using namespace std;

		if (folder_path.empty()) {
#ifdef _WIN
			folder_path = "C:\\tg_parse\\"; // todo: rework it?
#endif
		}

		// fully universal thing.

		// in case that such folder path doesn't exist, let's create it.
		// iirc there is no such thing as recursion support, so, be aware.
		if (!filesystem::exists(folder_path)) {

			if (!filesystem::create_directory(folder_path)) {
				assert("unable to create log directory!");
			}

		}

		// file will support unicode and be created if not exist.
		ofstream file(folder_path + out_path, ios::out | ios::app);
		if (file.is_open()) {
			file << line << std::endl;
			file.close();
		} else {
			assert("unable to open/create log file!");
		}

	}

}