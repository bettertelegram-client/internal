#pragma once

#include <vendor.h>
#include <hash.hpp>
#include <singleton.hpp>

#include <map>

namespace settings {

	class c_records : c_singleton <c_records> {

	public:

		// add record to configuration map.
		template <typename T, typename... Args>
		inline bool create(std::string name, Args... args) {
			return m_storage.try_emplace(hash::fnv1a64_rt(name.c_str(), name.length()), reinterpret_cast <uintptr_t*> (new T(std::forward <Args> (args)...))).second;
		}

		// get value from configuration map for modification.
		// e.g *at_reference("my_option") = false; (or it's better to use 'set' for this purpose)
		//
		// note: can be nullptr.
		template <typename T>
		inline T* at_reference(std::string name) {
			
			auto id = hash::fnv1a64_rt(name.c_str(), name.length());

			if (m_storage.contains(id)) {
				return reinterpret_cast <T*> (m_storage.at(id));
			}

			return nullptr;
		}

		// getters and setters, or a wrappers around 'at_reference'.

		template <typename T>
		inline T get(std::string name) {
			
			auto record = this->at_reference <T> (name);

			if (record) {
				return *record;
			}

			return (T) nullptr;
		}

		template <typename T>
		inline void set(std::string name, T value) {

			auto record = this->at_reference <T> (name);
			
			if (record) {
				*record = value;
			}

		}

	private:
		
		std::map <uint64_t, uintptr_t*> m_storage;

	};

}