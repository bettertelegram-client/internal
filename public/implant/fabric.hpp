#pragma once

#include <vendor.h>
#include <hash.hpp>
#include <hooks.hpp>

#include "implant.hpp"

namespace implant {

	class c_fabric : public c_singleton <c_fabric> {

	public:

		// register implant in the map.
		void create(c_implant* implant);

		// get implant from map by name.
		c_implant* get(const char* name);

		// get trampoline to original.
		uintptr_t get(c_implant* implant);

	private:

		// generate id for the implant.
		uint64_t get_id(const char* name) {
			return hash::fnv1a64_rt(name, strlen(name));
		}

	private:

		std::map <uint64_t, std::pair <uintptr_t, c_implant*>> m_implants = {};

	};

}