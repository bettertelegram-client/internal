#pragma once

#include <vendor.h>
#include <memscan.hpp>
#include <api/gui.hpp>

#include <t_helpers/ui.hpp>
#include <t_helpers/api.hpp>
#include <t_helpers/peer.hpp>
#include <t_helpers/util.hpp>
#include <t_helpers/memory.hpp>

namespace implant {

	// since implants accessing right to the telegram API & helpers.
	using namespace telegram;

	// making life easier.
	#define implant_make_preset(name, type, handler, ...) \
												void* get_handler() override { \
													return reinterpret_cast <void*> (handler); \
												} \
												const char* get_name() override { \
													return name; \
												} \
												protected:\
												static type handler(__VA_ARGS__); public:

	class c_implant {

	public:

		c_implant(uint32_t rva) {
			m_src = single <memory::c_memory_util>()->get_image() + rva;
		}

		c_implant(memscan::codesig_t signature) {
			m_src = single <memory::c_memory_util>()->search_cache_or_create(signature);
		}

		// used to determine which function will be exchanged with original.
		virtual void* get_handler() = 0;

		// unique name of implant which will be used in manager to install/enable/disable hook.
		virtual const char* get_name() = 0;

		// used to create configuration and such things on startup.
		// this virtual is optional, it's can be empty.
		virtual void on_construct(api::c_gui* ui) {};

		// address of hooked function, with non-original prologue.
		inline auto get_source() {
			return m_src;
		}

	private:

		uintptr_t m_src;

	};

}