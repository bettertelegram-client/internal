#pragma once

#include <implant/helpers.hpp>
#include <telegram/core/update_checker.h>

namespace implant {

	// brief: prevent message removal by another peer in the chat.

	class c_keeper : public c_implant {

	public:

#ifdef _WIN64
		c_keeper() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_keeper", void __fastcall, handler, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
#endif

	};

}