#pragma once

#include <implant/helpers.hpp>
#include <settings/filters.hpp>
#include <data/data_histories.h>

// do not touch, internals.
namespace private_implant {

	using namespace implant;

	// brief: replacing message to send with custom one without updating it on client.

	class c_send : public c_implant, protected settings::c_filters {

	public:

#ifdef _WIN64
		c_send() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_send", uint64_t __fastcall, handler, uintptr_t, uintptr_t, MTPinputPeer*, uintptr_t, MTPString*, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
#endif

		virtual void set_send_enabled(bool enable);

	protected:

		static bool is_send_enabled;
	};

}