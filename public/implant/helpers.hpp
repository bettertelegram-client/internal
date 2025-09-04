#pragma once

#include "fabric.hpp"
#include <api/gui.hpp>
#include <settings/records.hpp>
#include "../../thirdparty/singleton.hpp"

namespace implant {

	// be aware:
	// must be registered in '.cpp' file of implant!
	#define register_implant(name) namespace _private { static name* g_implant_##name = new name(); static auto g_implant_##name##_helper = new implant::c_helper(g_implant_##name); }
	#define implant_helper(name) _private::g_implant_##name##_helper

	class c_helper : public c_singleton <c_helper>{

	public:

		// on the helper creation.
		c_helper(c_implant* implant) : m_implant (implant) {

			// register new implant in the system.
			single <c_fabric> ()->create(implant);

			// firing event. (configs, depends, etc)
			implant->on_construct(single <api::c_gui>());

			// enable implant by default.
			this->enable();

		};

		// enable hook on implant.
		bool enable();

		// disable hook on implant.
		bool disable();

		// get original prologue of target function.
		uintptr_t get_original_point();

		// execute original prologue of target function.
		template <typename T, memory::e_func_conv conv = memory::e_func_conv::k_fastcall, typename... Args>
		inline T call_original(Args... args) noexcept {
			return single <memory::c_memory_util>()->call <T, conv>(this->get_original_point(), std::forward <Args>(args)...);
		}

	private:
		
		c_implant* m_implant;

	};

	// easier way to get fast settings API access.
	inline static auto get_settings() {
		return single <settings::c_records>();
	}

}