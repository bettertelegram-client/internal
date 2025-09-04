#include <implant/helpers.hpp>

namespace implant {

	bool c_helper::enable() {

		if (single <hooks::c_engine>()->enable(m_implant->get_source()) != hooks::e_status::k_success) {
			assert("unable to enable target implant!");
			return false;
		}

		return true;
	}

	bool c_helper::disable() {

		if (single <hooks::c_engine>()->disable(m_implant->get_source()) != hooks::e_status::k_success) {
			assert("unable to disable target implant!");
			return false;
		}

		return true;
	}

	uintptr_t c_helper::get_original_point() {
		return single <c_fabric>()->get_instance()->get(m_implant);
	}

}