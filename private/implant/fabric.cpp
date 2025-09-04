#include <implant/fabric.hpp>

namespace implant {

	void c_fabric::create(c_implant* implant) {

		auto details = single <hooks::c_engine>()->create(implant->get_source(), implant->get_handler());
		if (details.first != hooks::e_status::k_success) {
			assert("unable to create hook!");
		}

		m_implants.try_emplace(this->get_id(implant->get_name()), std::pair(details.second, implant));
	}

	c_implant* c_fabric::get(const char* name) {

		auto id = this->get_id(name);

		if (m_implants.contains(id)) {
			return m_implants.at(id).second;
		}

		return nullptr;
	}

	uintptr_t c_fabric::get(c_implant* implant) {

		auto id = this->get_id(implant->get_name());

		if (m_implants.contains(id)) {
			return m_implants.at(id).first;
		}

		return 0;
	}

}