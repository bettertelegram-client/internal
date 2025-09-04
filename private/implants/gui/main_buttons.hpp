#pragma once

#include <implant/helpers.hpp>
#include <api/gui.hpp>

#include <telegram/settings/settings_common.h>

namespace private_implant {

	using namespace implant;

	// brief: process rendering of action-type icons.

	class c_main_buttons : public c_implant, protected api::c_gui {

	public:

#ifdef _WIN64
		c_main_buttons() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_main_buttons", gsl::not_null <Ui::SettingsButton*>* __fastcall, handler, gsl::not_null <Ui::SettingsButton*>*, gsl::not_null <Ui::VerticalLayout*>, rpl::producer <QString>*, const style::SettingsButton*, Settings::IconDescriptor*);
#endif

	};

}