#pragma once

#include <implant/helpers.hpp>
#include <api/gui.hpp>

#include <ui/widgets/menu/menu_add_action_callback.h>

namespace private_implant {

	using namespace implant;

	// brief: process rendering of action-type icons.

	class c_action_buttons : public c_implant, protected api::c_gui {

	public:

#ifdef _WIN64
		c_action_buttons() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_action_buttons", QAction* __fastcall, handler, Ui::Menu::MenuCallback*, QString*, std::function <void()>*, style::internal::Icon*);
#endif

	private:
		static std::unordered_map<Ui::Menu::MenuCallback*, bool> menu_buttons;

	};

}