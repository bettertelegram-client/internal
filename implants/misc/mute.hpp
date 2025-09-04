#pragma once

#include <implant/helpers.hpp>
#include <window/notifications_manager_default.h>

namespace implant {

	// brief: remove unnecessary messages from the right window bar.

	class c_notification_muter : public c_implant {

	public:

#ifdef _WIN64
		c_notification_muter() : c_implant(generate_signature("", "")) {};
		implant_make_preset("tg_notify_mute", void __fastcall, handler, Window::Notifications::Default::Manager*, Window::Notifications::Manager::NotificationFields*);
#endif

	};

}