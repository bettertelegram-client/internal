#pragma once

#include <implant/helpers.hpp>
#include <window/window_session_controller.h>
#include "convo_manager.hpp"

namespace implant {

	// brief: obtaining active dialog id.

	class c_chat_info : public c_implant {

	public:

#ifdef _WIN64
		c_chat_info() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_chat_info", void __fastcall, handler, Window::SessionNavigation*, gsl::not_null <Data::Thread*>, MsgId, const Window::SectionShow*);
#endif

		void on_construct(api::c_gui* ui) override;
		virtual void set_chat_info_enabled(bool enable);

	protected:

		static bool is_chat_info_enabled;
	};

}	