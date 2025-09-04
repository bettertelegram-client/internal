#pragma once

#include <implant/helpers.hpp>
#include <telegram/core/update_checker.h>

namespace implant {

	// brief: remove attempts to get an update.

	class c_updater : public c_implant {

	public:

#ifdef _WIN64
		c_updater() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_updater", void __fastcall, handler, Core::Updater*, bool);
#endif

		// example of config build.
		void on_construct(api::c_gui* ui) override {
			get_settings()->create <bool>("allow_updates", false);
		}

	};

}