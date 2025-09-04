#pragma once

#include <implant/helpers.hpp>

namespace implant {

	// todo: configs.

	// brief: Ghost mode for telegram which is separated by two main parts.
	// 
	//        1. managing offline status on application show/close.
	//        2. disabling packet send when user typing/uploading/looking for a stickers/etc.
	//

	class c_ghost_mode : public c_implant {
	public:

#ifdef _WIN64

		c_ghost_mode() : c_implant(generate_signature_ref("", "")) {
			setup_worker();
		};

		implant_make_preset("tg_ghost_mode", bool __fastcall, handler, Core::Application*, not_null<Main::Session*>);
#endif

		void on_construct(api::c_gui* ui) override {

			using namespace api;

			// config.
			implant::get_settings()->create <bool> ("ghost_mod", false);

			// buttons.
			auto ghost_mode = ui->create_button("ghost_mod", icons::e_registered_icons::k_offline, telegram::ui::k_night_mode);

			ghost_mode->title = L"Ghost Mode";
			ghost_mode->must_contain = telegram::ui::k_settings;
			ghost_mode->toggler_present = true;

			// todo: move to implant.
			ghost_mode->callback = [](c_gui* instance, c_gui::button_options_t* options) {
				implant::get_settings()->set <bool>("ghost_mod", options->current_state);
			};

		}

	private:

		void setup_worker() {

			std::thread worker([]() {

				while (true) {

					if (get_settings()->get <bool> ("ghost_mod")) {

						// todo: handle send error.
						telegram::unsafe::set_active_mode(false);

					}

					// todo: this can be reworked in the future?
					std::this_thread::sleep_for(std::chrono::seconds(2));

				}

			});

			// don't care about this thread anymore.
			// it's must be safe to do this at injection time.
			worker.detach();

		}

	};

	class c_ghost_messages : public c_implant {

	public:

#ifdef _WIN64
		c_ghost_messages() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_ghost_messages", void __fastcall, handler, QVector <uint32_t>*, uint32_t*);
#endif

	};

}