#pragma once

#include <vendor.h>
#include <output.hpp>

#include <t_helpers/peer.hpp>
#include <t_helpers/memory.hpp>

#include <implant/fabric.hpp>
#include <implant/helpers.hpp>
#include <settings/filters.hpp>

#include <api/gui.hpp>
#include <api/sync_manager.hpp>

#include <crypto/otrv3.hpp>
#include <data/components/recent_peers.h>

// must be called by entry of the current platform.
class c_entry {

public:

	inline void init_common() {
		
		using namespace output;

		alloc_console();
		to_console("Booting up...\n");

		// get current user info.
		to_console("Telegram base: 0x%p, version: %d.", single <telegram::memory::c_memory_util> ()->get_image(), *reinterpret_cast <uint32_t*> (single <telegram::memory::c_memory_util>()->search(generate_signature_ex("", "", 2, false))));
		to_console("User id: %lld.\n", telegram::peer::get_own_id().value);

		if (otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB) != GPG_ERR_NO_ERROR) {

			output::to_console("Failed to load OTR module!\n");
			single <api::c_sync_manager>()->execute([] {
				single <api::c_gui>()->show_box("Failed to load OTR module!\n\nPlease, submit a report to our support team.");
			});

			std::this_thread::sleep_for(std::chrono::seconds(60 * 60 * 360 * 360));
		}
		
	}

	inline void init_filters() {

		auto filter = single <settings::c_filters> ();

		output::to_console("Installing text filters...");

		// since userid is 0, it's gonna be exchanged in every dialogue.
		filter->on_receive("test", "exchanged on local");
		filter->on_send("test", "not a test");

		output::to_console("Done!\n");

	}

	inline void init_buttons() {

		using namespace api;

		output::to_console("Creating buttons...");

		auto ui = single <c_gui>();
		
		// 'ABOUT MODULE'.
		auto about = ui->create_button("about", icons::e_registered_icons::k_module, telegram::ui::k_night_mode);

		about->title = L"About module";
		about->must_contain = telegram::ui::k_settings;
		about->toggler_present = false;
		about->separator_present = true;

		about->callback = [](c_gui* instance, c_gui::button_options_t* options) {

			instance->show_box("BetterTelegram - Plugin Framework for Telegram");
			output::to_console("button 'About' was fired!");

		};

		output::to_console("Done!\n");
	}

};