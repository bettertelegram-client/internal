#include "updater.hpp"
#include <output.hpp>
#include <api/gui.hpp>

namespace implant {

	register_implant(c_updater);

#ifdef _WIN64

	// Core::Updater::start.
	void __fastcall c_updater::handler(Core::Updater* instance, bool force_wait) {
		
		if (!get_settings()->get <bool> ("allow_updates")) {
			output::to_console("update request was successfully handled.");
		}
		return;
	}

#endif

}