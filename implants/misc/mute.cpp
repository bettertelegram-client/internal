#include "mute.hpp"
#include <output.hpp>

// TODO: rebuild the DLL, try to get it to be FUD from WD wacatac after HA scan ...
// TODO: make auto updater without config reset feature for BetterTelegram.EXE when there is a new version ...
// TODO: WMI is flagged in BetterTeelgram.EXE by HA ... remove that for generating a random string into id.hwid in BT folder at app login time & create new if it doesnt exist. merge it together with licence as the new HWID

namespace implant {

	register_implant(c_notification_muter);

#ifdef _WIN64

	// Window::Notifications::Default::Manager::doShowNotification.
	void __fastcall c_notification_muter::handler(Window::Notifications::Default::Manager* instance, Window::Notifications::Manager::NotificationFields* fields) {

		if (fields->item) {

			auto text = fields->item->_text;
			if (text.empty() || text.text.size() == 0) return;
	
		}

		return implant_helper(c_notification_muter)->call_original <void>(instance, fields);
	}

#endif

}