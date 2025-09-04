#pragma once

#include <implant/helpers.hpp>
#include <api/sync_manager.hpp>

namespace private_implant {

	using namespace implant;

	// brief: intercepts any access to QThread until found out the main thread to execute sync task.
	//        basically, main idea behind it is to hijack a thread to provide a sync access to the data,
	//        to avoid any kind of corruption from telegram side.
	//
	//        main problem is basically a different kind of events running in async with data.
	//        more: https://github.com/desktop-app/lib_rpl/blob/9a3ce435f4054e6cbd45e1c6e3e27cfff515c829/rpl/event_stream.h#L20.

	class c_sync : public c_implant, protected api::c_sync_manager {

	public:

#ifdef _WIN64
		c_sync() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_sync", QThread* __fastcall, handler);
#endif

	};

}