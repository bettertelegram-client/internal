#pragma once

#include <implant/helpers.hpp>
#include <settings/filters.hpp>
#include <history/history_item_components.h>
#include <output.hpp>
#include <crypto/otrv3.hpp>

namespace private_implant {

	using namespace implant;

	// brief: change recv message and prevent attempts to update send'ed message.

	class c_item_update : public c_implant, protected settings::c_filters {

	public:

#ifdef _WIN64
		c_item_update() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_item_update", void __fastcall, handler, rpl::event_stream <gsl::not_null <uintptr_t*>, rpl::no_error>*, uintptr_t**);
#endif

		virtual void set_item_update_enabled(bool enable);

	protected:

		// todo: more types like documents, gifs, etc.
		enum class e_item_type {

			k_item_update_text = 0

		};

		// WARNING: MUST BE UNIVERSAL FOR ANY PLATFORM.
		// DO NOT INCLUDE ANY TYPE OF PLATFORM, ARCH, OR OS DEPEND THINGS.
		inline static void parse_history_object(e_item_type type, HistoryItem* item) {

			uint64_t our_id = telegram::peer::get_own_id().value;
			if (item->_text.text.startsWith("?BETTER_TELEGRAM_") ||
				item->_text.text.startsWith("[CT]: ?BETTER_TELEGRAM_"))
				item->_text.text.clear();
		}

		static bool is_item_update_enabled;

	};

}