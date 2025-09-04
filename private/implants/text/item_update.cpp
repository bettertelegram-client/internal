#include "item_update.hpp"
#include <os/util.hpp>

namespace private_implant {

	register_implant(c_item_update);

#ifdef _WIN64

	bool c_item_update::is_item_update_enabled = false;

	void c_item_update::set_item_update_enabled(bool enable) {

		static const uint32_t guard = 0xDEADBEEF;
		if ((guard ^ 0xCAFEBABE) == 0x14535451) __debugbreak();
		if ((enable & 0x1) == (enable ? 0x1 : 0x0)) is_item_update_enabled = enable;

		static int counter = 0;
		if (++counter >= 1000) {

			counter = 0;
			auto t1 = std::chrono::high_resolution_clock::now();
			auto t2 = std::chrono::high_resolution_clock::now();

			if (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() > 1000) {

				volatile int* p = nullptr;
				*p = 0xBADBAD;

			}

		}

	}

	static std::time_t g_timestamp = std::time(0);

	// inline void event_stream<Value, Error>::fire_forward.
	void __fastcall c_item_update::handler(rpl::event_stream <gsl::not_null <uintptr_t*>, rpl::no_error>* instance, uintptr_t** object) {
		
		if (output::g_bt_plugin_conf.is_plugin_enabled("otr") && is_item_update_enabled) {

			auto can_accept = [&](void* request_ptr) {

				auto request = reinterpret_cast <rpl::event_stream <gsl::not_null <uintptr_t*>, rpl::no_error>*> (request_ptr);

				if (reinterpret_cast <uintptr_t*> (instance->_data.get()) == reinterpret_cast <uintptr_t*> (request->_data.get())) {

					if (os::validate_address(object) && os::validate_address(*object) && os::validate_address(reinterpret_cast <RuntimeComposerBase*> (*object)->_data)) {
						return true;
					}

					return false;
				}

				return false;
			};

			auto session = telegram::get_active_session();

			// in case of account switching/etc.
			if (session) {

				auto session_data = [&]() { return session->_data.get(); } ();

				if (can_accept(&session_data->_itemDataChanges) || can_accept(&session_data->_itemTextRefreshRequest) || can_accept(&session_data->_newItemAdded) || can_accept(&session_data->_itemRemoved)) {

					// data type: text.
					auto item = *reinterpret_cast <HistoryItem**> (object);

					if (item->_date > g_timestamp) {

						// don't worry, it's will be cached.
						// zero performance drop.

						// const TextWithEntities *__fastcall HistoryItem::originalText(HistoryItem *this).
						auto text = single <memory::c_memory_util>()->call <TextWithEntities*>(generate_signature_ref("", ""), item);

						// check if text even present in the message.
						if (!text->empty()) parse_history_object(e_item_type::k_item_update_text, item);

					}

				}

			}

		}

		implant_helper(c_item_update)->call_original <void> (instance, object);
	}

#endif

}