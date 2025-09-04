#include "chat_info.hpp"
#include <output.hpp>
#include <api/gui.hpp>
#include <crypto/otrv3.hpp>
#include "otr_messaging.hpp"

namespace implant {

	register_implant(c_chat_info);

#ifdef _WIN64

	static int make_rand_num() {

		srand(time(0));
		return 111111 + rand() % (999999 - 111111 + 1);

	}

	bool c_chat_info::is_chat_info_enabled = false;

	void c_chat_info::set_chat_info_enabled(bool enable) {

		static const uint32_t guard = 0xDEADBEEF;
		if ((guard ^ 0xCAFEBABE) == 0x14535451) __debugbreak();
		if ((enable & 0x1) == (enable ? 0x1 : 0x0)) is_chat_info_enabled = enable;

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

	void c_chat_info::on_construct(api::c_gui* ui) {

		using namespace api;

		// buttons.

		// todo: features provider.
		single <features::c_convo_manager>()->generate_buttons(ui);
		single <features::c_otr_messaging>()->generate_buttons(ui);

	}	

	// Window::SessionNavigation::showThread.
	void __fastcall c_chat_info::handler(Window::SessionNavigation* instance, gsl::not_null <Data::Thread*> thread, MsgId item_id, const Window::SectionShow* params) {
		
		using namespace crypto;
		using namespace api;
		using namespace telegram;

		auto peer = thread->owningHistory()->peer.get();
		if (peer) {

			if (output::g_bt_plugin_conf.is_plugin_enabled("otr") && is_chat_info_enabled) {

				auto peer_info = telegram::peer::peer_info_t(peer);
				peer::set_last_peer(peer);

				// output::to_console("active chat was switched! new peer: %s (@%s:%lld).", peer_info.first_name.c_str(), peer_info.user_name, peer_info.id.value);

				auto ui = single <api::c_gui>();
				bool peers_authenticated = true;
				single <features::c_convo_manager>()->update_button_state(ui, peer->id.value);

				auto storage = single<otr::c_storage_manager>();
				auto peer_data = storage->get_peer(peer->id.value);

				// so the idea for chats is to send a discovery message the moment we join, so in that same instance all peers will respond to us, so we automatically know about them
				// and essentially we no longer need to wait for peer discovery (no loop within a thread which stalls the program execution)
				// so right when we want to start OTR session we can send the OTR AUTH MSG to everybody
				if (peer->isChat() || peer->isChannel()) {

					if (peer_data) {

						if (!peer_data->group_data->peers.empty()) {

							for (const auto& peer : peer_data->group_data->peers)
								if (!peer.second->is_authenticated)
									peers_authenticated = false;
						}
						else
						peers_authenticated = false;

						// disabled if not all peers authenticated, enabled otherwise
						peer_data->group_data->is_otr_enabled = peers_authenticated;

					} // assuming no peers have been discovered yet and/or this is a new group we joined
					else peers_authenticated = false;

					// so in this case we only send the OTR INIT auth in the following scenarios 
					//
					// 1) its "a new group we just joined" & we dont know about anyone yet (!peer_data)
					// 2) we already joined this group before, but the peer list is empty, so we want to discover new peers if theyre there (group_data->peers.empty())
					// 3) we authenticated in this group before, but there is some new peer(s) that joined, and we havent authenticated with them yet

					// Removed it because it seemed to be unnecessary spam, especially since Enable OTR button sends a discovery message anyways
					if (!peers_authenticated) {

						// ALIVE=FALSE by default since if OTR auth is requested, the session hasnt been setup yet
						telegram::unsafe::send_message(QString::asprintf("?BETTER_TELEGRAM_PEER=%llu? ALIVE=%s,%d", 
							peer->id.value, peers_authenticated ? "TRUE" : "FALSE", make_rand_num()), peer->id);
				
					}

				} else
				// since for regular peers (non-group chats), the OTR INIT auth is sent manually from otr_messaging.hpp, we check if the peer is_authenticated, and if so, enable the button
				peers_authenticated = (peer_data && peer_data->is_authenticated);
			
				single <features::c_otr_messaging>()->update_button_state(ui, peer->id.value, peer->isChat() || peer->isChannel(), peers_authenticated);

			}

		}

		implant_helper(c_chat_info)->call_original <void> (instance, thread, item_id, params);

	}

#endif

}