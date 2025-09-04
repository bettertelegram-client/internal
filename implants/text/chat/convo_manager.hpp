#pragma once

#include <vendor.h>
#include <output.hpp>
#include <api/gui.hpp>
#include <t_helpers/peer.hpp>

#include <set>

// TODO:MAKE FEATURES CLASS INSTANCE.
namespace features {

	class c_convo_manager : public c_singleton <c_convo_manager> {

	public:

		void generate_buttons(api::c_gui* ui) {

			using namespace api;
			using namespace telegram;

			auto keep_chat = ui->create_button("keep_chat", icons::e_registered_icons::k_delete_acc, telegram::ui::k_export_chat_history);
			keep_chat->title = L"Enable clean protect";
			//keep_chat->must_contain = telegram::ui::k_export_chat_history;
			keep_chat->toggler_present = false;

			keep_chat->callback = [](c_gui* instance, c_gui::button_options_t* options) {

				if (output::g_bt_plugin_conf.is_plugin_enabled("purge")) {

					auto last_peer = peer::get_last_peer();
					if (last_peer) {

						auto id = last_peer->id.value;
						if (!m_peers.contains(id)) {
							m_peers.emplace(id);
							// output::to_console("chat-protection for peer %llu was added.", id);
						}
						else {
							m_peers.erase(id);
							// output::to_console("chat-protection for peer %llu was removed!", id);
						}

					}

					instance->update_button_title(options, "Disable clean protect", "Enable clean protect");

				}
			};

			auto delete_chats = ui->create_button("delete_chats", icons::e_registered_icons::k_garbage, telegram::ui::k_experimental_settings);

			delete_chats->title = L"Delete all chats";
			delete_chats->must_contain = telegram::ui::k_export_telegram_data;
			delete_chats->toggler_present = false;
			delete_chats->separator_present = true;

			delete_chats->callback = [](c_gui* instance, c_gui::button_options_t* options) {

				for (auto& peer_view : telegram::get_active_session()->_data->_peers) {
					
					auto peer_id = peer_view.first.value;

					if (!m_peers.contains(peer_id)) {
						peer::remove_chat(peer_view.second.get(), true);
						// output::to_console("chat with %llu was successfully deleted!", peer_id);
					} else {
						// output::to_console("can't delete chat with %llu, peer is under protectection!", peer_id);
					}

				}

			};

		}

		void update_button_state(api::c_gui* ui, uint64_t id) {

			auto keep_state = ui->get_button_options("keep_chat");
			keep_state->current_state = m_peers.contains(id);

			ui->update_button_title(keep_state, "Disable clean protect", "Enable clean protect");
			ui->update_button_options("keep_chat", keep_state);

		}

		void protect_chat(uint64_t id) {
			
			if (!m_peers.contains(id)) {
				m_peers.emplace(id);
			}

		}

		void remove_chat(uint64_t id) {

			if (m_peers.contains(id)) {
				m_peers.erase(id);
			}

		}

		bool is_protected(uint64_t id) {
			return m_peers.contains(id);
		}

	private:
		inline static std::set <uint64_t> m_peers = {};

	};

}