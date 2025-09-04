#pragma once

#include <vendor.h>
#include "util.hpp"

// warning: everything from here must be called with an wrapper.
// read the documentation, it's an extremely unsafe!
namespace telegram::peer {

	namespace internals {
		static PeerData* g_last_peer = nullptr;
	}

	struct peer_info_t {

		std::string first_name, user_name = "null";
		PeerId id;

		peer_info_t(PeerData* data) {

			if (data->isUser()) {

				auto user_data = static_cast <UserData*> (data);
				auto usernames = user_data->_username._usernames;

				if (!usernames.empty()) {
					this->user_name = usernames.front().toStdString();
				}
				else {
					this->user_name = std::to_string(user_data->id.value);
				}

				this->first_name = user_data->_name.toStdString();
				this->id = user_data->id;

			}

			if (data->isChat()) {

				auto chat_data = static_cast <ChatData*> (data);

				this->user_name = std::to_string(chat_data->id.value);

				this->first_name = chat_data->_name.toStdString();
				this->id = chat_data->id;

			}

			if (data->isChannel()) {

				auto channel_data = static_cast <ChannelData*> (data);
				auto usernames = channel_data->_username._usernames;

				if (!usernames.empty()) {
					this->user_name = usernames.front().toStdString();
				}
				else {
					this->user_name = std::to_string(channel_data->id.value);
				}

				this->first_name = channel_data->_name.toStdString();
				this->id = channel_data->id;

			}

		};

		peer_info_t(UserData* data) {

			auto usernames = data->_username._usernames;

			if (!usernames.empty()) {
				this->user_name = usernames.front().toStdString();
			}
			else {
				this->user_name = std::to_string(data->id.value);
			}

			this->first_name = data->_name.toStdString();
			this->id = data->id;
		}

		peer_info_t(PeerId peer_id, const std::string f_name, const std::string u_name = "null")
			: id(peer_id), first_name(f_name), user_name(u_name) {}
	};

	static inline auto get_history(Data::Histories* histories, PeerId target) {

		void* history = nullptr;

#ifdef _WIN64
		single <memory::c_memory_util>()->call <gsl::not_null<History*>*>(generate_signature_ref("", ""), histories, &history, target);
#endif

		return *reinterpret_cast <gsl::not_null<History*>*> (&history);
	}

	static inline auto remove_chat(PeerData* peer, bool both_sides) {

#ifdef _WIN64
		single <memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), get_active_session()->_api.get(), peer, both_sides);
#endif

	}

	static inline auto get_own_id() {
		return PeerId(telegram::get_active_session()->_userId.bare);
	}

	static inline auto get_last_peer() {
		if (internals::g_last_peer)
		{
			return internals::g_last_peer;
		}
	}

	static inline void set_last_peer(PeerData* peer) {

		if (peer) {
			internals::g_last_peer = peer;
		}

	}

}