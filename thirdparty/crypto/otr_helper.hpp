#pragma once

#include <vendor.h>
#include <unordered_map>
#include <t_helpers/peer.hpp>
#include <t_helpers/util.hpp>
#include <libotr/privkey.hpp>
#include <libotr/userstate.hpp>

namespace crypto::otr {

	struct group_peer_t {

		telegram::peer::peer_info_t info;
		bool sent_first_msg;
		bool is_authenticated;
		bool sent_auth_notification;

	};

	struct group_data_t {

		bool sent_otr_group;
		bool did_start_ake;
		bool is_otr_enabled;
		std::mutex peer_mutex;
		time_t last_sent_group_msg;
		time_t last_sent_discovery_msg;
		std::unordered_map <uint64_t, group_peer_t*> peers = {};

		group_data_t(bool sent, bool ake, bool otr, time_t last_msg, time_t last_discovery,
			std::unordered_map<uint64_t, group_peer_t*> p) :
			sent_otr_group(sent),
			did_start_ake(ake),
			is_otr_enabled(otr),
			last_sent_group_msg(last_msg),
			last_sent_discovery_msg(last_discovery),
			peers(std::move(p)) {
		}

	};

	struct peer_data_t {

		telegram::peer::peer_info_t info;
		bool is_processed, is_active;
		time_t last_msg;
		bool is_group_chat;
		bool is_authenticated;
			
		group_data_t* group_data;

	};

	struct inject_data_t {

		OtrlUserState state;
		uint64_t peer_id;

	};

	class c_storage_manager : public c_singleton <c_storage_manager> {
	public:

		void setup_keys(OtrlUserState state, std::string& private_key, std::string& fingerprints) {

			printf("[BetterTelegram] Generating OTR private key\n");
			otrl_privkey_read(state, private_key.c_str());
			otrl_privkey_read_fingerprints(state, fingerprints.c_str(), 0, 0);
			printf("[BetterTelegram] Done!\n\n");

		}

		auto get_key_path(uint64_t id) -> std::pair <std::string, std::string> {

			auto user_id = std::to_string(id);

			char keys_path[MAX_PATH] = { 0 };
			ExpandEnvironmentStringsA("%APPDATA%\\BetterTelegram\\keys\\", keys_path, sizeof(keys_path) - 1);

			std::string fingerprints(keys_path), private_key(keys_path);

			fingerprints += user_id + "_print.txt";
			private_key += user_id + "_private.key";

			return std::make_pair(fingerprints, private_key);
		}

		auto add_peer(telegram::peer::peer_info_t profile, bool is_group_chat = false, bool sent_otr_group = false, bool did_start_ake = false) -> peer_data_t* {

			if (!m_peers.contains(profile.id.value)) {

				auto data = new peer_data_t(
					profile,
					false, true,
					time(0),
					is_group_chat,
					false,
					new group_data_t(
						sent_otr_group,
						did_start_ake,
						false,
						0, 0, {}));

				m_peers.emplace(profile.id.value, data);
				printf("[OTR] peer was added! value: %llu, %p\n", profile.id.value, m_peers.at(profile.id.value));

				return data;
			}

			return 0;
		}

		auto add_peer(PeerData* peer, bool is_group_chat = false, bool sent_otr_group = false, bool did_start_ake = false) -> peer_data_t* {

			if (!m_peers.contains(peer->id.value)) {

				telegram::peer::peer_info_t profile = telegram::peer::peer_info_t(peer);

				auto data = new peer_data_t(
					profile,
					false, true,
					time(0),
					is_group_chat,
					false,
					new group_data_t(
						sent_otr_group,
						did_start_ake,
						false,
						0, 0, {}));

				m_peers.emplace(profile.id.value, data);
				printf("[OTR] peer was added! value: %llu, %p\n", profile.id.value, m_peers.at(profile.id.value));

				return data;
			}

			return 0;
		}

		auto get_peer(uint64_t id) -> peer_data_t* {

			return m_peers.contains(id) ? m_peers.at(id) : nullptr;
		}

		bool remove_peer(uint64_t id) {

			if (m_peers.contains(id)) {

				delete m_peers.at(id);
				m_peers.erase(id);

				return true;
			}

			return false;
		}

		auto get_state() -> OtrlUserState {

			if (!m_state) {
				m_state = otrl_userstate_create();
			}

			return m_state;
		}

	private:

		OtrlUserState m_state = nullptr;
		std::unordered_map <uint64_t, peer_data_t*> m_peers = {};

	};

}