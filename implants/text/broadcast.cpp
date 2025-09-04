#include "broadcast.hpp"
#include <output.hpp>
#include <crypto/otrv3.hpp>
#include "../../../implants/text/chat/otr_messaging.hpp"

#include <../public/api/rtti.hpp>
#include <../public/api/licence.hpp>

namespace implant {

	register_implant(c_broadcast);

#ifdef _WIN64

	std::time_t c_broadcast::g_timestamp = std::time(0);
	bool c_broadcast::is_broadcast_enabled = false;

	static int make_rand_num() {

		srand(time(0));
		return 111111 + rand() % (999999 - 111111 + 1);

	}

	void c_broadcast::set_broadcast_enabled(bool enable) {

		static const uint32_t guard = 0xDEADBEEF;
		if ((guard ^ 0xCAFEBABE) == 0x14535451) __debugbreak();
		if ((enable & 0x1) == (enable ? 0x1 : 0x0)) is_broadcast_enabled = enable;
	
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

	static std::pair<std::pair<uint64_t, uint64_t>, size_t> validate_auth(std::string auth_string) {
		
		bool is_group_chat = strncmp(auth_string.c_str(), "?BETTER_TELEGRAM_CHAT=", 22) == 0 ? true : false;
		bool is_discovery = auth_string.find("? ALIVE=") != std::string::npos ? true : false;
		std::smatch match;
		std::regex pattern(
			!is_group_chat ?
			R"(\?BETTER_TELEGRAM_PEER=(\d+)\?)" :
			R"(\?BETTER_TELEGRAM_CHAT=(\d+):(\d+)\?)");

		if (std::regex_search(auth_string, match, pattern)) {

			uint64_t group_id = 0, target_id = 0;

			try {
				if (is_group_chat) {
					group_id = std::stoull(match[1].str());
					target_id = std::stoull(match[2].str());
				} else {
					target_id = std::stoull(match[1].str());
				}
			}
			catch (...) {
				group_id = 0;
				target_id = 0;
			}

			return { { is_group_chat ? group_id : is_discovery ? 1 : 0, target_id }, (size_t)(match.suffix().first - auth_string.begin() + 1) };

		}

		return { { 0, 0 }, 0 };
	}

	// History::addNewItem.
	auto __fastcall c_broadcast::handler(History* instance, gsl::not_null <HistoryItem*>* result, gsl::not_null <HistoryItem*> item, bool unread) -> gsl::not_null<HistoryItem*>* {
		
		if (item && result) {

			using namespace crypto;
			using namespace telegram;
		
			auto author = item->_from.get();
			auto target = item->_history->peer.get();
			auto text   = item->_text.text.toStdString();

			auto is_valid_peer = [](PeerData* peer) {
				return  peer->isUser() ||
						peer->isChat() ||
						peer->isChannel();
			};

			if ((is_valid_peer(author) && is_valid_peer(target)) && (!text.empty() && item->_date > c_broadcast::g_timestamp)) {

				if (output::g_bt_plugin_conf.is_plugin_enabled("otr") && is_broadcast_enabled) {

					using namespace rtti;
					auto sender    = peer::peer_info_t(author);
					auto receiver  = peer::peer_info_t(target);
					auto self_info = peer::peer_info_t(get_active_session()->_user);
					if (sender.id.value == peer::peer_info_t(target).id.value) receiver = self_info;

					OtrlTLV* tlvs = 0;
					char* newmessage = 0;
					ConnContext* otr_is_enabled = 0;
					std::string peer_recver_id = "", peer_sender_id = "";
					uint64_t our_id = telegram::peer::get_own_id().value;
					auto& licence = licence::protection::get_instance();
					using AddAppDataFn = void(*)(void*, ConnContext*);

					auto output = validate_auth(text);
					bool is_group_chat = target->isChat() || target->isChannel();//, should_hide_text = false; ---> CRASH
					if (is_group_chat) {

						// if (output.second) should_hide_text = strncmp(text.c_str() + output.second, "MSG=", 4) == 0 ? true : false;
						if (output.first.second) {
						
							// discovery message AND it didnt come from us, send discovery response so others can discover us
							if (sender.id.value != our_id) {

								auto storage = single<otr::c_storage_manager>();
								PeerId group = PeerId(output.first.first <= 1 ? output.first.second : output.first.first);
								telegram::peer::peer_info_t peer_info(group, std::to_string(group.value));
								otr::peer_data_t* group_chat = storage->add_peer(peer_info, true);
								
								if (output.first.first == 1) {
							
									if (!group_chat) group_chat = storage->get_peer(output.first.second);
									if ( group_chat) {

										std::lock_guard<std::mutex> lock(group_chat->group_data->peer_mutex);
										// so this is my workaround for peers who closes telegram unexpectedly & tried to reAuthenticate themselves after rejoining the group chat
										// since active peers already have a ConnContext (OTR state) set up, they wont respond to discovery messages from the given peer, so we need
										// to check if the peer is in our list, then remove the previous peer entry for him, delete the ConnContext entry for them & reset the connection
										bool is_peer_known = group_chat->group_data->peers.contains(sender.id.value), send_discovery_reply = false;
										if (is_peer_known &&
											// so basically, ALIVE=FALSE with a known peer is only sent if that peer already authenticated with us before but he closed his telegram
											// client or it crashed or whatever reason & we didnt get to deauthenticate with him manually, so we must do it automatically
											strncmp((text.c_str() + output.second), "ALIVE=FALSE", 11) == 0) {
											// if its already authenticated & its sending ALIVE=FALSE, thats the final/clear indicator that its a past client that needs to reauth
											auto group_peer = group_chat->group_data->peers.at(sender.id.value);
											if (group_peer && group_peer->is_authenticated) {
								
												std::string our_group_id = (std::to_string(group.value) + "_" + std::to_string(our_id));
												std::string target_group_id = (std::to_string(group.value) + "_" + std::to_string(sender.id.value));

												my_rtti::call_func<void>(
													licence.decrypt_string(15),
													licence.decrypt_string(18), {
														static_cast<OtrlUserState>(storage->get_state()),
														static_cast<const OtrlMessageAppOps*>(&otr::g_options),
														static_cast<void*>(nullptr),
														static_cast<const char*>(our_group_id.c_str()),
														static_cast<const char*>("BTOTR"),
														static_cast<const char*>(target_group_id.c_str())
													}
												);

												group_peer->is_authenticated = false;
												group_peer->sent_auth_notification = false;
												group_chat->group_data->sent_otr_group = true;

												send_discovery_reply = true;

											}

										} else
										if (!is_peer_known) {

											group_chat->group_data->peers.emplace(sender.id.value, new otr::group_peer_t(telegram::peer::peer_info_t(item->_from), false, false, false));
											group_chat->group_data->last_sent_discovery_msg = time(0);

											send_discovery_reply = true;
											// if someone new joins the group, reset the OTR button (if user clicks it again, it will send OTR AUTH MSG to newly joined peers)
											if (group_chat->group_data->is_otr_enabled) {

												auto c_gui = single <api::c_gui>();
												auto active_chat = c_gui->get_active_window();
												if (active_chat && (active_chat.value == group.value))
													c_gui->show_box("[BetterTelegram]: " + (sender.first_name.length() ? sender.first_name : sender.user_name)
														+ " has joined the group. You may choose to Enable-OTR to communicate with them, otherwise ignore this message.");
										
												group_chat->group_data->is_otr_enabled = false;
												single <features::c_otr_messaging>()->update_button_state(c_gui, group.value, true);

											}
									
										}

										if (send_discovery_reply) telegram::unsafe::send_message(QString::asprintf("?BETTER_TELEGRAM_PEER=%llu? ALIVE=%s,%d", 
											group.value, group_chat->is_authenticated ? "TRUE" : "FALSE", make_rand_num()), group);

									}

								} else
								if (output.first.first > 1) {

									if (output.first.second == our_id) {

										otr::opdata_struct opdata = { 0 };
										opdata.sender_id = sender.id.value;
										opdata.group_id = output.first.first;
										peer_recver_id = (std::to_string(opdata.group_id) + "_" + std::to_string(our_id));
										peer_sender_id = (std::to_string(opdata.group_id) + "_" + std::to_string(sender.id.value));
									
										const char* real_message = text.c_str() + (text.starts_with("?BETTER_TELEGRAM_") ? output.second : 0);
										auto storage = single<otr::c_storage_manager>();

										my_rtti::call_func<int>(
											licence.decrypt_string(15),
											licence.decrypt_string(19), {
												static_cast<OtrlUserState>(storage->get_state()),
												static_cast<const OtrlMessageAppOps*>(&otr::g_options),
												static_cast<void*>((void*)&opdata),
												static_cast<const char*>(peer_recver_id.c_str()),
												static_cast<const char*>("BTOTR"),
												static_cast<const char*>(peer_sender_id.c_str()),
												static_cast<const char*>(real_message),
												static_cast<char**>(&newmessage),
												static_cast<OtrlTLV**>(nullptr),
												static_cast<ConnContext**>(nullptr),
												static_cast<AddAppDataFn>(nullptr),
												static_cast<void*>(nullptr)
											}
										);
										
										otr_is_enabled = my_rtti::call_func<ConnContext*>(
											licence.decrypt_string(15),
											licence.decrypt_string(16), {
												static_cast<OtrlUserState>(storage->get_state()),
												static_cast<const char*>(peer_sender_id.c_str()),
												static_cast<const char*>(peer_recver_id.c_str()),
												static_cast<const char*>("BTOTR"),
												static_cast<otrl_instag_t>(1),
												static_cast<int>(0),
												static_cast<int*>(nullptr),
												static_cast<AddAppDataFn>(nullptr),
												static_cast<void*>(nullptr)
											}
										);

										
									} else item->_text.text.clear();

								}

							}

						}

					} else
					if (sender.id.value != our_id && !output.first.first) {
			
						auto storage = single<otr::c_storage_manager>();
						storage->add_peer(item->_from);

						peer_recver_id = std::to_string(our_id);
						peer_sender_id = std::to_string(sender.id.value);

						otr::opdata_struct opdata = { 0 };
						opdata.sender_id = sender.id.value;
						const char* real_message = text.c_str() + (text.starts_with("?BETTER_TELEGRAM_") ? output.second : 0);
						my_rtti::call_func<int>(
							licence.decrypt_string(15),
							licence.decrypt_string(19), {
								static_cast<OtrlUserState>(storage->get_state()),
								static_cast<const OtrlMessageAppOps*>(&otr::g_options),
								static_cast<void*>((void*)&opdata),
								static_cast<const char*>(peer_recver_id.c_str()),
								static_cast<const char*>("BTOTR"),
								static_cast<const char*>(peer_sender_id.c_str()),
								static_cast<const char*>(real_message),
								static_cast<char**>(&newmessage),
								static_cast<OtrlTLV**>(nullptr),
								static_cast<ConnContext**>(nullptr),
								static_cast<AddAppDataFn>(nullptr),
								static_cast<void*>(nullptr)
							}
						);

						otr_is_enabled = my_rtti::call_func<ConnContext*>(
							licence.decrypt_string(15),
							licence.decrypt_string(16), {
								static_cast<OtrlUserState>(storage->get_state()),
								static_cast<const char*>(peer_sender_id.c_str()),
								static_cast<const char*>(peer_recver_id.c_str()),
								static_cast<const char*>("BTOTR"),
								static_cast<otrl_instag_t>(1),
								static_cast<int>(0),
								static_cast<int*>(nullptr),
								static_cast<AddAppDataFn>(nullptr),
								static_cast<void*>(nullptr)
							}
						);

					}

					if (newmessage) {

						if (otr_is_enabled && otr_is_enabled->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
							
							if (std::string(newmessage) == licence.decrypt_string(3) /*"BetterTelegram OTR Ended"*/) {

								auto storage = single<otr::c_storage_manager>();
								my_rtti::call_func<void>(
									licence.decrypt_string(15),
									licence.decrypt_string(18), {
										static_cast<OtrlUserState>(storage->get_state()),
										static_cast<const OtrlMessageAppOps*>(&otr::g_options),
										static_cast<void*>(nullptr),
										static_cast<const char*>(peer_recver_id.c_str()),
										static_cast<const char*>("BTOTR"),
										static_cast<const char*>(peer_sender_id.c_str())
									}
								);

								auto c_gui = single <api::c_gui>();
								auto active_chat = c_gui->get_active_window();
								if (is_group_chat && sender.id.value != our_id) {

									auto group_chat = storage->get_peer(output.first.first);
									std::lock_guard<std::mutex> lock(group_chat->group_data->peer_mutex);

									// only alerts the user if the message belongs to the current chat (dont spam them with disconnects in case theres tons of active OTR sessions)
									if (active_chat && (active_chat.value == output.first.first))
										c_gui->show_box("[BetterTelegram]: Chat peer " + (sender.first_name.length() ? sender.first_name : sender.user_name) + " has closed their OTR session!");

									group_chat->group_data->peers.erase(sender.id.value);
							
								} else {

									auto peer = storage->get_peer(sender.id.value);
									if (peer) {

										peer->is_authenticated = false;
										single <features::c_otr_messaging>()->update_button_state(c_gui, sender.id.value, false);

										if (active_chat && (active_chat.value == sender.id.value))
											c_gui->show_box("[BetterTelegram]: Peer OTR session with " + peer->info.first_name + " has ended!");
								
										storage->remove_peer(sender.id.value);

									}

								}
						
							}

							item->_text.text = QString::asprintf("[OTR]: %s", newmessage);

						}

						free(newmessage);

					}

					if (!item->_text.text.startsWith("?BETTER_TELEGRAM_") && !item->_text.text.startsWith("[OTR]") && !item->_text.text.startsWith("[CT]"))
						 item->_text.text = QString::asprintf("[CT]: %s", text.c_str());
		
				}

			}

		}

		return implant_helper(c_broadcast)->call_original <gsl::not_null<HistoryItem*>*>(instance, result, item, unread);
	}

#endif

}