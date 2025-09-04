#pragma once

#include <vendor.h>
#include <output.hpp>
#include <api/gui.hpp>
#include <t_helpers/api.hpp>
#include <t_helpers/peer.hpp>

#include <crypto/otrv3.hpp>

#include "../../public/api/rtti.hpp"
#include "../../public/api/licence.hpp"

using namespace rtti;

#include <set>

// TODO:MAKE FEATURES CLASS INSTANCE.
namespace features {

	struct otr_res_params {

		PeerData* last_peer;
		time_t first_msg_time;
		api::c_gui* instance;
		api::c_gui::button_options_t* options;

	};

	class c_otr_messaging : public c_singleton <c_otr_messaging> {

	public:

		static int make_rand_num() {

			srand(time(0));
			return 111111 + rand() % (999999 - 111111 + 1);

		}

		static unsigned long __stdcall poll_otr_response(void* args) {

			Sleep(3333);

			otr_res_params* params = (otr_res_params*)args;
			auto store = single <crypto::otr::c_storage_manager>();
			auto peer = store->get_peer(params->last_peer->id.value);

			if (peer) {

				auto& licence = licence::protection::get_instance();
				if (params->first_msg_time == peer->last_msg) store->remove_peer(params->last_peer->id.value);
				else params->instance->update_button_title(params->options, "Disable OTR mode", "Enable OTR mode");

			}

			free(params);
			return 0;
		}

		void generate_buttons(api::c_gui* ui) {

			using namespace api;
			using namespace crypto;

			// Button.
			auto otr = single <c_gui>()->create_button("otr", icons::e_registered_icons::k_otr, telegram::ui::k_clear_history);

			otr->title = L"Enable OTR mode";
			otr->callback = [this](c_gui* instance, c_gui::button_options_t* options) {

				auto& licence = licence::protection::get_instance();
				if (output::g_bt_plugin_conf.is_plugin_enabled("otr") && licence.is_otr_enabled()) {

					auto storage = single <otr::c_storage_manager>();
					auto last_peer = telegram::peer::get_last_peer();

					// TODO: for whatever reason this crashes randomly all the sudden at the time of activation/click of a button .. and also theres the bug that sent messages dont appear after sending ... fix these + debug the otr group discovery removal
					if (last_peer) {

						auto last_peer_id = last_peer->id.value;
						bool is_group_chat = last_peer->isChat() || last_peer->isChannel();
						auto active_peer = storage->get_peer(last_peer_id);
						
						std::string own_id_str = std::to_string(telegram::peer::get_own_id().value);
						std::string peer_id_str = std::to_string(last_peer_id);
						using AddAppDataFn = void(*)(void*, ConnContext*);

						// if this peer DOESNT EXIST yet & we are the first one to auth (since group chat gets created in broadcast.cpp when someone else authenticates first) 
						// OR for peers since they only need to be created once on each side
						if (!active_peer ? true : /* else if the peer DOES EXISTS and its a group chat */ (is_group_chat ? /* then check if the OTR button state is not already Enabled */
						!active_peer->group_data->is_otr_enabled : /* else if it did start AKE already, it authenticated so we dont need to do it again, skip */ false)) {

							if (is_group_chat) {

								if (!active_peer) {

									active_peer = storage->add_peer(last_peer, true, true, true);
									if (!active_peer) active_peer = storage->get_peer(last_peer_id);

								}

								if (active_peer && active_peer->group_data->peers.size()) {

									// set it to true because during broadcast if peer started AKE, then we already have group_data but we arent the AKE initiator
									active_peer->group_data->did_start_ake = true;
									active_peer->group_data->last_sent_discovery_msg = time(0);

									for (const auto& peer : active_peer->group_data->peers) {

										if (!peer.second->is_authenticated) {

											std::string peer_recver_id = (std::to_string(last_peer_id) + "_" + std::to_string(peer.first));
											std::string peer_sender_id = (std::to_string(last_peer_id) + "_" + std::to_string(telegram::peer::get_own_id().value));

											char* otr_init_msg = 0;
											std::string otr_message = licence.decrypt_string(2);
											gcry_error_t err = my_rtti::call_func<gcry_error_t>(
												licence.decrypt_string(15),
												licence.decrypt_string(17), {
													static_cast<OtrlUserState>(storage->get_state()),                             // 0
													static_cast<const OtrlMessageAppOps*>(&otr::g_options),                       // 1
													static_cast<void*>(nullptr),                                                  // 2
													static_cast<const char*>(peer_sender_id.c_str()),                             // 3
													static_cast<const char*>("BTOTR"),                                            // 4
													static_cast<const char*>(peer_recver_id.c_str()),                             // 5
													static_cast<otrl_instag_t>(OTRL_INSTAG_BEST),                                 // 6
													static_cast<const char*>(otr_message.c_str()),                                // 7
													static_cast<OtrlTLV*>(nullptr),                                               // 8
													static_cast<char**>(&otr_init_msg),											  // 9
													static_cast<OtrlFragmentPolicy>(OTRL_FRAGMENT_SEND_SKIP),                     // 10
													static_cast<ConnContext**>(nullptr),                                          // 11
													static_cast<AddAppDataFn>(nullptr),											  // 12
													static_cast<void*>(nullptr)                                                   // 13
												}
											);

											if (!err && otr_init_msg) {

												std::string otr_full_init_msg = "?BETTER_TELEGRAM_CHAT=" + std::to_string(last_peer_id) + ":" + std::to_string(peer.first) + "? " + otr_init_msg;
												telegram::unsafe::send_message(
													QString::fromStdString(otr_full_init_msg),
													last_peer->id);

												free(otr_init_msg);
											}

										}

									}

								} else /* in this case assume the peer opened telegram after a force-exit, and group chat was selected already, so chat_info.cpp hook wasnt called, send manual discovery */ {

									single<c_gui>()->show_box("[BetterTelegram]: In order to start an OTR session, a discovery message will be sent to your peers. Wait up to 10 seconds for all peers to discover you & then Enable-OTR again.");
									telegram::unsafe::send_message(QString::asprintf("?BETTER_TELEGRAM_PEER=%llu? ALIVE=FALSE,%d", last_peer_id, make_rand_num()), last_peer->id);

								}

							} else {

								char* otr_init_msg = 0;
								std::string otr_message = licence.decrypt_string(2);
								my_rtti::call_func<gcry_error_t>(
									licence.decrypt_string(15),
									licence.decrypt_string(17), {
										static_cast<OtrlUserState>(storage->get_state()),                             // 0
										static_cast<const OtrlMessageAppOps*>(&otr::g_options),                       // 1
										static_cast<void*>(nullptr),                                                  // 2
										static_cast<const char*>(own_id_str.c_str()),                                 // 3
										static_cast<const char*>("BTOTR"),                                            // 4
										static_cast<const char*>(peer_id_str.c_str()),                                // 5
										static_cast<otrl_instag_t>(OTRL_INSTAG_BEST),                                 // 6
										static_cast<const char*>(otr_message.c_str()),                                // 7
										static_cast<OtrlTLV*>(nullptr),                                               // 8
										static_cast<char**>(&otr_init_msg),											  // 9
										static_cast<OtrlFragmentPolicy>(OTRL_FRAGMENT_SEND_SKIP),                     // 10
										static_cast<ConnContext**>(nullptr),                                          // 11
										static_cast<AddAppDataFn>(nullptr),											  // 12
										static_cast<void*>(nullptr)                                                   // 13
									}
								);

								if (otr_init_msg) {

									storage->add_peer(last_peer);

									auto peer = single<c_gui>()->get_active_window();
									auto target_peer = peer ? peer : last_peer->id;
									// for solo chats make sure we are sending to the current active window (the foreground), to prevent chat window bug
									telegram::unsafe::send_message(QString::asprintf("?BETTER_TELEGRAM_PEER=%llu? %s", telegram::peer::get_own_id().value, otr_init_msg), target_peer);

									otr_res_params* res = (otr_res_params*)malloc(sizeof(otr_res_params));
									res->first_msg_time = time(0);
									res->last_peer = last_peer;
									res->instance = instance;
									res->options = options;
									// wait for response from buddy in otrv3.cpp - inject_message_callback
									CreateThread(0, 0, poll_otr_response, res, 0, 0);
									free(otr_init_msg);

								} else output::to_console("OTR: user %llu already authorizated!", last_peer_id);

							}

						} else {

							bool has_deauthed_group = false;
							if (is_group_chat) {

								// for a group, send the deauthentication message to everybody from the known peer list
								if (active_peer && active_peer->group_data && !active_peer->group_data->peers.empty() && active_peer->is_authenticated) {

									{
										std::lock_guard<std::mutex> lock(active_peer->group_data->peer_mutex);
										for (const auto& peer : active_peer->group_data->peers) {

											std::string group_recver_id = (std::to_string(last_peer_id) + "_" + std::to_string(peer.first));
											std::string group_sender_id = (std::to_string(last_peer_id) + "_" + std::to_string(telegram::peer::get_own_id().value));
											
											char* otr_group_deauth_msg = 0;
											std::string otr_message = licence.decrypt_string(3);
											gcry_error_t result = my_rtti::call_func<gcry_error_t>(
												licence.decrypt_string(15),
												licence.decrypt_string(17), {
													static_cast<OtrlUserState>(storage->get_state()),                             // 0
													static_cast<const OtrlMessageAppOps*>(&otr::g_options),                       // 1
													static_cast<void*>(nullptr),                                                  // 2
													static_cast<const char*>(group_sender_id.c_str()),                            // 3
													static_cast<const char*>("BTOTR"),                                            // 4
													static_cast<const char*>(group_recver_id.c_str()),                            // 5
													static_cast<otrl_instag_t>(OTRL_INSTAG_BEST),                                 // 6
													static_cast<const char*>(otr_message.c_str()),                                // 7
													static_cast<OtrlTLV*>(nullptr),                                               // 8
													static_cast<char**>(&otr_group_deauth_msg),									  // 9
													static_cast<OtrlFragmentPolicy>(OTRL_FRAGMENT_SEND_SKIP),                     // 10
													static_cast<ConnContext**>(nullptr),                                          // 11
													static_cast<AddAppDataFn>(nullptr),											  // 12
													static_cast<void*>(nullptr)                                                   // 13
												}
											);

											if (otr_group_deauth_msg) {

												telegram::unsafe::send_message(QString::asprintf("?BETTER_TELEGRAM_CHAT=%llu:%llu? %s", last_peer_id, peer.first, otr_group_deauth_msg), last_peer->id);
												free(otr_group_deauth_msg);

											}

											my_rtti::call_func<void>(
												licence.decrypt_string(15),
												licence.decrypt_string(18), {
													static_cast<OtrlUserState>(storage->get_state()),
													static_cast<const OtrlMessageAppOps*>(&otr::g_options),
													static_cast<void*>(nullptr),
													static_cast<const char*>(group_sender_id.c_str()),
													static_cast<const char*>("BTOTR"),
													static_cast<const char*>(group_recver_id.c_str())
												}
											);

											// important as many parts of the code rely on this
											peer.second->is_authenticated = false;

										}

									}

									active_peer->group_data->is_otr_enabled = (active_peer->is_authenticated = false);

									single <features::c_otr_messaging>()->update_button_state(single <api::c_gui>(), last_peer_id, true);
									has_deauthed_group = true;

								}

							} else {

								char* otr_peer_deauth_msg = 0;
								std::string otr_message = licence.decrypt_string(3);
								my_rtti::call_func<gcry_error_t>(
									licence.decrypt_string(15),
									licence.decrypt_string(17), {
										static_cast<OtrlUserState>(storage->get_state()),                             // 0
										static_cast<const OtrlMessageAppOps*>(&otr::g_options),                       // 1
										static_cast<void*>(nullptr),                                                  // 2
										static_cast<const char*>(own_id_str.c_str()),                                 // 3
										static_cast<const char*>("BTOTR"),                                            // 4
										static_cast<const char*>(peer_id_str.c_str()),                                // 5
										static_cast<otrl_instag_t>(OTRL_INSTAG_BEST),                                 // 6
										static_cast<const char*>(otr_message.c_str()),                                // 7
										static_cast<OtrlTLV*>(nullptr),                                               // 8
										static_cast<char**>(&otr_peer_deauth_msg),									  // 9
										static_cast<OtrlFragmentPolicy>(OTRL_FRAGMENT_SEND_SKIP),                     // 10
										static_cast<ConnContext**>(nullptr),                                          // 11
										static_cast<AddAppDataFn>(nullptr),											  // 12
										static_cast<void*>(nullptr)                                                   // 13
									}
								);

								if (otr_peer_deauth_msg) {

									telegram::unsafe::send_message(QString::asprintf("?BETTER_TELEGRAM_PEER=%llu? %s", telegram::peer::get_own_id().value, otr_peer_deauth_msg), last_peer->id);
									free(otr_peer_deauth_msg);

								}

								my_rtti::call_func<void>(
									licence.decrypt_string(15),
									licence.decrypt_string(18), {
										static_cast<OtrlUserState>(storage->get_state()),
										static_cast<const OtrlMessageAppOps*>(&otr::g_options),
										static_cast<void*>(nullptr),
										static_cast<const char*>(own_id_str.c_str()),
										static_cast<const char*>("BTOTR"),
										static_cast<const char*>(peer_id_str.c_str())
									}
								);
							}

							if (!is_group_chat || has_deauthed_group) {

								active_peer->is_active = options->current_state;
								output::to_console("OTR: switched state for user %llu. (state: %d)", active_peer->info.id.value, active_peer->is_active);

								if (!is_group_chat) storage->remove_peer(last_peer_id);
								else {
									std::lock_guard<std::mutex> lock(active_peer->group_data->peer_mutex);
									active_peer->group_data->peers.clear();
								}

								instance->update_button_title(options, "Disable OTR mode", "Enable OTR mode");

							}

						}

					}
				
				}

			};

			output::to_console("OTR: OK.\n");

		}

		void update_button_state(api::c_gui* ui, uint64_t peer_id, bool is_group, bool force_set_otr = false) {

			auto otr_state = ui->get_button_options("otr");
			auto storage = single <crypto::otr::c_storage_manager>();

			if (!force_set_otr) {

				auto chat = storage->get_peer(peer_id);
				otr_state->current_state = chat ? (is_group ? chat->group_data->is_otr_enabled : chat->is_authenticated) : false;

			} else
			otr_state->current_state = true;

			ui->update_button_title(otr_state, "Disable OTR mode", "Enable OTR mode");
			ui->update_button_options("otr", otr_state);

		}

	};

}