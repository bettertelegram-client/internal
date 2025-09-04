#include "send.hpp"
#include <output.hpp>
#include <os/util.hpp>
#include <api/gui.hpp>
#include <crypto/otrv3.hpp>

#include <../public/api/rtti.hpp>
#include <../public/api/licence.hpp>

using namespace rtti;

namespace private_implant {

	register_implant(c_send);

#ifdef _WIN64

	bool c_send::is_send_enabled = false;

	void c_send::set_send_enabled(bool enable) {

		static const uint32_t guard = 0xDEADBEEF;
		if ((guard ^ 0xCAFEBABE) == 0x14535451) __debugbreak();
		if ((enable & 0x1) == (enable ? 0x1 : 0x0)) is_send_enabled = enable;

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

	// Data::Histories::PrepareMessage<MTPmessages_SendMessage>.
	uint64_t __fastcall c_send::handler(uintptr_t a1, uintptr_t a2, MTPinputPeer* peer, uintptr_t a4, MTPString* message, uintptr_t a6, uintptr_t a7, uintptr_t a8, uintptr_t a9, uintptr_t a10, uintptr_t a11, uintptr_t a12, uintptr_t a13, uintptr_t a14, uintptr_t a15) {

		// setting up a local variables.
		// auto config = get_send_config();

		auto peer_type = uint32_t(peer->_type);
		// if something present in config. (and we're actually sending to somebody)
		// warning: this also prevents from the thread early startup access.
		auto receiver_id = [&]() {

			if (!peer) return uint64_t(0);

			// small fixes for llvm. (-Wc++11-narrowing)
			constexpr auto peer_user = uint32_t(mtpc_inputPeerUser), peer_user_from_message = uint32_t(mtpc_inputPeerUserFromMessage);

			switch (peer_type) {

				// also means 'MTPDinputPeerEmpty'.
				default: return uint64_t(0);

				case mtpc_inputPeerSelf: return telegram::peer::get_own_id().value;
				case mtpc_inputPeerChat: return peer->queryData <MTPDinputPeerChat>()._chat_id.v;
				case peer_user: return peer->queryData <MTPDinputPeerUser>()._user_id.v;
				case mtpc_inputPeerChannel: return peer->queryData <MTPDinputPeerChannel>()._channel_id.v;
				case peer_user_from_message: return peer->queryData <MTPDinputPeerUserFromMessage>()._user_id.v;

			}
			
		} ();

		auto mtp = *message;

		if (receiver_id) {

			if (!mtp.v.startsWith("?BETTER_TELEGRAM_") && output::g_bt_plugin_conf.is_plugin_enabled("otr") && is_send_enabled) {

				std::string recver_id = "";
				std::string sender_id = "";
				uint64_t group_id = 0, peer_id = 0;

				auto storage = single<crypto::otr::c_storage_manager>();
				auto& licence = licence::protection::get_instance();
				using AddAppDataFn = void(*)(void*, ConnContext*);

				if (peer_type == mtpc_inputPeerChat || peer_type == mtpc_inputPeerChannel) {

					group_id = single<api::c_gui>()->get_active_window().value;

					auto group_chat = storage->get_peer(group_id);
					if (group_chat) {

						auto& peers = group_chat->group_data->peers;
						for (auto it = peers.begin(); it != peers.end(); ++it) {
							auto& [_peer_id, group_peer] = *it;

							if (!group_peer) continue;
							if (group_peer->is_authenticated) {

								std::string peer_recver_id = std::to_string(group_id) + "_" + std::to_string(_peer_id);
								std::string peer_sender_id = std::to_string(group_id) + "_" + std::to_string(telegram::peer::get_own_id().value);

								ConnContext* session = my_rtti::call_func<ConnContext*>(
									licence.decrypt_string(15),
									licence.decrypt_string(16), {
										static_cast<OtrlUserState>(storage->get_state()),
										static_cast<const char*>(peer_recver_id.c_str()),
										static_cast<const char*>(peer_sender_id.c_str()),
										static_cast<const char*>("BTOTR"),
										static_cast<otrl_instag_t>(1),
										static_cast<int>(0),
										static_cast<int*>(nullptr),
										static_cast<AddAppDataFn>(nullptr),
										static_cast<void*>(nullptr)
									}
								);

								if (!session || session->msgstate != OTRL_MSGSTATE_ENCRYPTED)
									continue;
						
								char* encrypted_message = 0;
								gcry_error_t err = my_rtti::call_func<gcry_error_t>(
									licence.decrypt_string(15),
									licence.decrypt_string(17), {
										static_cast<OtrlUserState>(storage->get_state()),                             // 0
										static_cast<const OtrlMessageAppOps*>(&crypto::otr::g_options),               // 1
										static_cast<void*>(nullptr),                                                  // 2
										static_cast<const char*>(peer_sender_id.c_str()),                             // 3
										static_cast<const char*>("BTOTR"),                                            // 4
										static_cast<const char*>(peer_recver_id.c_str()),                             // 5
										static_cast<otrl_instag_t>(OTRL_INSTAG_BEST),                                 // 6
										static_cast<const char*>(mtp.v.constData()),                                  // 7
										static_cast<OtrlTLV*>(nullptr),                                               // 8
										static_cast<char**>(&encrypted_message),								      // 9
										static_cast<OtrlFragmentPolicy>(OTRL_FRAGMENT_SEND_SKIP),                     // 10
										static_cast<ConnContext**>(nullptr),                                          // 11
										static_cast<AddAppDataFn>(nullptr),											  // 12
										static_cast<void*>(nullptr)                                                   // 13
									}
								);

								if (encrypted_message) {
								
									if (err == GPG_ERR_NO_ERROR) {

										if (std::next(it) != peers.end()) {

											QString full_message = QString::asprintf("?BETTER_TELEGRAM_CHAT=%llu:%llu? %s", group_id, _peer_id, encrypted_message);
											telegram::unsafe::send_message(full_message, PeerId(group_id));

										} else {

											mtp = tl::make_string(QString::asprintf("?BETTER_TELEGRAM_CHAT=%llu:%llu? %s", group_id, _peer_id, encrypted_message));
											uint64_t ret = implant_helper(c_send)->call_original <uint64_t>(a1, a2, peer, a4, &mtp, a6, a7, a8, a9, a10, a11, a12, a13);
											free(encrypted_message);
											return ret;

										}
									}

									free(encrypted_message);
								}
							
							}
						
						}

					}

				} else {
					
					recver_id = std::to_string(receiver_id);
					sender_id = std::to_string(telegram::peer::get_own_id().value);
					
					ConnContext* this_session = my_rtti::call_func<ConnContext*>(
						licence.decrypt_string(15),
						licence.decrypt_string(16), {
							static_cast<OtrlUserState>(storage->get_state()),
							static_cast<const char*>(recver_id.c_str()),
							static_cast<const char*>(sender_id.c_str()),
							static_cast<const char*>("BTOTR"),
							static_cast<otrl_instag_t>(1),
							static_cast<int>(0),
							static_cast<int*>(nullptr),
							static_cast<AddAppDataFn>(nullptr),
							static_cast<void*>(nullptr)
						}
					);

					if (this_session) {

						if (this_session->msgstate == OTRL_MSGSTATE_ENCRYPTED) {

							char* encrypted_message = 0;
							gcry_error_t err = my_rtti::call_func<gcry_error_t>(
								licence.decrypt_string(15),
								licence.decrypt_string(17), {
									static_cast<OtrlUserState>(storage->get_state()),                             // 0
									static_cast<const OtrlMessageAppOps*>(&crypto::otr::g_options),               // 1
									static_cast<void*>(nullptr),                                                  // 2
									static_cast<const char*>(sender_id.c_str()),                                  // 3
									static_cast<const char*>("BTOTR"),                                            // 4
									static_cast<const char*>(recver_id.c_str()),                                  // 5
									static_cast<otrl_instag_t>(OTRL_INSTAG_BEST),                                 // 6
									static_cast<const char*>(mtp.v.constData()),                                  // 7
									static_cast<OtrlTLV*>(nullptr),                                               // 8
									static_cast<char**>(&encrypted_message),								      // 9
									static_cast<OtrlFragmentPolicy>(OTRL_FRAGMENT_SEND_SKIP),                     // 10
									static_cast<ConnContext**>(nullptr),                                          // 11
									static_cast<AddAppDataFn>(nullptr),											  // 12
									static_cast<void*>(nullptr)                                                   // 13
								}
							);


							if (encrypted_message) {

								if (err == GPG_ERR_NO_ERROR) {

									mtp = tl::make_string(encrypted_message);
								
									uint64_t ret = implant_helper(c_send)->call_original <uint64_t>(a1, a2, peer, a4, &mtp, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);
									free(encrypted_message);
									return ret;

								}

								free(encrypted_message);

							}

						}

					}

				}

				if (!mtp.v.startsWith("[CT]") && !mtp.v.startsWith("[OTR]"))
					 mtp = tl::make_string(QString::asprintf("[%s]: %s", !mtp.v.startsWith("?BETTER_TELEGRAM_") ? "CT" : "OTR", mtp.v.constData()));
				
			}
		
		}

		return implant_helper(c_send)->call_original <uint64_t>(a1, a2, peer, a4, &mtp, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);
	}
	
#endif

}