#include "otrv3.hpp"
#include <api/gui.hpp>
#include <t_helpers/api.hpp>
#include "../../../implants/text/chat/otr_messaging.hpp"

void crypto::otr::gen_fingerprint(void* data, OtrlUserState user_state, const char* account_name, const char* protocol, const char* user_name, unsigned char fingerprint[20]) {

    printf("[OTR] gen_fingerprint -> processing request... (account_name: %s, user_name: %s)\n", account_name, user_name);

    char out_fingerprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
    memset(&out_fingerprint, 0, OTRL_PRIVKEY_FPRINT_HUMAN_LEN);

    otrl_privkey_fingerprint(user_state, out_fingerprint, account_name, protocol);

    printf("[OTR] gen_fingerprint -> result: %s.\n", out_fingerprint);
}

OtrlPolicy crypto::otr::get_policy(void* data, ConnContext* context) {
    // printf("[OTR] get_policy -> processing request...\n");
    return OTRL_POLICY_ALLOW_V3 | OTRL_POLICY_REQUIRE_ENCRYPTION;
}

int crypto::otr::is_logged_in(void* data, const char* account_name, const char* protocol, const char* recipient) {
    // printf("[OTR] is_logged_in -> processing request... (account_name: %s, recipient: %s)\n", account_name, recipient);
    return -1;
}

void crypto::otr::add_appdata(void* data, ConnContext* context) {
    // printf("[OTR] add_appdata -> processing request...\n");
}

void crypto::otr::inject_message(void* data, const char* account_name, const char* protocol, const char* recipient, const char* message) {

    printf("[OTR] inject_message -> processing request... (data: 0x%p, account_name: %s, recipient: %s)\n", data, account_name, recipient);
    
    opdata_struct* opdata = (opdata_struct*) data;

    BareId recver_id = telegram::peer::get_own_id().value;
    peer_data_t* remote_peer = 0;
    
    if (!opdata->group_id) {

        // if this is received, OTR response is sent so it means buddy is not offline (so we dont mess up the OTR state in otr_messaging.hpp)
        remote_peer = single <c_storage_manager>()->get_peer(opdata->sender_id);
        if (remote_peer) remote_peer->last_msg = time(0);

    }

    // printf("[OTR] inject_message -> sending message to %llu from %llu\n", opdata->sender_id, recver_id);

    telegram::unsafe::send_message((
        !opdata->group_id ? 
        QString::asprintf("?BETTER_TELEGRAM_PEER=%llu? %s", recver_id, message) : 
        QString::asprintf("?BETTER_TELEGRAM_CHAT=%llu:%llu? %s", opdata->group_id, opdata->sender_id, message)),
        !opdata->group_id ? remote_peer->info.id : PeerId(opdata->group_id));
}

void crypto::otr::write_fingerprints(void* data) {
    // printf("[OTR] write_fingerprints -> processing request...\n");
}

void crypto::otr::update_context_list(void* data) {
    // printf("[OTR] update_context_list -> processing request...\n");
}

std::vector<std::string> group_split_id(const std::string& input) {

    std::vector<std::string> parts;
    std::stringstream ss(input);
    std::string segment;

    while (std::getline(ss, segment, '_')) parts.push_back(segment);

    return parts;
}

void crypto::otr::gone_secure(void* data, ConnContext* context) {
    printf("[OTR] SECURE -> passed... (data: 0x%p, accountname: %s, username: %s)... passed\n", data, context->accountname, context->username);

    opdata_struct* opdata = (opdata_struct*)data;
    auto storage = single<otr::c_storage_manager>();

    if (opdata->group_id /* chat 1:many OTR */) {

        auto peer_info    = group_split_id(context->username);
        auto account_info = group_split_id(context->accountname);
        
        if (account_info.size() == 2 && peer_info.size() == 2) {

            if (std::stoull(account_info[0]) == opdata->group_id && std::stoull(account_info[1]) == telegram::peer::get_own_id().value) {

                int64_t peer_id = std::stoull(peer_info[1]);
                auto otrv3 = storage->get_peer(opdata->group_id);

                if ((otrv3 && otrv3->group_data) && otrv3->group_data->peers.contains(peer_id)) {

                    auto peer = otrv3->group_data->peers.at(peer_id);
                    {
                        std::lock_guard<std::mutex> lock(otrv3->group_data->peer_mutex);
                        peer->is_authenticated = true;
                    }

                    bool all_peers_authenticated = true;
                    for (const auto& peer : otrv3->group_data->peers) if (!peer.second->is_authenticated) all_peers_authenticated = false;

                    if (all_peers_authenticated && !peer->sent_auth_notification) {{

                        std::lock_guard<std::mutex> lock(otrv3->group_data->peer_mutex);
                        otrv3->group_data->is_otr_enabled = (peer->sent_auth_notification = true);
                        otrv3->group_data->sent_otr_group = false;
                        otrv3->is_authenticated = true; }
                    
                        auto c_gui = single<api::c_gui>();
                        auto active_chat = c_gui->get_active_window();
                        single <features::c_otr_messaging>()->update_button_state(c_gui, opdata->group_id, true);
                        if (active_chat && (active_chat.value == opdata->group_id))
                            c_gui->show_box("[BetterTelegram]: Group OTR authentication complete! Your buddies should do the same in order to chat.");

                    }

                }

            }

        }

    } else /* solo 1:1 OTR */ {
    
        auto peer = storage->get_peer(opdata->sender_id);
        if (peer) {

            peer->is_authenticated = true;

            auto c_gui = single <api::c_gui>();
            single <features::c_otr_messaging>()->update_button_state(c_gui, opdata->sender_id, false);

            if (c_gui)
            c_gui->show_box("[BetterTelegram]: OTR session with " + peer->info.first_name + " has started!");

        }

    }

}

void crypto::otr::gone_insecure(void* data, ConnContext* context) {
    // printf("[OTR] IN-SECURE -> processing request... (data: %p)\n", data);
}

void crypto::otr::still_secure(void* data, ConnContext* context, int is_reply) {
    // printf("[OTR] still_secure -> processing request...\n");
}

const char* crypto::otr::error_message(void* data, ConnContext* context, OtrlErrorCode error_code) {
    // printf("[OTR] error_message -> processing request... (code: %d)\n", error_code);
    return 0;
}

void crypto::otr::error_message_free(void* data, const char* error_message) {

    // printf("[OTR] error_message_free -> processing request... (message: %s)\n", error_message);

    if (error_message) {
        free((void*)error_message);
    }

}

void crypto::otr::log_message(void* data, const char* message) {
    // unused?
}

int crypto::otr::max_message_size(void* data, ConnContext* context) {
    // printf("[OTR] max_message_size -> processing request...\n");
    return 8192;
}

const char* crypto::otr::account_name(void* data, const char* account_name, const char* protocol) {

    auto result = strdup(account_name);
    // printf("[OTR] account_name -> processing request... (result: %s)\n", result);

    return result;
}

void crypto::otr::account_name_free(void* data, const char* account_name) {

    // printf("[OTR] account_name_free -> processing request...\n");

    if (account_name) {
        free((void*)account_name);
    }

}

void crypto::otr::received_symkey(void* data, ConnContext* context, unsigned int use, const unsigned char* use_data, size_t use_data_length, const unsigned char* sym_key) {
    // printf("[OTR] received_symkey -> processing request... (use: %d, use_data: 0x%p, use_data_length: %llu, sym_key: 0x%p)\n", use, use_data, use_data_length, sym_key);
}

const char* crypto::otr::resent_msg_prefix(void* data, ConnContext* context) {
    // printf("[OTR] resent_msg_prefix -> processing request...\n");
    return 0;
}

void crypto::otr::resent_msg_prefix_free(void* data, const char* prefix) {
    // printf("[OTR] resent_msg_prefix_free -> processing request (prefix: %s)\n", prefix);

    if (prefix) {
        free((void*)prefix);
    }

}

void crypto::otr::handle_smp_event(void* data, OtrlSMPEvent smp_event, ConnContext* context, unsigned short progress_percent, char* question) {

    // printf("[OTR] handle_smp_event -> processing request... (smp_event: %d, progress_percent: %d, question: %p)\n", smp_event, progress_percent, question);

}

void crypto::otr::handle_msg_event(void* data, OtrlMessageEvent msg_event, ConnContext* context, const char* message, unsigned int error) {

    opdata_struct* opdata = (opdata_struct*)data;
    auto storage = single<otr::c_storage_manager>();

    switch (msg_event) {

        case OTRL_MSGEVENT_ENCRYPTION_ERROR: {
            printf("[OTR] handle_msg_event = ENCRYPTION ERROR\n");
        }; break;

        case OTRL_MSGEVENT_CONNECTION_ENDED: {
            printf("[OTR] handle_msg_event = CONNECTION ENDED\n");
        }; break;

        case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE: {
            printf("[OTR] handle_msg_event = RCVDMSG NOT IN PRIVATE\n");
        }; break;

        case OTRL_MSGEVENT_RCVDMSG_UNREADABLE: {
            printf("[OTR] handle_msg_event = RCVDMSG UNREADABLE\n");
        }; break;

        case OTRL_MSGEVENT_RCVDMSG_MALFORMED: {
            printf("[OTR] handle_msg_event = RCVDMSG MALFORMED\n");
        }; break;

        case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED: {
            printf("[OTR] handle_msg_event = RCVDMSG UNENCRYPTED\n");
        }; break;

        case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED: {
            printf("[OTR] handle_msg_event = RCVDMSG UNRECOGNIZED\n");
        }; break;

        case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE: {
            printf("[OTR] handle_msg_event = RCVDMSG FOR OTHER INSTANCE\n");
        }; break;

    }

}

void crypto::otr::convert_msg(void* data, ConnContext* context, OtrlConvertType type, char** dst, const char* src) {
    printf("[OTR] convert_msg -> processing request... (type: %d, src: %s)\n", type, src);
}

void crypto::otr::convert_free(void* data, ConnContext* context, char* dst) {

    // printf("[OTR] convert_free -> processing request...\n");

    if (dst) free((void*)dst);

}

void crypto::otr::create_instag(void* data, const char* account_name, const char* protocol) {

    printf("[OTR] create_instag -> processing request... (data: 0x%p, account_name: %s)\n", data, account_name);

    auto appdata_path = std::string(std::getenv("APPDATA"));
    if (!appdata_path.empty()) {

        printf("[OTR] create_instag -> generating...\n");

        std::filesystem::path path = appdata_path.append("\\BetterTelegram\\keys\\").append(account_name).append("_instag.txt");
        otrl_instag_generate(single <otr::c_storage_manager>()->get_state(), path.string().c_str(), account_name, protocol);

        printf("[OTR] create_instag -> result stored at %s.\n", path.string().c_str());

    }

}

void crypto::otr::create_privkey(void* data, const char* account_name, const char* protocol) {

    printf("[OTR] create_privkey -> processing request... (data: 0x%p, account_name: %s)\n", data, account_name);

    auto appdata_path = std::string(std::getenv("APPDATA"));
    if (!appdata_path.empty()) {

        printf("[OTR] create_privkey -> generating...\n");
        std::filesystem::path path = appdata_path.append("\\BetterTelegram\\keys\\").append(account_name).append("_private.key");

        otrl_privkey_generate(single <otr::c_storage_manager>()->get_state(), path.string().c_str(), account_name, protocol);
        otrl_privkey_read(single <otr::c_storage_manager>()->get_state(), path.string().c_str());

        printf("[OTR] create_privkey -> result stored at %s.\n", path.string().c_str());

    }

}