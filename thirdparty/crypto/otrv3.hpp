#pragma once

#include <vendor.h>
#include <stdlib.h>

#include "otr_helper.hpp"

#include <libgcrypt/gcrypt.hpp>
#include <libotr/proto.hpp>
#include <libotr/userstate.hpp>
#include <libotr/context.hpp>
#include <libotr/message.hpp>
#include <libotr/privkey.hpp>

// todo: remove debug prints in the future.
namespace crypto::otr {

    struct opdata_struct {

        BareId sender_id;
        BareId group_id;

    };

    void gen_fingerprint(void* data, OtrlUserState user_state, const char* account_name, const char* protocol, const char* user_name, unsigned char fingerprint[20]);
    OtrlPolicy get_policy(void* data, ConnContext* context);
    int is_logged_in(void* data, const char* account_name, const char* protocol, const char* recipient);
    void add_appdata(void* data, ConnContext* context);
    void inject_message(void* data, const char* account_name, const char* protocol, const char* recipient, const char* message);
    void write_fingerprints(void* data);
    void update_context_list(void* data);
    void gone_secure(void* data, ConnContext* context);
    void gone_insecure(void* data, ConnContext* context);
    void still_secure(void* data, ConnContext* context, int is_reply);
    const char* error_message(void* data, ConnContext* context, OtrlErrorCode error_code);
    void error_message_free(void* data, const char* error_message);
    void log_message(void* data, const char* message);
    int max_message_size(void* data, ConnContext* context);
    const char* account_name(void* data, const char* account_name, const char* protocol);
    void account_name_free(void* data, const char* account_name);
    void received_symkey(void* data, ConnContext* context, unsigned int use, const unsigned char* use_data, size_t use_data_length, const unsigned char* sym_key);
    const char* resent_msg_prefix(void* data, ConnContext* context);
    void resent_msg_prefix_free(void* data, const char* prefix);
    void handle_smp_event(void* data, OtrlSMPEvent smp_event, ConnContext* context, unsigned short progress_percent, char* question);
    void handle_msg_event(void* data, OtrlMessageEvent msg_event, ConnContext* context, const char* message, unsigned int error);
    void convert_msg(void* data, ConnContext* context, OtrlConvertType type, char** dst, const char* src);
    void convert_free(void* data, ConnContext* context, char* dst);
    void create_instag(void* data, const char* account_name, const char* protocol);
    void create_privkey(void* data, const char* account_name, const char* protocol);

    static s_OtrlMessageAppOps g_options = {

        get_policy,             create_privkey,         is_logged_in,       inject_message,
        update_context_list,    gen_fingerprint,        write_fingerprints, gone_secure,
        gone_insecure,          still_secure,           max_message_size,   account_name,
        account_name_free,      received_symkey,        error_message,      error_message_free,
        resent_msg_prefix,      resent_msg_prefix_free, handle_smp_event,   handle_msg_event,
        create_instag,          convert_msg,            convert_free

    };

}