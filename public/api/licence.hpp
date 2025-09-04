#pragma once 

#ifndef _LICENCE_HPP_
#define _LICENCE_HPP_

#include <Windows.h>

#include <cryptlib.h>
#include <chacha.h>
#include <rabbit.h>
#include <hex.h>

#include <nlohmann/json.hpp>

#define SECURITY_WIN32
#include <security.h>
#define SCHANNEL_USE_BLACKLISTS
#include <subauth.h>
#include <schnlsp.h>
#include <shlwapi.h>
#include <WS2tcpip.h>

#include "../thirdparty/singleton.hpp"
#include "../public/api/rtti.hpp"

#include "../../implants/text/broadcast.hpp"
#include "../../implants/text/chat/chat_info.hpp"
#include "../../private/implants/text/item_update.hpp"
#include "../../private/implants/text/send.hpp"

#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

using namespace CryptoPP;

#define my_max(x, y) ((x) >= (y) ? (x) : (y))
#define my_min(x, y) ((x) <= (y) ? (x) : (y))

#define TLS_MAX_PACKET_SIZE (16384+512)

namespace licence {

	typedef struct {
		unsigned long long sock;
		CredHandle handle;
		CtxtHandle context;
		SecPkgContext_StreamSizes sizes;
		int received;
		int used;
		int available;
		char* decrypted;
		char incoming[TLS_MAX_PACKET_SIZE];
	} tls_socket;

	class protection : public c_singleton <protection> {

	public:

		static protection& init_instance(nlohmann::json json, std::string& uuid) {
			if (!instance) instance = std::make_unique<protection>(std::move(json), std::move(uuid));
			return *instance;
		}

		static protection& get_instance() {
			if (!instance) __debugbreak();
			return *instance;
		}

		protection(nlohmann::json json, std::string uuid) {

			this->nonce_list = json["1"].get<std::vector<std::string>>();
			this->rabbit_keys = json["2"].get<std::vector<std::string>>();
			this->chacha_keys = json["3"].get<std::vector<std::string>>();
			this->enc_str_list = json["4"].get<std::string>();
			this->licence_uuid = strdup(uuid.c_str());
		}

		~protection() {

			dec_key_order.clear();
			rabbit_keys.clear();
			chacha_keys.clear();
			nonce_list.clear();
			free(licence_uuid);
		}

		std::string decrypt_string(const std::string& encrypted_string, const std::string& chacha_key_hex, const std::string& rabbit_key_hex, const std::string& nonce_hex);
		std::string decrypt_string(int index);

		private_implant::c_send& get_send() { return send_hook; }
		implant::c_broadcast& get_broadcast() { return broadcast_hook; }
		implant::c_chat_info& get_chat_info() { return chat_info_hook; }
		private_implant::c_item_update& get_item_update() { return item_update_hook; }

		std::string string_base64_decode(const std::string& in);
		std::vector<unsigned char> byte_base64_decode(const std::string& input);
		std::string rc4_decode(const std::string& message, const std::string& secret_key);
		nlohmann::json send_get_request(const std::string& url, const std::string& session_key);
		nlohmann::json send_post_request(const std::string& url, const nlohmann::json& post_data, const std::string& cipher_key);

		const bool is_otr_enabled() { return this->_is_otr_enabled; }
		void set_otr_enabled() { this->_is_otr_enabled = true; }

	private:

		std::string base64_encode(const unsigned char* input, size_t len);
		unsigned char decode_base64_char(char c);
		std::string encrypt_aes(const std::string& plaintext, const std::string& session_key);
		std::string decrypt_aes(const std::string& b64_input, const std::string& session_key);
		bool check_cert_hash(const uint8_t* cert_hash_in_memory, const std::string& obfuscated_cert_hash);
		int tls_connect(tls_socket* s, const char* hostname, unsigned short port);
		int tls_write(tls_socket* s, const void* buffer, int size);
		int tls_read(tls_socket* s, void* buffer, int size);
		void tls_disconnect(tls_socket* s);
		std::string sha256(const char* str);
		// void generate_licence_order(std::string& enc_string, const char* unique_value);
		std::string generate_timebased_OTP(const std::string& session_key);
		void unlock_cert_hash(uint8_t* hash) {
			const uint8_t parts[32] = {
				0xCA, 0xE1, 0x8C, 0xF5, 0x75, 0x51, 0x95, 0x2E,
				0x80, 0xDA, 0x40, 0x71, 0xBE, 0x86, 0xF4, 0x33,
				0x9E, 0x40, 0x83, 0x03, 0x1D, 0x81, 0x86, 0x7F,
				0xEB, 0x59, 0xD6, 0x38, 0x71, 0x06, 0x81, 0x57
			};
			for (int i = 0; i < 32; ++i) hash[i] = parts[i] ^ 0x37;
		}

		std::vector<std::string> nonce_list, rabbit_keys, chacha_keys;
		std::vector<int> dec_key_order;
		bool _is_otr_enabled = false;
		std::string enc_str_list;
		char* licence_uuid;

		implant::c_broadcast broadcast_hook;
		implant::c_chat_info chat_info_hook;
		private_implant::c_send send_hook;
		private_implant::c_item_update item_update_hook;

		static std::unique_ptr<protection> instance;

		friend class c_singleton<protection>;
		protection() = default;
	};

}

#endif