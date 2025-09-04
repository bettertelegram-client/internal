#pragma once

#include <vendor.h>
#include "peer.hpp"
#include "util.hpp"
#include <base/random.h>
#include <api/api_text_entities.h>

// please, read the documentation before use any of it.
// it's extremely unsafe to call it in the main thread of this module.
namespace telegram::unsafe {

	struct message_config_t {

		void* history;

		Api::SendOptions options;
		FullReplyTo reply_to;

		bool clear_craft = true, generate_local = true;
		MsgId replace_media_of = 0;

		message_config_t(Main::Session* session, PeerId peer) {

			this->history = telegram::peer::get_history(session->_data->_histories.get(), peer);
			this->options = Api::SendOptions{ 0 };
			this->reply_to = FullReplyTo{

				.messageId = { peer, 0 },
				.quote = { TextWithEntities::Simple("") },
				.storyId = { 0 },
				.topicRootId = 0

			};

		}

	};

	static inline void set_active_mode(bool is_online) {

		// since packet requires 'm_offline' field.
		auto status = is_online ? mtpc_boolFalse : mtpc_boolTrue;

		// crash fix: let's be sure that session are present to send API requests,
		//            otherwise client might crash on login menu.
		if (!telegram::get_active_session()) return;

		// building the request via official API.
		auto request = telegram::get_active_session()->api().request(reinterpret_cast <MTPaccount_UpdateStatus&&> (status));

		// these one just dummies, i assume just a todo purposes?
		auto mute_done = std::function([](const MTP::Response&) { return true; });
		auto mute_error = std::function([](const MTP::Error&, const MTP::Response&) { return false; });
		request.setDoneHandler(reinterpret_cast <MTP::DoneHandler&&> (mute_done));
		request.setFailHandler(reinterpret_cast <MTP::FailHandler&&> (mute_error));

#ifdef _WIN64
		// MTP::Instance::send<tl::boxed<MTPaccount_updateStatus>>.
		single <memory::c_memory_util>()->call <mtpMsgId>(generate_signature("", ""), request._sender->_instance, &request._request, &request._done, &request._fail, request._dcId, request._canWait, request._afterRequestId, request._overrideRequestId);
#endif

	}

	// WARNING: THREAD-UNSAFE FUNCTIONS.
	// PLEASE, USE IT WITH WRAPPER.
	static inline void send_message(ApiWrap* api, Api::MessageToSend* message) {

		// ApiWrap::sendMessage.
#ifdef _WIN64
		single <memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), api, message);
#endif

	}

	// passing QString in arguments to support unicode from the beginning.
	static inline void send_message(QString text, PeerId peer) {

		auto session = telegram::get_active_session();

		auto configuration = unsafe::message_config_t(session, peer);
		auto message = Api::MessageToSend(*reinterpret_cast <Api::SendAction*> (&configuration));
		message.textWithTags.text = text;

		send_message(session->_api.get(), &message);
	}

}