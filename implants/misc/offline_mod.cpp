#include "offline_mod.hpp"
#include <output.hpp>
#include <api/api_updates.h>
#include <mtproto/mtproto_concurrent_sender.h>
#include <gen/scheme.h>

namespace implant {

	register_implant(c_ghost_mode);
	register_implant(c_ghost_messages);

#ifdef _WIN64

	// Application::hasActiveWindow.
	//
	// explanation at link below:
	// https://github.com/telegramdesktop/tdesktop/blob/3b0bd9d1d1d21efd1cb9204a17656ce3fdcd8cd3/Telegram/SourceFiles/api/api_updates.cpp#L989.
	bool __fastcall c_ghost_mode::handler(Core::Application* instance, not_null<Main::Session*> session) {
		
		if (get_settings()->get <bool> ("ghost_mod")) {

			// that's odd, but there is no damage to telegram, since it calls only for 'check online'.
			return false;

		}
		
		return implant_helper(c_ghost_mode)->call_original <bool> (instance, session);
	}

	// todo: better to remake it as a callback.
	// 
	// tl::Writer<QVector<int>>::Put. (SerializedRequest::Serialize)
	void __fastcall c_ghost_messages::handler(QVector <uint32_t>* storage, uint32_t* packet_id) {

		if (get_settings()->get <bool> ("ghost_mod")) {

			// native accessing to the pointer since all checks for pointer are passed long before in core.
			auto packet = *packet_id;

			// todo: more packets?
			switch (packet) {

				// reading messages, interaction with the chat, etc.
				case mtpc_messages_readHistory:
				case mtpc_sendMessageTypingAction:
				case mtpc_sendMessageCancelAction:
				case mtpc_sendMessageRecordVideoAction:
				case mtpc_sendMessageUploadVideoAction:
				case mtpc_sendMessageRecordAudioAction:
				case mtpc_sendMessageUploadAudioAction:
				case mtpc_sendMessageUploadPhotoAction:
				case mtpc_sendMessageUploadDocumentAction:
				case mtpc_sendMessageGeoLocationAction:
				case mtpc_sendMessageChooseContactAction:
				case mtpc_sendMessageGamePlayAction:
				case mtpc_sendMessageRecordRoundAction:
				case mtpc_sendMessageUploadRoundAction:
				case mtpc_sendMessageHistoryImportAction:
				case mtpc_sendMessageChooseStickerAction:
				case mtpc_sendMessageEmojiInteraction: {

					// packet will be declined only to send, meanwhile, on our client everything will be processed as usually.
					*packet_id = 0;
					output::to_console("message interaction packet request was declined. [0x%0x]", packet);

				}; break;

			}

		}

		implant_helper(c_ghost_messages)->call_original <void>(storage, packet_id);
	}

#endif

}