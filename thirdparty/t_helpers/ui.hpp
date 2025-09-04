#pragma once

#include <vendor.h>
#include "util.hpp"
#include <ui/boxes/confirm_box.h>

// warning: everything from here must be called with an wrapper.
// read the documentation, it's an extremely unsafe!
namespace telegram::ui {

	// FNV1A64 form.
	enum e_icons : uint64_t {

		// MAIN BUTTONS:
		// 
		// left panel.
		k_archived_chats = 0x235F68042197D601,
		k_new_group = 0x72405DA7659D99D5,
		k_new_channel = 0x3211332D0AB53399,
		k_contacts = 0xCBDEDF5EC9D361F9,
		k_calls = 0x0D66D9FCED41E3AE,
		k_saved_messages = 0x01235F2F3D0C57A8,
		k_settings = 0x144A36EECC73CD77,
		k_night_mode = 0x8DC3B3BF84C7A3EC,

		// settings.
		k_my_account = 0x5655A1720658D6B5,
		k_notifications_and_sounds = 0xEECD50B5E9F895F7,
		k_privacy_and_security = 0x68E4F5FEE21F0424,
		k_chat_settings = 0xB0EB821A1EB40DCB,
		k_advanced = 0xBA0FF609D60A3EE3,
		k_speakers_and_camera = 0x7521C5D6B8699FA2,
		k_battery_and_animations = 0xD5633F53847EF2A0,
		k_language = 0x348C550DB91643A9,
		k_default_interface_scale = 0x40F04C4EB29BD8F7,
		k_telegram_business = 0xBE217057BD4D0298,
		k_send_a_gift = 0xCF99423876D23C79,
		k_telegram_faq = 0xC204E72A6002A478,
		k_telegram_features = 0x3C9932499EF6909B,
		k_ask_a_question = 0xFFA1CA355BF980C7,

		// my account.
		k_name = 0x5655A1720658D6B5,
		k_phone_number = 0x0D66D9FCED41E3AE,
		k_username = 0x843703255F92C771,
		k_personal_channel = 0x3211332D0AB53399,
		k_date_of_birth = 0xCF99423876D23C79,

		// notifications and sounds.
		k_private_chats = 0x5655A1720658D6B5,
		k_groups = 0x72405DA7659D99D5,
		k_channels = 0x3211332D0AB53399,

		// privacy and security.
		k_two_step_verification = 0x16ACC01ABABAB3A0,
		k_auto_delete_messages = 0x3041B02444E5E80A,
		k_local_passcode = 0x68E4F5FEE21F0424,
		k_blocked_users = 0x75BAF808E9466A69,
		k_connected_websites = 0x7FD346A48058BA0A,
		k_active_sessions = 0xDFF4D342CDC30D5A,

		// chat settings.
		k_your_name_color = 0x6A8EBC0B087F1238,
		k_auto_night_mode = 0x8DC3B3BF84C7A3EC,
		k_font_family = 0x6B5084A2FCA30FC9,
		k_edit_theme = 0x8B77485E2C1FF30A,
		k_manage_sticker_sets = 0xA042F53269E0E73E,
		k_choose_emoji_set = 0x472F092D7C2F802A,
		k_archive_settings = 0x8A69863A69289587,

		// folders.
		k_create_new_folder = 0xBACB6AF966B5F3F2,

		// advanced.
		k_connection_type = 0xEBA883EA2D3A7D9A,
		k_manage_local_storage = 0xB286985BC28A9D3D,
		k_downloads = 0xD4B3B737B02EBFE3,
		k_in_private_chats = 0x5655A1720658D6B5,
		k_in_groups = 0x72405DA7659D99D5,
		k_in_channels = 0x3211332D0AB53399,
		k_export_telegram_data = 0xBA16B1B8B325872E,
		k_experimental_settings = 0x4E9CCE34FEF98814,

		// battery and animations.
		k_animations_in_calls = 0x0D66D9FCED41E3AE,
		k_interface_animations = 0x717CBBA3E6DE267C,

		// - - - - -

		// ACTION BUTTONS:
		//
		// settings.
		k_add_account = 0xD3C1E4BEEA1BC6E6,
		k_edit_profile = 0xF03936B25AFD2E39,

		// chat settings.
		k_create_new_theme = 0x6A8EBC0B087F1238,

		// chat.
		k_view_profile = 0x5655A1720658D6B5,
		k_set_wallpaper = 0x6A8EBC0B087F1238,
		k_export_chat_history = 0xBA16B1B8B325872E,
		k_clear_history = 0xCF5838A6EA2BFBCF,

		// chat actions.
		k_open_in_new_window = 0xEA4621D15AA6A947,
		k_unarchive = 0x0818844D98DA10AE,
		k_pin = 0x074DF5B630EA8860,
		k_archive = 0x8A69863A69289587,
		k_mark_as_unread = 0xEEBEDFA32F33EE3E,
		k_unmute = 0x7521C5D6B8699FA2,
		k_stop_and_block_bot = 0x75BAF808E9466A69,

		// message actions.
		k_go_to_message = 0x40F04C4EB29BD8F7,
		k_copy = 0x5A87E7612033FA50,
		k_forward = 0x5534C12813A7774B,
		k_delete = 0x43A5EBA3C1170CDF,
		k_save_as = 0xD4B3B737B02EBFE3,
		k_view_all_photos = 0xCF5B26F737B15149,

		// user info.
		k_auto_delete = 0x3041B02444E5E80A,
		k_add_to_contacts = 0x292B8343DEF0973A,
		k_block_user = 0x75BAF808E9466A69,
		k_share_this_contact = 0xB7A9A8DD1625B400,
		k_edit_contact = 0xF03936B25AFD2E39,

		// channel.
		k_view_channel_info = 0x160B4ED371EC288E,
		k_boost_channel = 0x8087E51BE28ECBC8,
		k_view_discussion = 0xFFA1CA355BF980C7,
		k_report = 0xA6B9231BC1D50935,

		// group.
		k_create_topic = 0xFFA1CA355BF980C7,
		k_view_group_info = 0x160B4ED371EC288E,
		k_manage_group = 0xBA0FF609D60A3EE3,
		k_add_members = 0x292B8343DEF0973A,
		k_start_video_chat = 0x717CBBA3E6DE267C,
		k_schedule_video_chat = 0x61CD499121984E26,
		k_stream_with = 0xBA779088EAE81EC3,

		// group info.
		k_boosts = 0x8087E51BE28ECBC8,
		k_story_archive = 0x619438AD3AF4CF77,

		// topic.
		k_view_topic_info = 0x160B4ED371EC288E,
		k_edit_topic = 0xF03936B25AFD2E39,
		k_boost_group = 0x8087E51BE28ECBC8,
		k_create_poll = 0x581054E785112092,
		k_close_topic = 0x75BAF808E9466A69,

		// topic info.
		k_copy_topic_link = 0x5A87E7612033FA50,

	};

	static inline void add_separator(Ui::VerticalLayout* layout) {

#ifdef _WIN64
		// Ui::AddDivider(gsl::not_null<Ui::VerticalLayout *> container).
		single <memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), layout);
#endif

	}

	// repaint pixmap in case of theme update.
	static inline void repaint_pixmap(QPixmap* pixmap, QRgb color) {

		QPainter painter(pixmap);

		painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
		painter.fillRect(pixmap->rect(), color);
		painter.end();

	}

	static inline void rescale_icon(style::internal::Icon* icon, int32_t width, int32_t height) {

		auto parts = &icon->_data->_parts.front();
		auto mask = parts->_mask;

		QImage qt_img;
		qt_img.loadFromData(mask->data(), mask->size());

		qt_img = qt_img.scaled(width, height, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);

		// we don't need to update an mask since it's the same image.
		// but need to update mask image since it's upscaled now.
		parts->_maskImage = qt_img;

		// updating target image in pixmap.

#ifdef _WIN64
		// QPixmap::fromImage.
		single <memory::c_memory_util>()->call <QPixmap*>(generate_signature_ref("", ""), &parts->_pixmap, &qt_img, Qt::ColorMode_Mask);
#endif

	}

	static inline auto generate_icon(uint8_t* image, int32_t image_size, style::internal::IconData* copy_data, int32_t width, int32_t height) {

		auto icon = new style::internal::Icon();

#ifdef _WIN
		auto mask = reinterpret_cast <style::internal::IconMask*> (calloc(1, sizeof(style::internal::IconMask)));
#endif

		mask->_data = image;
		*reinterpret_cast <uintptr_t*> (reinterpret_cast <uint8_t*> (mask) + offsetof(style::internal::IconMask, _size)) = image_size;

		// getting mono_icon from copy target to replace it with our own image.
		// todo: refactor it?

#ifdef _WIN64
		// style::internal::IconData::IconData.
		single <memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), icon, std::in_place, &copy_data->_parts.front());
#endif

		auto parts = &icon->_data->_parts.front();
		parts->_mask = mask;

		// scaling icon (default is 128x128) to the target parameters.
		rescale_icon(icon, width, height);

		// repainting icon to following target theme.
		repaint_pixmap(&parts->_pixmap, parts->_color->c.rgb());
		return icon;
	}

}