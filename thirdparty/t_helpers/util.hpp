#pragma once

#include <vendor.h>

// API.
#include <stdafx.h>
#include <apiwrap.h>
#include <api/api_common.h>
#include <data/data_peer.h>
#include <data/data_user.h>
#include <data/data_chat.h>
#include <history/history.h>
#include <core/application.h>
#include <main/main_domain.h>
#include <main/main_session.h>
#include <main/main_account.h>
#include <data/data_session.h>
#include <data/data_channel.h>
#include <data/data_histories.h>
#include <history/history_item.h>
#include <data/data_forum_topic.h>
#include <lib_ui/ui/widgets/buttons.h>
#include <telegram/ui/boxes/confirm_box.h>
#include <telegram/window/window_controller.h>
#include <telegram/window/window_main_menu.h>
#include <lib_ui/ui/platform/ui_platform_window.h>
#include <telegram/window/window_session_controller.h>

#include "memory.hpp"

// can be called from anywhere.
namespace telegram {

	inline static auto get_instance() {

		Core::Application* instance = nullptr;

		if (!instance) {
#ifdef _WIN64
			instance = single <memory::c_memory_util>()->call <Core::Application*>(generate_signature_ref("", ""));
#endif
		}

		return instance;
	}

	inline static auto get_active_session() {

		auto domain = get_instance()->_domain.get();
		auto account = domain->_active.current();

		return account->_session.get();
	}

	inline static auto get_settings() {

		//
		// for now, 'm_ui' have size of system pointer, but i'm not too sure about future. 
		// laying that much on internal leads to possible UD. need to rewrite it.
		// 
		// todo: rewrite, too much of internals.
		//

		typedef struct {

			base::Timer m_timer;
			uintptr_t m_ui;
			Core::Settings m_settings;

		} priv_t;

		auto priv = reinterpret_cast <priv_t*> (get_instance()->_private.get());
		return &priv->m_settings;
	}

}