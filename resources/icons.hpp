#pragma once

#include "icons/module.h"
#include "icons/otr.h"
#include "icons/update.h"
#include "icons/offline.h"
#include "icons/garbage.h"
#include "icons/delete_acc.h"
#include "icons/reload.h"

namespace icons {

	enum class e_registered_icons {

		k_module = 0,
		k_otr,
		k_update,
		k_offline,
		k_garbage,
		k_delete_acc,
		k_reload

	};

	typedef struct {

		uint8_t* data;
		uint64_t size;

	} icon_info_t;

	static icon_info_t get_icon_info(e_registered_icons id) {

		switch (id) {

		default: {
			assert("unknown icon id!");
		}; break;

		case e_registered_icons::k_module: 	return { .data = icon::mod, .size = sizeof(icon::mod) };
		case e_registered_icons::k_otr: 	return { .data = icon::otr, .size = sizeof(icon::otr) };
		case e_registered_icons::k_update: 	return { .data = icon::update, .size = sizeof(icon::update) };
		case e_registered_icons::k_offline: return { .data = icon::offline, .size = sizeof(icon::offline) };
		case e_registered_icons::k_garbage: return { .data = icon::garbage, .size = sizeof(icon::garbage) };
		case e_registered_icons::k_delete_acc: return { .data = icon::delete_acc, .size = sizeof(icon::delete_acc) };
		case e_registered_icons::k_reload: return { .data = icon::reload, .size = sizeof(icon::reload) };

		};

	}

}