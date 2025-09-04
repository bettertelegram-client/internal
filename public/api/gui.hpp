#pragma once

#include <vendor.h>
#include <singleton.hpp>
#include <formatter.hpp>
#include <icons.hpp>

#include <t_helpers/ui.hpp>
#include <telegram/window/window_peer_menu.h>

namespace api {

	class c_gui : c_singleton <c_gui> {

	public:

		// button configuration.
		struct button_options_t {

			// button title. (can be changed based on current_state)
			std::wstring title = L"";

			// on click callback. (must return required state of the button)
			std::function <void(api::c_gui*, button_options_t*)> callback = nullptr;

			// determines if button enabled/disabled.
			bool current_state = false;

			// switcher as for 'Night Mode', for example.
			// note: not gonna work for action buttons.
			bool toggler_present = true;

			// determines current visibility status of button.
			bool is_visible = true;

			// creates separator above button. (only for the main icons)
			bool separator_present = false;

			// allows to render button only if target icon exist above in the same box.
			// e.g in case that there is same icons that used in different box'es.
			telegram::ui::e_icons must_contain = telegram::ui::e_icons(0);

		};

	public:
		
		// alternative for the system message boxes to notify something right in the GUI.
		// note: separator used by the default to simulate header.
		void show_box(std::string text);

		// wide-support variant of show box.
		void show_box(std::wstring text);

		// creates a target button with an icon below a telegram icon.
		// callback can be empty, but state will be changed on click!
		auto create_button(const char* name, icons::e_registered_icons icon, telegram::ui::e_icons icon_above_1/*, telegram::ui::e_icons icon_above_2*/) -> button_options_t*;

		// removes a button from render list.
		bool remove_button(const char* name);

		// updating button title based on their current state.
		void update_button_title(const char* name, std::wstring turn_on, std::wstring turn_off);

		// ASCII variant of updating button title.
		void update_button_title(const char* name, std::string turn_on, std::string turn_off);

		// updating button title based on their current state. (callback version/wide)
		void update_button_title(button_options_t* options, std::wstring turn_on, std::wstring turn_off);

		// updating button title based on their current state. (callback version/ascii)
		void update_button_title(button_options_t* options, std::string turn_on, std::string turn_off);

		// get current options for target button. (used to determine whenever state changed or just get a settings)
		auto get_button_options(const char* name) -> button_options_t*;

		// send's a request to update current button configuration.
		void update_button_options(const char* name, button_options_t* options);

		// get the current active window (peer/group chat) with which the user is interacting
		PeerId get_active_window();

		// version with C-style formatter for the arguments. (ASCII variant)
		template <typename... Args>
		inline void show_box(std::string text, Args... args) {
			this->show_box(formatter::to_string(text, std::forward <Args>(args)...));
		}

		// version with C-style formatter for the arguments. (wide variant)
		template <typename... Args>
		inline void show_box(std::wstring text, Args... args) {
			this->show_box(formatter::to_wide(text, std::forward <Args>(args)...));
		}

	protected:

		struct button_t {

			// fnv1a hash of the name.
			uint64_t id;

			// settings for the button.
			button_options_t parameters;

			// info about our own.
			icons::icon_info_t icon;

			// icon above our own button.
			telegram::ui::e_icons icon_above_1;
			telegram::ui::e_icons icon_above_2;

			// reserved for the internals purposes.
			uintptr_t icon_data = 0;

			// creates a button with an default option. (accessible only for inheritor)
			button_t(icons::e_registered_icons icon, telegram::ui::e_icons above_1, /*telegram::ui::e_icons above_2,*/ const char* name) {

				this->id = hash::fnv1a64_ct(name);

				this->icon = icons::get_icon_info(icon);
				this->icon_above_1 = above_1;
				// this->icon_above_2 = above_2;

				this->parameters = button_options_t {};

			}

		};

		// builds a vector of buttons that requires target telegram icon to be rendered.
		static inline auto get_buttons(telegram::ui::e_icons icon) {

			std::vector <button_t*> buttons;

			// TODO: figure out how to skip the button here if it has already been added in action_buttons.cpp (right now it appears fine in sinister group chat .. once but in normal group chats its doubled (both icon_above's are found)
			for (auto& button : m_buttons) {

				if (button->icon_above_1 == icon/* || button->icon_above_2 == icon */) {
					buttons.emplace_back(button);
				}

			}

			return buttons;
		}

		// builds up a hash for button name and search if it's present in the map.
		// be aware: can be null.
		static inline button_t* get_button(const char* name) {

			auto id = hash::fnv1a64_ct(name);

			for (auto& button : m_buttons) {

				if (button->id == id) {
					return button;
				}

			}

			return nullptr;
		}

	private:

		static std::vector <button_t*> m_buttons;

	};

}