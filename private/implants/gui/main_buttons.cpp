#include "main_buttons.hpp"

namespace private_implant {

	register_implant(c_main_buttons);

#ifdef _WIN64

	// Settings::AddButtonWithIcon.
	gsl::not_null <Ui::SettingsButton*>* __fastcall c_main_buttons::handler(gsl::not_null <Ui::SettingsButton*>* _button, gsl::not_null <Ui::VerticalLayout*> container, rpl::producer <QString>* text, const style::SettingsButton* settings, Settings::IconDescriptor* descriptor) {
		
		auto result = implant_helper(c_main_buttons)->call_original <gsl::not_null <Ui::SettingsButton*>*> (_button, container, text, settings, descriptor);

		if (descriptor->icon && !descriptor->icon->empty()) {

			static auto prev_icon_hash = ui::e_icons(0);

			auto icon_data = &descriptor->icon->_data->_parts.front();
			auto icon_mask = std::make_pair(icon_data->_mask, icon_data->_maskImage);

			auto icon_hash = ui::e_icons(hash::fnv1a64_rt(reinterpret_cast <const char*> (icon_mask.first->data()), icon_mask.first->size()));

			auto buttons = get_buttons(icon_hash);

			for (auto button : buttons) {

				// button can actually be a dead link due to "remove_button".
				if (button) {

					auto parameters = button->parameters;
					if (parameters.is_visible && (parameters.must_contain == prev_icon_hash || !parameters.must_contain)) {

						auto own_desc = *reinterpret_cast <Settings::IconDescriptor*> (descriptor);
						auto desc_data = own_desc.icon->_data;

						// creating an icon with a pixmap from other icon for current button.
						if (!button->icon_data) {
							button->icon_data = reinterpret_cast <uintptr_t> (ui::generate_icon(button->icon.data, button->icon.size, desc_data, desc_data->_width, desc_data->_height));
						}

						// in case of theme update.
						auto icon_parts = &reinterpret_cast <style::internal::Icon*> (button->icon_data)->_data->_parts.front();
						ui::repaint_pixmap(&icon_parts->_pixmap, icon_parts->_color->c.rgb());

						// generating a button.
						QString text = QString().fromStdWString(parameters.title);
						auto callback = std::function <void()>() = [=]() {
							
							button->parameters.current_state = !parameters.current_state;

							if (parameters.callback != nullptr) {
								parameters.callback(single <api::c_gui>(), &button->parameters);
							}

						};

						own_desc.icon = reinterpret_cast <style::icon*> (button->icon_data);

						if (parameters.separator_present) {
							ui::add_separator(container);
						}

						void* temp = nullptr;
						auto rpl = rpl::single(text);

						auto generated_button = implant_helper(c_main_buttons)->call_original <gsl::not_null <Ui::SettingsButton*>*> (&temp, container, &rpl, settings, &own_desc);

						if (parameters.toggler_present) {

							auto value = rpl::single(parameters.current_state);
							single <memory::c_memory_util>()->call <Ui::SettingsButton*>(generate_signature_ref("", ""), generated_button->get(), &value, false);

						}

						generated_button->get()->setClickedCallback(callback);

					}

				}

			}

			// to prevent the collisions..
			if (prev_icon_hash != icon_hash) {
				prev_icon_hash = icon_hash;
			}

		}

		return result;
	}

#endif

}