#include "action_buttons.hpp"

namespace private_implant {

	register_implant(c_action_buttons);

#ifdef _WIN64

	// Ui::Menu::MenuCallback::operator.
	QAction* __fastcall c_action_buttons::handler(Ui::Menu::MenuCallback* instance, QString* _text, std::function <void()>* _handler, style::internal::Icon* _icon) {

		using namespace telegram;

		static auto prev_icon_hash = ui::e_icons(0);
		
		auto icon_data = &_icon->_data->_parts.front();
		auto icon_mask = std::make_pair(icon_data->_mask, icon_data->_maskImage);

		auto icon_hash = ui::e_icons(hash::fnv1a64_rt(reinterpret_cast <const char*> (icon_mask.first->data()), icon_mask.first->size()));

		auto buttons = get_buttons(icon_hash);

		// so if we set the button, we can set it to true in the list, but how can we know ??if this is a new menu being loaded??, so that we can reset the button set flag and restart (flag so it doesnt get set more than once)

		for (auto button : buttons) {

			// button can actually be a dead link due to "remove_button".
			if (button) {

				auto parameters = button->parameters;
				if (parameters.is_visible && (parameters.must_contain == prev_icon_hash || !parameters.must_contain)) {

					// standard icon w/h is 24 pixel's.
					int32_t default_size = 24;
					int32_t width = !icon_mask.second.width() ? default_size : icon_mask.second.width(), height = !icon_mask.second.height() ? default_size : icon_mask.second.height();

					auto icon_data = reinterpret_cast <style::internal::Icon*> (button->icon_data);

					// creating an icon with a pixmap from other icon for current button.
					if (!icon_data) {
						button->icon_data = reinterpret_cast <uintptr_t> (ui::generate_icon(button->icon.data, button->icon.size, _icon->_data, width, height));
						icon_data = reinterpret_cast <style::internal::Icon*> (button->icon_data); // updating link it's now allocated on the heap.
					}

					// little trick for upscaling.
					// since by the default w/h will have a different size on different settings,
					// we actually need to update current icon data.
					// if (width != default_size || height != default_size) {
					//	ui::rescale_icon(icon_data, width, height);
					// }

					// in case of theme update.
					auto icon_parts = &reinterpret_cast <style::internal::Icon*> (button->icon_data)->_data->_parts.front();
					ui::repaint_pixmap(&icon_parts->_pixmap, icon_parts->_color->c.rgb());

					// and finally, generating a button.
					QString text = QString().fromStdWString(parameters.title);
					auto callback = std::function <void()>() = [=]() {

						button->parameters.current_state = !parameters.current_state;

						if (parameters.callback != nullptr) {
							parameters.callback(single <api::c_gui>(), &button->parameters);
						}

					};

					implant_helper(c_action_buttons)->call_original <QAction*> (instance, &text, &callback, button->icon_data);
				}

			}

		}

		// to prevent the collisions..
		if (prev_icon_hash != icon_hash) {
			prev_icon_hash = icon_hash;
		}

		return implant_helper(c_action_buttons)->call_original <QAction*> (instance, _text, _handler, _icon);
	}

#endif

}