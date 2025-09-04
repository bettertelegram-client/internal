#include <api/gui.hpp>

namespace api {

#ifdef _WIN64

	void c_gui::show_box(std::wstring text) {

		using namespace telegram;

		object_ptr <Ui::GenericBox> generic_box = nullptr;

		// QString have internal unicode translate, so, in theory, we must be just fine with unicode text.
		v::text::data string = rpl::single(QString().fromStdWString(text));

		// object_ptr<Ui::GenericBox> *__fastcall Ui::MakeConfirmBox.
		single <memory::c_memory_util>()->call <object_ptr <Ui::GenericBox>*>(generate_signature_ref("", ""), &generic_box, &string);

		// ignoring 'ESC' button.
		generic_box->_closeByEscape = false;

		// simulating header by this way.
		ui::add_separator(generic_box.data()->_content);

		// void __fastcall Ui::Show::showBox.
		single <memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), telegram::get_instance()->_lastActiveWindow->_sessionController->uiShow().get(), &generic_box, uint64_t(2));

	}

	PeerId c_gui::get_active_window() {
		return telegram::get_active_session()->_windows.front()->_activeChatEntry.current().fullId.peer;
	}

#endif

	// this code is basically platform independ.

	// basically, ASCII can be converted to the wide without much performance lost.
	// that's what we're doing.
	void c_gui::show_box(std::string text) {
		this->show_box(std::wstring(text.begin(), text.end()));
	}

	std::vector <c_gui::button_t*> c_gui::m_buttons = {};

	c_gui::button_options_t* c_gui::create_button(const char* name, icons::e_registered_icons icon, telegram::ui::e_icons icon_above_1/*, telegram::ui::e_icons icon_above_2*/) {

		auto button = new button_t(icon, icon_above_1/*, icon_above_2*/, name);

		m_buttons.emplace_back(button);
		return &button->parameters;
	}
	
	bool c_gui::remove_button(const char* name) {

		auto button = this->get_button(name);
		if (!button) return false;

		m_buttons.erase(std::remove(m_buttons.begin(), m_buttons.end(), button), m_buttons.end());
		delete button;

		return true;
	}

	void c_gui::update_button_title(button_options_t* options, std::wstring turn_on, std::wstring turn_off) {
		options->title = options->current_state ? turn_on : turn_off;
	}

	void c_gui::update_button_title(button_options_t* options, std::string turn_on, std::string turn_off) {
		this->update_button_title(options, std::wstring(turn_on.begin(), turn_on.end()), std::wstring(turn_off.begin(), turn_off.end()));
	}

	void c_gui::update_button_title(const char* name, std::wstring turn_on, std::wstring turn_off) {

		auto button = this->get_button(name);

		if (button) {
			this->update_button_title(&button->parameters, turn_on, turn_off);
		}

	}

	void c_gui::update_button_title(const char* name, std::string turn_on, std::string turn_off) {
		this->update_button_title(name, std::wstring(turn_on.begin(), turn_on.end()), std::wstring(turn_off.begin(), turn_off.end()));
	}

	c_gui::button_options_t* c_gui::get_button_options(const char* name) {

		auto button = this->get_button(name);
		if (!button) return nullptr;

		return &button->parameters;
	}

	void c_gui::update_button_options(const char* name, button_options_t* options) {

		auto button = this->get_button(name);

		if (button) {
			button->parameters = *options;
		}

	}

}