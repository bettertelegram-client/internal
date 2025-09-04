#pragma once

#include <implant/helpers.hpp>
#include <t_helpers/accounts.hpp>
#include <os/util.hpp>

namespace implant {

	// used at iteration when loading accounts.
	constexpr uint8_t k_max_accounts = 127;

	//
	// brief: up accounts count limit from 5 to $MAX_ACCOUNTS_COUNT$.
	// note: implants will work only if user created account using module.
	//

	class c_limits : public c_implant {

	public:

#ifdef _WIN64
		
		c_limits() : c_implant(generate_signature_ref("", "")) {
			apply_patches();
		}

		implant_make_preset("tg_limits", uint64_t __fastcall, handler, Main::Domain*);
#endif

	private:

		void on_construct(api::c_gui* ui) override {

			using namespace api;
			using namespace telegram;

			// buttons.
			auto refresher = ui->create_button("reload_accs", icons::e_registered_icons::k_reload, telegram::ui::k_edit_profile);

			refresher->title = L"Reload accounts";
			refresher->must_contain = telegram::ui::k_add_account;
			refresher->toggler_present = false;
			refresher->separator_present = true;

			// load as much accounts as we can to the current app.
			refresher->callback = [](c_gui* instance, c_gui::button_options_t* options) {

				for (size_t account_it = accounts::get_active_count(); account_it < k_max_accounts; account_it++) {

					if (accounts::is_exist(account_it)) {
						accounts::load(account_it);
					}

				}

			};

		}

		void apply_patches() {

			auto memory = single <telegram::memory::c_memory_util> ();

#ifdef _WIN64

			// Main::Domain::add.
			// 
			// .text:0000000141A042B0             sub     rax, rcx
			// .text:0000000141A042B3             sar     rax, 4                < nops.
			// .text:0000000141A042B7             cmp     rax, 6
			// .text:0000000141A042BB             jnb     loc_141A044B4
			//
			// patch length: 17.
			os::write_execute <uint8_t, 17> (memory->search(generate_signature("", "")), 0x90);
			
			// AccountsList::setupAdd.
			//
			// .text:0000000141E94174             jb      short loc_141E941E7
			//                                    ^
			//                                     > from conditional jump to direct jump.
			//
			// patch length: 1.
			os::write_execute <uint8_t> (memory->search(generate_signature("", "")), 0xEB);

			// Domain::startModern.
			//
			// .text:0000000141FEBD71             lea     eax, [rcx-1]
			// .text:0000000141FEBD74             cmp     eax, 5           < nops.
			// .text:0000000141FEBD77             ja      loc_141FEC1B5
			//
			// patch length: 12.
			os::write_execute <uint8_t, 12> (memory->search(generate_signature("", "")), 0x90);

			// AccountList::rebuild.
			//
			// .text:0000000141E94B9E             cmp     ebx, 6
			//                                                 ^ -> to 0x7F, which allow us to have about 127 accounts. 
			//                                                   (signed char)
			// patch length: 1.
			os::write_execute(memory->search(generate_signature_ex("", "", 2, false)), k_max_accounts);

			// !important!
			// this simple patch is protecting user against crash'es after adding too many accounts via module.
			//
			// Domain::writeAccounts.
			// 
			// .text:0000000141FEC410             mov     [rsp-8+arg_8], rbx
			//                                                 ^ -> ret.
			// patch length: 1.
			os::write_execute(memory->search(generate_signature_ref("", "")), 0xC3);

#endif

		}

	};



	// 
	// brief: when telegram loads up an account, it's firstly creates 'Main::Account' constructor,
	//        which calls to function 'ComposeDataString' to build up account folder name like 'user_data#id'.
	//
	//        problem with bypassing limit on telegram accounts, is it leads to crash when telegram is in attempt to bootstrap.
	//        mine solution is really simple: change '#' to '$' in ComposeDataString.
	//
	//        so, it will load accounts only when module will be loaded into telegram memory without leading crash to the application.
	// 
	//        p.s only in case if target accounts was added when this implant was enabled.
	//

	class c_limits_observe : public c_implant {

	public:

#ifdef _WIN64
		c_limits_observe() : c_implant(generate_signature_ref("", "")) {};
		implant_make_preset("tg_limits_observe", QString* __fastcall, handler, QString*, QString*, int);
#endif

	};

}