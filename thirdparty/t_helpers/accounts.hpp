#pragma once

#include <vendor.h>

#include <storage/storage_domain.h>
#include <storage/storage_account.h>
#include <mtproto/mtproto_config.h>

#include "util.hpp"
#include "memory.hpp"

// todo: create account right from tdata on click?
namespace telegram::accounts {

	bool is_exist(uint32_t index) {

		// buffer will be erased/re-used at the exit.
		std::array <uint8_t, sizeof(Main::Account)> temp_buffer = { 0 };

		auto domain = get_instance()->_domain->_local.get();

#ifdef _WIN64
		// Main::Account::Account. (constructor)
		single <memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), temp_buffer.data(), domain->_owner, domain->_dataName, index);
#endif

		// let's use wide since there can be cyrillic and other letters.
		return std::filesystem::exists(reinterpret_cast <Main::Account*> (temp_buffer.data())->_local.get()->_basePath.toStdWString());
	}

	// use function 'is_exist' before 'load' to be sure that account will be loaded.
	void load(uint32_t index) {

		// NOTE: all of the allocations is not getting free'd on purpose.
		//       thing is, pointer is being used even after processed in the application.
		//       so, it's important to keep them alive as long as possible.

		// execution chain: 
		// 1. calling constructor to fill up a member variables.
		// 2. since 'prepareToStart' does not exist -> calling 'Storage::Account::start' natively to fill up a MTProto config,
		//    by decrypting local key.
		// 3. load account to the current application instance using 'Main::Account::start'.
		// 4. and finally let's register account in application using 'Main::Domain::accountAddedInStorage'.
		auto domain = get_instance()->_domain->_local.get();

		auto account = reinterpret_cast <Main::Account*> (new uint8_t[sizeof(Main::Account)]);
		memset(account, 0, sizeof(Main::Account));

#ifdef _WIN64
		// Main::Account::Account. (constructor)
		single <telegram::memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), account, domain->_owner, domain->_dataName, index);
#endif

		auto config = reinterpret_cast <MTP::Config*> (new uint8_t[sizeof(MTP::Config)]);
		memset(config, 0, sizeof(MTP::Config));

#ifdef _WIN64
		// Storage::Account::start.
		single <telegram::memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), account, config, domain->_localKey);
#endif

#ifdef _WIN64
		// Main::Account::start
		single <telegram::memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), account, config);
#endif

		// since we're allocated Main::Account, it's now simplier to provide data without any wrappers.
		auto acc_idx = reinterpret_cast <Main::Domain::AccountWithIndex*> (new uint8_t[sizeof(Main::Domain::AccountWithIndex)]);
		acc_idx->index = index;

		// todo: native pointer may cause UB on delete[] action. (fixme?)
		*reinterpret_cast <uintptr_t*> (&acc_idx->account) = reinterpret_cast <uintptr_t> (account);

#ifdef _WIN64
		// Main::Domain::accountAddedInStorage.
		single <telegram::memory::c_memory_util>()->call <void>(generate_signature_ref("", ""), domain->_owner.get(), acc_idx);
#endif

	}

	size_t get_active_count() {
		return get_instance()->_domain.get()->_accounts.size();
	}

}