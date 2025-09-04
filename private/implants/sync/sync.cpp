#include "sync.hpp"
#include <crypto/otrv3.hpp>

namespace private_implant {

	using namespace implant;

	register_implant(c_sync);

#ifdef _WIN64

	// QThread::currentThread.
	QThread* __fastcall c_sync::handler() {

		static std::atomic_bool is_busy = false;

		// QCoreApplicationPrivate::mainThread.
		auto main_thread = single <memory::c_memory_util>()->call <QThread*>(generate_signature_ref("", ""));
		auto current_thread = implant_helper(c_sync)->call_original<QThread*>();
					
		if (current_thread == main_thread) {

			auto worker = get_current_worker();

			if (worker) {

				if (!is_busy.load()) {

					is_busy.store(true);

					if (worker->status == e_unit_status::k_unit_awaiting) {

						worker->unit();
						worker->status = e_unit_status::k_unit_finished;
						update_worker();

					}

					is_busy.store(false, std::memory_order_release);
					is_busy.notify_all();

				}

			} else {
				setup_worker();
			}

		}

		return current_thread;
	}

#endif

}