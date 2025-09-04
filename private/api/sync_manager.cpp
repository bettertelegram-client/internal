#include <api/sync_manager.hpp>

namespace api {

	std::set <c_sync_manager::worker_t* > c_sync_manager::m_stack = {};
	std::atomic <c_sync_manager::worker_t*> c_sync_manager::m_worker = { nullptr };

	void c_sync_manager::execute(std::function <void()> executor) {

		m_stack.emplace(

			// will be erased on update event, or remove/wait event's (last is optional)
			new worker_t {
				.id = 0,
				.unit = executor,
			}

		);

		update_worker();
	}

	void c_sync_manager::push(std::string name, std::function <void()> executor) {

		auto id = hash::fnv1a64_rt(name.c_str(), name.length());

		m_stack.emplace(

			// will be erased on update event, or remove/wait event's (last is optional)
			new worker_t {
				.id = id,
				.unit = executor,
			}

		);

		update_worker();
	}

	void c_sync_manager::remove(std::string name) {

		auto id = hash::fnv1a64_rt(name.c_str(), name.length());

		for (auto element : m_stack) {

			// removing only a finished one unit.
			if (element->id == id && element->status == e_unit_status::k_unit_finished) {

				m_stack.erase(element);
				delete element;

				return;
			}

		}

	}

	void c_sync_manager::wait(std::string name, bool delete_after) {

		auto id = hash::fnv1a64_rt(name.c_str(), name.length());

		// wait's until executor with target id will be pushed in stack.
		// (if there is a necessary to do it, e.g multi-thread wait)
		do {

			for (auto element : m_stack) {

				if (element->id == id && element->status == e_unit_status::k_unit_finished) {

					// removing element from stack and memory.
					if (delete_after) {
						m_stack.erase(element);
						delete element;
					}

					return;
				}

			}

			_mm_pause();

		} while (true);

	}

}