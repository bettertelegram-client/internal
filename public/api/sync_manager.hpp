#pragma once

#include <vendor.h>
#include <hash.hpp>

#include <set>
#include <mutex>
#include <functional>

namespace api {

	class c_sync_manager {

	public:

		// add function with an empty identification to the queue. (auto-clean)
		//
		// note:
		// functions without any of the identificators will be just erased by self after execution.
		void execute(std::function <void()> executor);

		// add function with unique id to the execution queue.
		//
		// note:
		// function with identificators must be erased with "remove/wait" functions.
		// otherwise futher updating of the queue will not be possible.
		void push(std::string name, std::function <void()> executor);

		// remove function from the queue.
		// note: you must be sure that request is already executed, otherwise it's gonna just spend a cpu cycles for nothing.
		void remove(std::string name);

		// wait for the function which will be executed in queue.
		// note: if function is not presented in the queue, we're gonna wait until it's gonna be push'ed.
		void wait(std::string name, bool delete_after = false);

	protected:

		// internals.
		// do not touch.
		enum class e_unit_status {

			k_unit_awaiting = 0,
			k_unit_finished

		};

		struct worker_t {

			uint64_t id;
			std::function <void()> unit;

			e_unit_status status = e_unit_status::k_unit_awaiting;

		};

		static inline void setup_worker() {

			if (!m_stack.empty()) {

				auto worker = m_worker.load(std::memory_order_relaxed);

				if (!worker) {

					auto stack_worker = *m_stack.begin();

					if (stack_worker && stack_worker->status == e_unit_status::k_unit_awaiting) {
						m_worker.store(stack_worker);
					}

				}

			}

		}

		// must be called on thread update event.
		static void update_worker() {

			// check if it's even contains something.
			if (!m_stack.empty()) {

				// since we're in lock, can access with relax.
				auto worker = m_worker.load(std::memory_order_relaxed);

				// if there is any worker?
				if (worker != nullptr) {

					// must be changed by caller.
					if (worker->status == e_unit_status::k_unit_finished) {

						// resolving the next worker by finding what comes after it.
						auto new_it = std::next(m_stack.find(worker), 1);

						// first of first, let's try to remove current worker from stack.
						//
						// it is linked to somebody?
						if (!worker->id) {

							// nope, we can clean it by ourselfs.
							// note: otherwise you must clean it by youself using ID that you gave to worker.
							m_stack.erase(worker);

							// freeing it from the memory.
							delete worker;
						}

						// if there any value?
						if (new_it != m_stack.end()) {
							m_worker.store(*new_it);
						} else {
							m_worker.store(nullptr); // really can't do anything.
						}

					}

				}


			}

		}

		static inline worker_t* get_current_worker() {
			return m_worker.load();
		}

	private:

		 static std::set <worker_t*> m_stack;
		 static std::atomic <worker_t*> m_worker;

	};

}