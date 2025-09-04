#pragma once

#include <vendor.h>

#include <atomic>
#include <mutex>
#include <utility>

// thread-safe singleton to avoid crt order race.
// https://en.cppreference.com/w/cpp/language/siof.
// 
// credits:
// https://github.com/jimmy-park/singleton/blob/main/include/singleton_atomic.hpp.
template <typename T>
class c_singleton {

public:

	template <typename... Args>
	inline static T* get_instance(Args&&... args) {

		using instance_type = T;

		if (!m_instance.load(std::memory_order_acquire)) {

			std::unique_lock lock { m_mutex };
			if (!m_instance.load(std::memory_order_relaxed)) {

				m_instance.store(new instance_type{ std::forward <Args>(args)... }, std::memory_order_release);
				lock.unlock();
				m_instance.notify_all();

			}

		}

		m_instance.wait(nullptr, std::memory_order_acquire);
		return m_instance.load(std::memory_order_relaxed);
	}

protected:

	c_singleton() = default;
	c_singleton(const c_singleton&) = delete;
	c_singleton(c_singleton&&) = delete;
	c_singleton& operator=(const c_singleton&) = delete;
	c_singleton& operator=(c_singleton&&) = delete;
	~c_singleton() = default;

private:

	struct deconstructor_t {

		std::atomic <T*> instance = { nullptr };

		~deconstructor_t() noexcept(noexcept(std::declval<T>().~T())) {
			delete instance.load(std::memory_order_acquire);
		}

	};

	inline static deconstructor_t m_deconstructor;
	inline static auto& m_instance { m_deconstructor.instance };
	inline static std::mutex m_mutex;

};

template <typename T>
inline static T* single() {
	return c_singleton <T>::get_instance();
};

template <typename T, typename... Args>
inline static T* single(Args&&... args) {
	return c_singleton <T>::get_instance(std::forward <Args> (args)...);
};