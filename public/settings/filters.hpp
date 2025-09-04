#pragma once

#include <vendor.h>
#include <singleton.hpp>

#include <map>
#include <t_helpers/peer.hpp>

namespace settings {

	// todo: support different kind receive messages.
	//       e.g images, stickers, gifs, docu, etc.
	class c_filters : c_singleton <c_filters> {

	public:

		void on_receive(QString source, QString to, uint64_t user_id = 0);
		void on_send(QString from, QString to, uint64_t user_id = 0);

	protected:

		struct filter_options_t {

			QString source, exchange;
			uint64_t target;

		};

		static inline auto get_recv_config() {
			return &m_recv;
		}

		static inline auto get_send_config() {
			return &m_send;
		}

	private:

		static std::vector <filter_options_t> m_recv;
		static std::vector <filter_options_t> m_send;

	};

}