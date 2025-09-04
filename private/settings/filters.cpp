#include <settings/filters.hpp>

namespace settings {

	std::vector <c_filters::filter_options_t> c_filters::m_send = {};
	std::vector <c_filters::filter_options_t> c_filters::m_recv = {};

	void c_filters::on_receive(QString source, QString exchange, uint64_t user_id) {

		filter_options_t config;

		config.source = source;
		config.exchange = exchange;
		config.target = user_id;

		m_recv.emplace_back(config);

	}

	void c_filters::on_send(QString from, QString exchange, uint64_t user_id) {

		filter_options_t config;

		config.source = from;
		config.exchange = exchange;
		config.target = user_id;

		m_send.emplace_back(config);

	}

}