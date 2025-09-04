#include "limits.hpp"
#include <output.hpp>

namespace implant {

	register_implant(c_limits);
	register_implant(c_limits_observe)

#ifdef _WIN64

	// Main::Domain::maxAccounts.
	uint64_t __fastcall c_limits::handler(Main::Domain* instance) {
		return 1024;
	}

	// Main::_anonymous_namespace_::ComposeDataString.
	QString* __fastcall c_limits_observe::handler(QString* result, QString* data, int index) {
		*result = implant_helper(c_limits_observe)->call_original <QString*>(result, data, index)->replace('#', '$');
		return result;
	}

#endif

}