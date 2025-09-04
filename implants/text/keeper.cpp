#include "keeper.hpp"

namespace implant {

	register_implant(c_keeper);

#ifdef _WIN64

	// compiler-generated chunk.
	// part of Api::Updates::applyUpdateNoPtsCheck.
	// used to find by constant 0xA20DB0E5.
	void __fastcall c_keeper::handler(uintptr_t, uintptr_t, uintptr_t, uintptr_t) {
		return; // yup, we don't need anything else.
	}

#endif

}