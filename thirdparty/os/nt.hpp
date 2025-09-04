#pragma once

#include <vendor.h>

namespace os::nt {

	static uint16_t k_dos_signature = 0x5A4D, k_nt_signature = 0x4550;
	static uint16_t k_optional_hdr32 = 0x10B, k_optional_hdr64 = 0x20B;

	enum e_directory_type {

		k_dir_export = 0,
		k_dir_import = 1,
		k_dir_resource = 2,
		k_dir_exception	= 3,
		k_dir_security = 4,
		k_dir_relocs = 5,
		k_dir_debug	= 6,
		k_dir_arch = 7,
		k_dir_globalptr	= 8,
		k_dir_tls = 9,
		k_dir_load_config = 10,
		k_dir_bound_import = 11,
		k_dir_iat = 12,
		k_dir_delay_import = 13,
		k_dir_com_desc = 14,
		k_dir_entries = 16

	};

	#define nt_reloc_offset(x) (x & 0xFFF)
	enum e_reloc_type {

		k_reloc_abs = 0,
		k_reloc_high = 1,
		k_reloc_low = 2,
		k_reloc_highlow = 3,
		k_reloc_highadj = 4,
		k_reloc_specific_5 = 5,
		k_reloc_reserved = 6,
		k_reloc_specific_7 = 7,
		k_reloc_specific_8 = 8,
		k_reloc_specific_9 = 9,
		k_reloc_dir64 = 10

	};

	typedef struct {

		uint16_t machine, number_of_sections;
		uint32_t time_stamp;
		uint32_t symbol_table, number_of_symbols;
		uint16_t optional_head_sz, characts;

	} image_file_head_t;

	typedef struct {

		uint8_t name[8];

		union {

			uint32_t physical;
			uint32_t size;

		} misc;

		uint32_t va;
		uint32_t raw_size, raw_data;
		uint32_t relocs_data;
		uint32_t linenumbers;
		uint16_t relocs_cnt;
		uint16_t linenumbers_cnt;
		uint32_t characts;

	} image_section_head_t;

	typedef struct {

		uint32_t va, size;

	} image_data_dir_t;

	typedef struct {

		uint16_t	magic;
		uint8_t     major_linker_ver;
		uint8_t     minor_linker_ver;
		uint32_t    size_of_code;
		uint32_t    size_of_init_data;
		uint32_t    size_of_uninit_data;
		uint32_t    entry_point;
		uint32_t    base_of_code;
		uint64_t    image_base;
		uint32_t    section_align;
		uint32_t    file_align;
		uint16_t    major_os_ver;
		uint16_t    minor_os_ver;
		uint16_t    major_image_ver;
		uint16_t    minor_image_ver;
		uint16_t    major_subsystem_ver;
		uint16_t    minor_subsystem_ver;
		uint32_t    win32_ver;
		uint32_t    size_of_image;
		uint32_t    size_of_headers;
		uint32_t    checksum;
		uint16_t    subsystem;
		uint16_t    dll_characts;
		uint64_t    size_of_stack_reserve;
		uint64_t    size_of_stack_commit;
		uint64_t    size_of_heap_reserve;
		uint64_t    size_of_heap_commit;
		uint32_t    loader_flags;
		uint32_t    number_of_rva_and_sizes;

		image_data_dir_t data_directory[k_dir_entries];

	} image_optional_head_t;

	typedef struct {

		uint16_t magic;
		uint16_t last_page_bytes;
		uint16_t pages_cnt;
		uint16_t relocs;
		uint16_t header_sz;
		uint16_t min_alloc;
		uint16_t max_alloc;
		uint16_t ss;
		uint16_t sp;
		uint16_t checksum;
		uint16_t ip;
		uint16_t cs;
		uint16_t lfarlc;
		uint16_t overlays;
		uint16_t reserved[4];
		uint16_t oem_id;
		uint16_t oem_info;
		uint16_t reserved2[10];
		int32_t  lfanew;

	} image_dos_head_t;

	typedef struct {

		uint32_t characts;
		uint32_t time_stamp_date;
		uint16_t major_ver;
		uint16_t minor_ver;
		uint32_t name;
		uint32_t base;
		uint32_t funcs_num;
		uint32_t names_num;
		uint32_t funcs_addr;
		uint32_t names_addr;
		uint32_t ordinals_addr;

	} image_export_dir_t;

	typedef struct {

		union {

			uint32_t characts;
			uint32_t original;

		} thunk;

		uint32_t time_date_stamp;
		uint32_t chain;
		uint32_t name;
		uint32_t first_thunk;

	} image_import_desc_t;

	typedef struct {

		union {

			uint64_t forwarder_string;
			uint64_t function;
			uint64_t ordinal;
			uint64_t address_of_data;

		} u1;

	} image_thunk_data_t;

	typedef struct {

		uint16_t	hint;
		char		name[1];

	} image_import_name_t;

	typedef struct {

		uint32_t				signature;
		image_file_head_t		file;
		image_optional_head_t	optional;

	} image_headers_t;

	typedef struct {
		uint32_t va, size;
	} image_base_reloc_t;

	template <typename T>
	static inline auto get_nt_headers(T base) {
		auto dos = reinterpret_cast <image_dos_head_t*> (base);
		return reinterpret_cast <image_headers_t*> (base + dos->lfanew);
	}

	template <typename T>
	static inline auto get_first_section(T base) {
		auto head = get_nt_headers(base);
		return reinterpret_cast <image_section_head_t*> ((reinterpret_cast <uintptr_t> (head) + offsetof(image_headers_t, optional) + (head)->file.optional_head_sz));
	}

	template <typename T>
	static inline uint8_t* get_export(T base, const char* name) {

		// since this function is used more often, there is more sense to make it type-undepend.
		auto ptr = reinterpret_cast <uintptr_t> (base);

		auto exports = reinterpret_cast <image_export_dir_t*> (ptr + get_nt_headers(ptr)->optional.data_directory[k_dir_export].va);
		auto names = reinterpret_cast <uint32_t*> (ptr + exports->names_addr);

		for (uint64_t idx = 0; idx < exports->names_num; ++idx) {

			auto symbol = reinterpret_cast <const char*> (ptr + names[idx]);

			if (!strcmp(symbol, name)) {

				auto rva = reinterpret_cast <uint32_t*> (ptr + exports->funcs_addr);
				auto ordinal = reinterpret_cast <uint16_t*> (ptr + exports->ordinals_addr);

				return reinterpret_cast <uint8_t*> (ptr + rva[ordinal[idx]]);
			}

		}

		return 0;
	}

}