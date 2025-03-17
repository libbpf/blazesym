Unreleased
----------
- Introduced `blaze_trace` function for tapping into the library's
  tracing functionality
- Added `apk_to_elf` attribute to `blaze_normalize_opts`
- Added `size` and `module` attributes to `blaze_sym` type
- Changed `size` attribute of `blaze_sym_info` to be signed
- Changed `blaze_user_meta_kind` to be represented as `uint8_t`
- Renamed `kernel_image` member of `blaze_symbolize_src_kernel` to
  `vmlinux`
- Renamed `obj_file_name` member of `blaze_sym_info` to `module`
- Renamed `map_files` member of `blaze_symbolize_src_process` to
  `no_map_files` and inverted its meaning
- Added support for disabling `kallsyms` and `vmlinux` to
  `blaze_symbolize_src_kernel`
- Added `blaze_symbolize_cache_elf` for caching of ELF data
- Added `blaze_symbolize_cache_process` for caching of process VMA
  metadata


0.1.0-rc.2
----------
- Fixed various functions accepting `uintptr_t` addresses, when they
  really should be using `uint64_t`
- Introduced `blaze_read_elf_build_id` helper
- Bumped `blazesym` dependency to `0.2.0-rc.2`


0.1.0-rc.1
----------
- Added `procmap_query_ioctl` attribute to `blaze_normalizer_opts`
- Renamed `blaze_result` to `blaze_syms`
  - Renamed `blaze_result_free` to `blaze_syms_free`
- Renamed `cache_maps` attribute of `blaze_normalizer_opts` to
  `cache_vmas`
- Introduced `blaze_supports_procmap_query` helper
- Bumped `blazesym` dependency to `0.2.0-rc.1`


0.1.0-rc.0
----------
- Added `debug_dirs` attribute to `blaze_symbolizer_opts`
- Added `cache_maps` attribute to `blaze_normalizer_opts`
- Introduced `blaze_err` enum and adjusted all fallible functions to
  set a thread local error
  - Introduced `blaze_err_last` to retrieve the last error
  - Introduced `blaze_err_str` function to convert errors to textual
    representation
- Introduced `blaze_normalize_opts` and added
  `blaze_normalize_user_addrs_opts` to use it
  - Removed `blaze_normalize_user_addrs_sorted` function
- Introduced `blaze_normalize_reason` type
  - Added `reason` attribute to `blaze_user_meta_unknown`
  - Added `blaze_normalize_reason_str` to retrieve textual representation
- Introduced `blaze_symbolize_reason` type
  - Added `reason` attribute to `blaze_sym`
  - Added `blaze_symbolize_reason_str` to retrieve textual representation
- Added `blaze_symbolize_elf_file_offsets` function for symbolization of
  file offsets
- Added support for transparently working with input data not in accordance with
  Rust's alignment requirements
- Removed `BLAZE_INPUT` macro
- Bumped `blazesym` dependency to `0.2.0-rc.0`


0.1.0-alpha.1
-------------
- Included `blazesym.h` header file in release package


0.1.0-alpha.0
-------------
- Added constructs for forward & backward compatibility:
  - Added `type_size` member to input types and `BLAZE_INPUT` macro for
    initialization
  - Reserved trailing padding bytes to ensure zero initialization
  - Reserved space for future extension in output types
- Added `blaze_normalizer_new_opts` function and `blaze_normalizer_opts` type
- Added `auto_reload` attribute to `blaze_symbolizer_opts`
- Renamed various symbolization functions to closer reflect Rust terminology
- Renamed `BLAZE_SYM_UNKNOWN` enum variant to `BLAZE_SYM_UNDEF`
- Added `perf_map` and `map_files` members to `blaze_symbolize_src_process` type


blazesym-0.2.0-alpha.8
----------------------
- Latest `blazesym` release containing C API bindings
  - Moving forward these bindings will be versioned and published separately
    from the `blazesym` Rust library
