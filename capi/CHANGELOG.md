Unreleased
----------
- Added `cache_maps` attribute to `blaze_normalizer_opts`
- Introduced `blaze_err` enum and adjusted all fallible functions to
  set a thread local error
  - Introduced `blaze_err_last` to retrieve the last error
  - Introduced `blaze_err_str` function to convert errors to textual
    representation
- Introduced `blaze_normalize_reason` type and extended
  - Added `reason` attribute to `blaze_user_meta_unknown`
- Added `blaze_symbolize_elf_file_offsets` function for symbolization of
  file offsets
- Removed `BLAZE_INPUT` macro
- Bumped `blazesym` dependency to `0.2.0-alpha.12`


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
