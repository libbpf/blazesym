Unreleased
----------
- Added constructs for forward & backward compatibility:
  - Added `type_size` member to input types and `BLAZE_INPUT` macro for
    initialization
  - Reserved trailing padding bytes to ensure zero initialization
  - Reserved space for future extension in output types
- Added `blaze_normalizer_new_opts` function and `blaze_normalizer_opts`
  type
- Added `auto_reload` attribute to `blaze_symbolizer_opts`
- Renamed various symbolization functions to closer reflect Rust
  terminology
- Renamed `BLAZE_SYM_UNKNOWN` enum variant to `BLAZE_SYM_UNDEF`
- Added `perf_map` and `map_files` members to
  `blaze_symbolize_src_process` type
