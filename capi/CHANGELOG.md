Unreleased
----------
- Added constructs for forward & backward compatibility:
  - Added `type_size` member to input types and `BLAZE_INPUT` macro for
    initialization
  - Reserved trailing padding bytes to ensure zero initialization
- Added `blaze_normalizer_new_opts` function and `blaze_normalizer_opts`
  type
- Renamed various symbolization functions to closer reflect Rust
  terminology
- Renamed `BLAZE_SYM_UNKNOWN` enum variant to `BLAZE_SYM_UNDEF`
- Added `perf_map` member to `blaze_symbolize_src_process` function
