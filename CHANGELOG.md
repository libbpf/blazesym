0.2.0-alpha.2
-------------
- Added `extern "C"` guards in `blazesym.h` header for easy of use from C++ code
- Added unused member variable to `blaze_user_addr_meta_unknown` type for
  compliance with C standard, stating undefined behavior for empty structs
- Changed `blaze_inspect_elf_src::path` type to `*const _`
- Fixed incorrect `NULL` checks when working with `blaze_symbolize_src_kernel`
  objects
- Switched away from using Git LFS for large benchmark files towards
  on-demand downloading from a different repository, controlled by
  `generate-bench-files` feature


0.2.0-alpha.1
-------------
- Removed no longer necessary `base_address` member from various types
- Renamed `SymInfo::address` member to `addr`
- Fixed incorrect allocation size calculation in C API
- Fixed file offset lookup potentially reporting subtly wrong offsets on
  certain ELF file segment constellations


0.2.0-alpha.0
-------------
- Initial documented release
