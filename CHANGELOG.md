Unreleased
----------
- Added `extern "C"` guards in `blazesym.h` header for easy of use from C++ code
- Added unused member variable to `blaze_user_addr_meta_unknown` type for
  compliance with C standard, stating undefined behavior for empty structs


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
