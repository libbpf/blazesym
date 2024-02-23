0.2.0-alpha.11
--------------
- Added support for Breakpad format behind `breakpad` feature (disabled
  by default)
- Added support for usage of perf map files as part of process symbolization
  - Added `perf_map` attribute to `symbolize::Process` type
- Added `map_files` attribute to `symbolize::Process` type
- Added support for symbolizing addresses mapping to ELF variables and
  for looking them up using `inspect` APIs
- Added support for GNU indirect functions to ELF logic
- Overhauled `SymType` enum
  - Made it non-exhaustive
  - Moved it out of `inspect` module
  - Renamed `Unknown` variant to `Undefined`
- Made auto reloading of symbolization sources on change configurable
- Fixed DWARF symbolization in the presence of cross compilation unit
  references


0.2.0-alpha.10
--------------
- Introduced `symbolize::Reason` enum to provide best guess at why symbolization
  was not successful as part of the `symbolize::Symbolized::Unknown` variant
- Introduced `apk` and `gsym` compile-time features (disabled by default)
- Improved handling of dynamic ELF symbols for symbolization and inspection
- Fixed Gsym symbolization issue for "large" addresses
- Reordered `pid` argument to normalization functions before addresses
- Reordered `src` argument to inspection functions before names


0.2.0-alpha.9
-------------
- Added caching logic for Gsym resolvers to `symbolize::Symbolizer`
- Adjusted various symbolization related types to contain `Cow` objects to
  facilitate hand out of memory mapped data without unnecessary allocations
  - Adjusted various symbolization code paths to stop heap-allocating
- Adjusted normalization logic to honor executable and readable proc maps
  entries
- Changed `debug_syms` to be a symbolization source property instead of a
  `symbolize::Symbolizer` attribute
- Renamed `inspect::Elf::debug_info` to `debug_syms`
- Handled potential numeric overflow in Gsym inlined function parser more
  gracefully
- Moved C API definitions into `blazesym-c` crate
- Fixed build for some Android flavors


0.2.0-alpha.8
-------------
- Fixed build failure when `dwarf` feature is not enabled
- Changed `Addr` to map to 64 bit integer
- Reworked normalization APIs to produce file offsets instead of virtual offsets
- Introduced `symbolize::Input` enum and made it part of symbolization APIs to
  distinguish between and support different input types
  - Added support for ELF symbolization using file offsets instead of addresses
- Added `symbolize::Source::Apk` variant
- Made symbolization source caching unconditional and removed
  least-recently-used semantics in favor of full user control
- Added caching for APK related symbolization data structures
- Added caching logic to `inspect::Inspector`
- Adjusted `inspect::SymInfo` type to optionally just reference cached
  data as opposed to having to heap-allocate copies of it
- Added support for iterating over all symbols in a source to
  `inspect::Inspector`
- Made `inspect::SymInfo::file_offset` member optional
- Added ability to contain backtraces in `Error` objects
- Added support for symbolizing Gsym addresses to `blazecli`
- Fixed bogus inlined function reporting for Gsym
- Bumped minimum supported Rust version to `1.65`


0.2.0-alpha.7
-------------
- "Flattened" return type of `symbolize::Symbolizer::symbolize` method from
  nested `Vec` to a single level `Vec` of newly introduced
  `symbolize::Symbolized` enum
- Further changes to `symbolize::Sym`:
  - Added `size` member and `to_path` helper method
  - Factored out `CodeInfo` type capturing all source code location information
  - Included optional inlined function information via `inlined` attribute
- Added support for reporting inlined functions for DWARF and Gsym formats
- Introduced `symbolize::Symbolizer::symbolize_single` for more convenient
  symbolization of a single address
- Introduced `normalize::Builder` type for customization of a
  `normalize::Normalizer` instance and made reading of build IDs
  configurable
- Adjusted ELF symbolization code to honor symbol sizes
- Renamed `symbolize::Builder::enable_src_location` to `enable_code_info`
- Bumped minimum supported Rust version to `1.64`


0.2.0-alpha.6
-------------
- Fixed potential panic when normalizing an APK ELF file using the C APIs


0.2.0-alpha.5
-------------
- Fixed potentially incorrect reporting of symbols from ELF source


0.2.0-alpha.4
-------------
- Added support for automatic demangling of symbols, controlled by
  `demangle` feature (at compile time) and corresponding flag in
  `symbolize::Builder` (at runtime)
- Renamed `symbolize::SymbolizedResult` to `Sym` and reworked it
  - Made it non-exhaustive
  - Renamed `symbol` member to `name`
  - Added `offset` member
  - Changed `line` member to be of type `u32` and `column` to `u16`
  - Made all source code location information optional
  - Split `path` member into `dir` and `file`
- Added additional end-to-end benchmarks
  - Added benchmark result summary to CI runs
- Fixed spurious maps file path creation for low addresses as part of
  normalization/symbolization
- Improved symbolization of addresses in ELF files with potentially
  bogus symbol sizes
- Introduced `blazecli` command line interface for the library
- Introduced `helper` module exposing `read_elf_build_id` function


0.2.0-alpha.3
-------------
- Introduced custom `Error` type instead of relying solely on
  `std::io::Error`
- Switched to using `gimli` for DWARF support
  - Added support for DWARF versions v2, v3, and v5 for symbol lookup and source
    code information retrieval
  - Introduced `dwarf` feature to make dependency optional
- Switched from `log` to using `tracing` as the logging backend
  - Added spans to a couple of relevant call sites
- Added support for using DWARF information for symbol lookup (instead of just
  ELF symbols; so far DWARF was only used for mapping names to symbol
  information)
- Added support for normalizing and symbolizing addresses in an ELF file
  contained in an APK
- Adjusted `symbolize::Source::Gsym` variant to support symbolizing Gsym from
  user provided "raw" data
- Renamed `normalize::UserAddrMeta::Binary` variant to `Elf`
- Renamed `blaze_user_addr_meta_unknown::__unused` member to `_unused`


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
