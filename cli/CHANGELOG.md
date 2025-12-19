Unreleased
----------
- Improved backtrace reporting when requested via `RUST_BACKTRACE` or
  `RUST_LIB_BACKTRACE` environment variables


0.1.12
------
- Bumped `blazesym` dependency to `0.2.0`


0.1.11
------
- Bumped `blazesym` dependency to `0.2.0-rc.5`


0.1.10
------
- Bumped `blazesym` dependency to `0.2.0-rc.4`


0.1.9
-----
- Added `--debug-dirs` and `--no-debug-syms` options to `symbolize
  process` sub-command
- Added `--no-debug-syms` option to `inspect dump elf` sub-command
- Added `--kallsyms` and `--vmlinux` options to `symbolize kernel`
  sub-command
- Fixed truncation of overly long tracing lines
- Bumped `blazesym` dependency to `0.2.0-rc.3`


0.1.8
-----
- Significantly shortened tracing output when enabled (via `-v`)


0.1.7
-----
- Added support for symbolization of kernel addresses
- Added `--map-files` option to `normalize user` sub-command
- Bumped `blazesym` dependency to `0.2.0-rc.2`


0.1.6
-----
- Added `--procmap-query` option to `normalize user` sub-command
- Bumped `blazesym` dependency to `0.2.0-rc.1`


0.1.5
-----
- Added `--debug-dirs` option to `symbolize elf` sub-command
- Bumped `blazesym` dependency to `0.2.0-rc.0`


0.1.4
-----
- Added `inspect` command
- Bumped `blazesym` dependency to `0.2.0-alpha.12`


0.1.3
-----
- Added support for symbolization using Breakpad (`*.sym`) files
- Added `--no-debug-syms` option to `symbolize elf` sub-command
- Added `--no-build-ids` option to `normalize user` sub-command
- Bumped `blazesym` dependency to `0.2.0-alpha.11`


0.1.2
-----
- Bumped `blazesym` dependency to `0.2.0-alpha.10`


0.1.1
-----
- Fixed process symbolization erring out with wrong input type message


0.1.0
-----
- Initial release
