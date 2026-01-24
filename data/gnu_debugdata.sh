# Taken from the original MiniDebugInfo documentation found here:
# https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/MiniDebugInfo.html

# Create temporary directory
tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

# Extract the dynamic symbols from the main binary, there is no need
# to also have these in the normal symbol table.
nm --dynamic "$1" --format=posix --defined-only \
  | awk '{ print $1 }' | sort > "$tmpdir/dynsyms"

# Extract all the text (i.e. function) symbols from the debuginfo.
# (Note that we actually also accept "D" symbols, for the benefit
# of platforms like PowerPC64 that use function descriptors.)
nm "$1" --format=posix --defined-only \
  | awk '{ if ($2 == "T" || $2 == "t" || $2 == "D") print $1 }' \
  | sort > "$tmpdir/funcsyms"

# Keep all the function symbols not already in the dynamic symbol
# table.
comm -13 "$tmpdir/dynsyms" "$tmpdir/funcsyms" > "$tmpdir/keep_symbols"

# Separate full debug info into debug binary.
objcopy --only-keep-debug "$1" "$tmpdir/debug"

# Copy the full debuginfo, keeping only a minimal set of symbols and
# removing some unnecessary sections.
objcopy --strip-all --remove-section .gdb_index --remove-section .comment \
  --keep-symbols="$tmpdir/keep_symbols" "$tmpdir/debug" "$tmpdir/mini_debuginfo"

# Copy src to dst and operate on that.
cp "$1" "$2"

# Drop the full debug info from the target binary.
strip --strip-all --remove-section .comment "$2"

# Inject the compressed data into the `.gnu_debugdata` section of the
# target binary.
xz "$tmpdir/mini_debuginfo"
objcopy --add-section .gnu_debugdata="$tmpdir/mini_debuginfo.xz" "$2"
