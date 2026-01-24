# taken from the original MiniDebugInfo documentation found here:
# https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/MiniDebugInfo.html

# Extract the dynamic symbols from the main binary, there is no need
# to also have these in the normal symbol table.
nm -D $1 --format=posix --defined-only \
  | awk '{ print $1 }' | sort > dynsyms

# Extract all the text (i.e. function) symbols from the debuginfo.
# (Note that we actually also accept "D" symbols, for the benefit
# of platforms like PowerPC64 that use function descriptors.)
nm $1 --format=posix --defined-only \
  | awk '{ if ($2 == "T" || $2 == "t" || $2 == "D") print $1 }' \
  | sort > funcsyms

# Keep all the function symbols not already in the dynamic symbol
# table.
comm -13 dynsyms funcsyms > keep_symbols

# Separate full debug info into debug binary.
objcopy --only-keep-debug $1 debug

# Copy the full debuginfo, keeping only a minimal set of symbols and
# removing some unnecessary sections.
objcopy -S --remove-section .gdb_index --remove-section .comment \
  --keep-symbols=keep_symbols debug mini_debuginfo

# cp src to dst and operate on that
cp $1 $2

# Drop the full debug info from the original binary.
strip --strip-all -R .comment $2

# Inject the compressed data into the .gnu_debugdata section of the
# original binary.
xz mini_debuginfo
objcopy --add-section .gnu_debugdata=mini_debuginfo.xz $2

# Clean up temporary files.
rm dynsyms funcsyms keep_symbols debug mini_debuginfo.xz
