#ifndef __blazesym_h_
#define __blazesym_h_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The type of a symbol.
 */
typedef enum blaze_sym_type {
  /**
   * That type could not be determined (possibly because the source does not
   * contains information about the type).
   */
  BLAZE_SYM_UNKNOWN,
  /**
   * The symbol is a function.
   */
  BLAZE_SYM_FUNC,
  /**
   * The symbol is a variable.
   */
  BLAZE_SYM_VAR,
} blaze_sym_type;

/**
 * The valid variant kind in [`blaze_user_addr_meta`].
 */
typedef enum blaze_user_addr_meta_kind {
  /**
   * [`blaze_user_addr_meta_variant::unknown`] is valid.
   */
  BLAZE_USER_ADDR_UNKNOWN,
  /**
   * [`blaze_user_addr_meta_variant::binary`] is valid.
   */
  BLAZE_USER_ADDR_BINARY,
} blaze_user_addr_meta_kind;

/**
 * An inspector of various "sources".
 *
 * Object of this type can be used to perform inspections of supported sources.
 * E.g., using an ELF file as a source, information about a symbol can be
 * inquired based on its name.
 */
typedef struct blaze_inspector blaze_inspector;

/**
 * A normalizer for addresses.
 *
 * Address normalization is the process of taking virtual absolute
 * addresses as they are seen by, say, a process (which include
 * relocation and process specific layout randomizations, among other
 * things) and converting them to "normalized" virtual addresses as
 * they are present in, say, an ELF binary or a DWARF debug info file,
 * and one would be able to see them using tools such as readelf(1).
 */
typedef struct blaze_normalizer blaze_normalizer;

/**
 * Symbolizer provides an interface to symbolize addresses.
 */
typedef struct blaze_symbolizer blaze_symbolizer;

/**
 * Information about a looked up symbol.
 */
typedef struct blaze_sym_info {
  const char *name;
  uintptr_t addr;
  size_t size;
  uint64_t file_offset;
  const char *obj_file_name;
  enum blaze_sym_type sym_type;
} blaze_sym_info;

/**
 * An object representing an ELF inspection source.
 *
 * C ABI compatible version of [`inspect::Elf`].
 */
typedef struct blaze_inspect_elf_src {
  /**
   * The path to the binary. This member is always present.
   */
  const char *path;
  /**
   * Whether or not to consult debug information to satisfy the request (if
   * present).
   */
  bool debug_info;
} blaze_inspect_elf_src;

/**
 * C compatible version of [`Binary`].
 */
typedef struct blaze_user_addr_meta_binary {
  /**
   * The path to the binary. This member is always present.
   */
  char *path;
  /**
   * The length of the build ID, in bytes.
   */
  size_t build_id_len;
  /**
   * The optional build ID of the binary, if found.
   */
  uint8_t *build_id;
} blaze_user_addr_meta_binary;

/**
 * C compatible version of [`Unknown`].
 */
typedef struct blaze_user_addr_meta_unknown {
  uint8_t __unused;
} blaze_user_addr_meta_unknown;

/**
 * The actual variant data in [`blaze_user_addr_meta`].
 */
typedef union blaze_user_addr_meta_variant {
  /**
   * Valid on [`blaze_user_addr_meta_kind::BLAZE_USER_ADDR_BINARY`].
   */
  struct blaze_user_addr_meta_binary binary;
  /**
   * Valid on [`blaze_user_addr_meta_kind::BLAZE_USER_ADDR_UNKNOWN`].
   */
  struct blaze_user_addr_meta_unknown unknown;
} blaze_user_addr_meta_variant;

/**
 * C ABI compatible version of [`UserAddrMeta`].
 */
typedef struct blaze_user_addr_meta {
  /**
   * The variant kind that is present.
   */
  enum blaze_user_addr_meta_kind kind;
  /**
   * The actual variant with its data.
   */
  union blaze_user_addr_meta_variant variant;
} blaze_user_addr_meta;

/**
 * A normalized address along with an index into the associated
 * [`blaze_user_addr_meta`] array (such as
 * [`blaze_normalized_user_addrs::metas`]).
 */
typedef struct blaze_normalized_addr {
  /**
   * The normalized address.
   */
  uintptr_t addr;
  /**
   * The index into the associated [`blaze_user_addr_meta`] array.
   */
  size_t meta_idx;
} blaze_normalized_addr;

/**
 * An object representing normalized user addresses.
 *
 * C ABI compatible version of [`NormalizedUserAddrs`].
 */
typedef struct blaze_normalized_user_addrs {
  /**
   * The number of [`blaze_user_addr_meta`] objects present in `metas`.
   */
  size_t meta_count;
  /**
   * An array of `meta_count` objects.
   */
  struct blaze_user_addr_meta *metas;
  /**
   * The number of [`blaze_normalized_addr`] objects present in `addrs`.
   */
  size_t addr_count;
  /**
   * An array of `addr_count` objects.
   */
  struct blaze_normalized_addr *addrs;
} blaze_normalized_user_addrs;

/**
 * A placeholder symbolizer for C API.
 *
 * It is returned by [`blaze_symbolizer_new`] and should be free by
 * [`blaze_symbolizer_free`].
 */
typedef struct blaze_symbolizer blaze_symbolizer;

/**
 * Options for configuring `blaze_symbolizer` objects.
 */
typedef struct blaze_symbolizer_opts {
  /**
   * Whether to enable usage of debug symbols.
   */
  bool debug_syms;
  /**
   * Whether to attempt to gather source code location information.
   *
   * This setting implies `debug_syms` (and forces it to `true`).
   */
  bool src_location;
} blaze_symbolizer_opts;

/**
 * The result of symbolization of an address.
 *
 * A `blaze_sym` is the information of a symbol found for an
 * address. One address may result in several symbols.
 */
typedef struct blaze_sym {
  /**
   * The symbol name is where the given address should belong to.
   */
  const char *symbol;
  /**
   * The address (i.e.,the first byte) is where the symbol is located.
   *
   * The address is already relocated to the address space of
   * the process.
   */
  uintptr_t addr;
  /**
   * The path of the source file defining the symbol.
   */
  const char *path;
  /**
   * The line number on which the symbol was to be found in the source code.
   */
  size_t line;
  size_t column;
} blaze_sym;

/**
 * `blaze_entry` is the output of symbolization for an address for C API.
 *
 * Every address has an `blaze_entry` in
 * [`blaze_result::entries`] to collect symbols found.
 */
typedef struct blaze_entry {
  /**
   * The number of symbols found for an address.
   */
  size_t size;
  /**
   * All symbols found.
   *
   * `syms` is an array of [`blaze_sym`] in the size `size`.
   */
  const struct blaze_sym *syms;
} blaze_entry;

/**
 * `blaze_result` is the result of symbolization for C API.
 *
 * Instances of [`blaze_result`] are returned by any of the `blaze_symbolize_*`
 * variants. They should be freed by calling [`blaze_result_free`].
 */
typedef struct blaze_result {
  /**
   * The number of addresses being symbolized.
   */
  size_t size;
  /**
   * The entries for addresses.
   *
   * Symbolization occurs based on the order of addresses.
   * Therefore, every address must have an entry here on the same
   * order.
   */
  struct blaze_entry entries[0];
} blaze_result;

/**
 * The parameters to load symbols and debug information from a process.
 *
 * Load all ELF files in a process as the sources of symbols and debug
 * information.
 */
typedef struct blaze_symbolize_src_process {
  /**
   * It is the PID of a process to symbolize.
   *
   * blazesym will parse `/proc/<pid>/maps` and load all the object
   * files.
   */
  uint32_t pid;
} blaze_symbolize_src_process;

/**
 * The parameters to load symbols and debug information from a kernel.
 *
 * Use a kernel image and a snapshot of its kallsyms as a source of symbols and
 * debug information.
 */
typedef struct blaze_symbolize_src_kernel {
  /**
   * The path of a copy of kallsyms.
   *
   * It can be `"/proc/kallsyms"` for the running kernel on the
   * device.  However, you can make copies for later.  In that situation,
   * you should give the path of a copy.
   * Passing a `NULL`, by default, will result in `"/proc/kallsyms"`.
   */
  const char *kallsyms;
  /**
   * The path of a kernel image.
   *
   * The path of a kernel image should be, for instance,
   * `"/boot/vmlinux-xxxx"`.  For a `NULL` value, it will locate the
   * kernel image of the running kernel in `"/boot/"` or
   * `"/usr/lib/debug/boot/"`.
   */
  const char *kernel_image;
} blaze_symbolize_src_kernel;

/**
 * The parameters to load symbols and debug information from an ELF.
 *
 * Describes the path and address of an ELF file loaded in a
 * process.
 */
typedef struct blaze_symbolize_src_elf {
  /**
   * The path to the ELF file.
   *
   * The referenced file may be an executable or shared object. For example,
   * passing "/bin/sh" will load symbols and debug information from `sh` and
   * passing "/lib/libc.so.xxx" will load symbols and debug information from
   * libc.
   */
  const char *path;
} blaze_symbolize_src_elf;

/**
 * The parameters to load symbols and debug information from a gsym file.
 */
typedef struct blaze_symbolize_src_gsym {
  /**
   * The path to a gsym file.
   */
  const char *path;
} blaze_symbolize_src_gsym;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Lookup symbol information in an ELF file.
 *
 * Return an array with the same size as the input names. The caller should
 * free the returned array by calling [`blaze_inspect_syms_free`].
 *
 * Every name in the input name list may have more than one address.
 * The respective entry in the returned array is an array containing
 * all addresses and ended with a null (0x0).
 *
 * The returned pointer should be freed by [`blaze_inspect_syms_free`].
 *
 * # Safety
 * The `inspector` object should have been created using
 * [`blaze_inspector_new`], `src` needs to point to a valid object, and `names`
 * needs to be a valid pointer to `name_cnt` strings.
 */
const struct blaze_sym_info *const *blaze_inspect_syms_elf(const struct blaze_inspector *inspector,
                                                           const struct blaze_inspect_elf_src *src,
                                                           const char *const *names,
                                                           size_t name_cnt);

/**
 * Free an array returned by [`blaze_inspect_syms_elf`].
 *
 * # Safety
 *
 * The pointer must be returned by [`blaze_inspect_syms_elf`].
 *
 */
void blaze_inspect_syms_free(const struct blaze_sym_info *const *syms);

/**
 * Create an instance of a blazesym inspector.
 *
 * The returned pointer should be released using
 * [`blaze_inspector_free`] once it is no longer needed.
 */
struct blaze_inspector *blaze_inspector_new(void);

/**
 * Free a blazesym inspector.
 *
 * Release resources associated with a inspector as created by
 * [`blaze_inspector_new`], for example.
 *
 * # Safety
 * The provided inspector should have been created by
 * [`blaze_inspector_new`].
 */
void blaze_inspector_free(struct blaze_inspector *inspector);

/**
 * Create an instance of a blazesym normalizer.
 *
 * The returned pointer should be released using
 * [`blaze_normalizer_free`] once it is no longer needed.
 */
struct blaze_normalizer *blaze_normalizer_new(void);

/**
 * Free a blazesym normalizer.
 *
 * Release resources associated with a normalizer as created by
 * [`blaze_normalizer_new`], for example.
 *
 * # Safety
 * The provided normalizer should have been created by
 * [`blaze_normalizer_new`].
 */
void blaze_normalizer_free(struct blaze_normalizer *normalizer);

/**
 * Normalize a list of user space addresses.
 *
 * The `addrs` array has to be sorted in ascending order. `pid` should
 * describe the PID of the process to which the addresses belong. It
 * may be `0` if they belong to the calling process.
 *
 * C ABI compatible version of [`Normalizer::normalize_user_addrs`].
 * Returns `NULL` on error. The resulting object should be freed using
 * [`blaze_user_addrs_free`].
 *
 * # Safety
 * Callers need to pass in a valid `addrs` pointer, pointing to memory of
 * `addr_count` addresses.
 */
struct blaze_normalized_user_addrs *blaze_normalize_user_addrs(const struct blaze_normalizer *normalizer,
                                                               const uintptr_t *addrs,
                                                               size_t addr_count,
                                                               uint32_t pid);

/**
 * Normalize a list of user space addresses.
 *
 * `pid` should describe the PID of the process to which the addresses belong.
 * It may be `0` if they belong to the calling process.
 *
 * C ABI compatible version of [`Normalizer::normalize_user_addrs_sorted`].
 * Returns `NULL` on error. The resulting object should be freed using
 * [`blaze_user_addrs_free`].
 *
 * # Safety
 * Callers need to pass in a valid `addrs` pointer, pointing to memory of
 * `addr_count` addresses.
 */
struct blaze_normalized_user_addrs *blaze_normalize_user_addrs_sorted(const struct blaze_normalizer *normalizer,
                                                                      const uintptr_t *addrs,
                                                                      size_t addr_count,
                                                                      uint32_t pid);

/**
 * Free an object as returned by [`blaze_normalized_user_addrs`] or
 * [`blaze_normalize_user_addrs_sorted`].
 *
 * # Safety
 * The provided object should have been created by
 * [`blaze_normalized_user_addrs`] or
 * [`blaze_normalize_user_addrs_sorted`].
 */
void blaze_user_addrs_free(struct blaze_normalized_user_addrs *addrs);

/**
 * Create an instance of a symbolizer.
 */
blaze_symbolizer *blaze_symbolizer_new(void);

/**
 * Create an instance of a symbolizer with configurable options.
 *
 * # Safety
 * `opts` needs to be a valid pointer.
 */
blaze_symbolizer *blaze_symbolizer_new_opts(const struct blaze_symbolizer_opts *opts);

/**
 * Free an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * The pointer must have been returned by [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`].
 */
void blaze_symbolizer_free(blaze_symbolizer *symbolizer);

/**
 * Symbolize addresses of a process.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_process`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_process(blaze_symbolizer *symbolizer,
                                                   const struct blaze_symbolize_src_process *src,
                                                   const uintptr_t *addrs,
                                                   size_t addr_cnt);

/**
 * Symbolize kernel addresses.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_kernel`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_kernel(blaze_symbolizer *symbolizer,
                                                  const struct blaze_symbolize_src_kernel *src,
                                                  const uintptr_t *addrs,
                                                  size_t addr_cnt);

/**
 * Symbolize addresses in an ELF file.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_elf`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_elf(blaze_symbolizer *symbolizer,
                                               const struct blaze_symbolize_src_elf *src,
                                               const uintptr_t *addrs,
                                               size_t addr_cnt);

/**
 * Symbolize addresses in a Gsym file.
 *
 * Return an array of [`blaze_result`] with the same size as the
 * number of input addresses. The caller should free the returned array by
 * calling [`blaze_result_free`].
 *
 * # Safety
 * `symbolizer` must have been allocated using [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`]. `src` must point to a valid
 * [`blaze_symbolize_src_gsym`] object. `addrs` must represent an array of
 * `addr_cnt` objects.
 */
const struct blaze_result *blaze_symbolize_gsym(blaze_symbolizer *symbolizer,
                                                const struct blaze_symbolize_src_gsym *src,
                                                const uintptr_t *addrs,
                                                size_t addr_cnt);

/**
 * Free an array returned by any of the `blaze_symbolize_*` variants.
 *
 * # Safety
 * The pointer must have been returned by any of the `blaze_symbolize_*`
 * variants.
 */
void blaze_result_free(const struct blaze_result *results);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* __blazesym_h_ */
