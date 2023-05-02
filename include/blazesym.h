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
 * Names of the BlazeSym features.
 */
typedef enum blazesym_feature_name {
  /**
   * Enable or disable returning line numbers of addresses.
   *
   * Users should set `blazesym_feature.params.enable` to enable or
   * disable the feature.
   */
  BLAZESYM_LINE_NUMBER_INFO,
  /**
   * Enable or disable loading symbols from DWARF.
   *
   * Users should set `blazesym_feature.params.enable` to enable or
   * disable the feature. This feature is disabled by default.
   */
  BLAZESYM_DEBUG_INFO_SYMBOLS,
} blazesym_feature_name;

/**
 * Types of symbol sources and debug information for C API.
 */
typedef enum blazesym_src_type {
  /**
   * Symbols and debug information from an ELF file.
   */
  BLAZESYM_SRC_T_ELF,
  /**
   * Symbols and debug information from a kernel image and its kallsyms.
   */
  BLAZESYM_SRC_T_KERNEL,
  /**
   * Symbols and debug information from a process, including loaded object files.
   */
  BLAZESYM_SRC_T_PROCESS,
  /**
   * Symbols and debug information from a gsym file.
   */
  BLAZESYM_SRC_T_GSYM,
} blazesym_src_type;

/**
 * BlazeSymbolizer provides an interface to symbolize addresses with
 * a list of symbol sources.
 *
 * Users should present BlazeSymbolizer with a list of symbol sources
 * (`SymbolSrcCfg`); for example, an ELF file and its base address
 * (`SymbolSrcCfg::Elf`), or a Linux kernel image and a copy of its
 * kallsyms (`SymbolSrcCfg::Kernel`).  Additionally, BlazeSymbolizer
 * uses information from these sources to symbolize addresses.
 */
typedef struct blazesym blazesym;

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
 * Information about a looked up symbol.
 */
typedef struct blaze_sym_info {
  const char *name;
  uintptr_t address;
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
  char *path;
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
typedef struct blazesym blazesym;

typedef union blazesym_feature_params {
  bool enable;
} blazesym_feature_params;

/**
 * Setting of the blazesym features.
 *
 * Contain parameters to enable, disable, or customize a feature.
 */
typedef struct blazesym_feature {
  enum blazesym_feature_name feature;
  union blazesym_feature_params params;
} blazesym_feature;

/**
 * The result of symbolization of an address for C API.
 *
 * A `blazesym_csym` is the information of a symbol found for an
 * address.  One address may result in several symbols.
 */
typedef struct blazesym_csym {
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
  uintptr_t start_address;
  /**
   * The path of the source code defines the symbol.
   */
  const char *path;
  /**
   * The instruction of the address is in the line number of the source code.
   */
  size_t line_no;
  size_t column;
} blazesym_csym;

/**
 * `blazesym_entry` is the output of symbolization for an address for C API.
 *
 * Every address has an `blazesym_entry` in
 * [`blazesym_result::entries`] to collect symbols found by BlazeSym.
 */
typedef struct blazesym_entry {
  /**
   * The number of symbols found for an address.
   */
  size_t size;
  /**
   * All symbols found.
   *
   * `syms` is an array of blazesym_csym in the size `size`.
   */
  const struct blazesym_csym *syms;
} blazesym_entry;

/**
 * `blazesym_result` is the result of symbolization for C API.
 *
 * The instances of blazesym_result are returned from
 * [`blaze_symbolize()`]. They should be freed by calling
 * [`blazesym_result_free()`].
 */
typedef struct blazesym_result {
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
  struct blazesym_entry entries[0];
} blazesym_result;

/**
 * The parameters to load symbols and debug information from an ELF.
 *
 * Describes the path and address of an ELF file loaded in a
 * process.
 */
typedef struct blazesym_ssc_elf {
  /**
   * The file name of an ELF file.
   *
   * It can be an executable or shared object.
   * For example, passing "/bin/sh" will load symbols and debug information from `sh`.
   * Whereas passing "/lib/libc.so.xxx" will load symbols and debug information from the libc.
   */
  const char *file_name;
  /**
   * The base address is where the file's executable segment(s) is loaded.
   *
   * It should be the address
   * in the process mapping to the executable segment's first byte.
   * For example, in /proc/&lt;pid&gt;/maps
   *
   * ```text
   *     7fe1b2dc4000-7fe1b2f80000 r-xp 00000000 00:1d 71695032                   /usr/lib64/libc-2.28.so
   *     7fe1b2f80000-7fe1b3180000 ---p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
   *     7fe1b3180000-7fe1b3184000 r--p 001bc000 00:1d 71695032                   /usr/lib64/libc-2.28.so
   *     7fe1b3184000-7fe1b3186000 rw-p 001c0000 00:1d 71695032                   /usr/lib64/libc-2.28.so
   * ```
   *
   * It reveals that the executable segment of libc-2.28.so was
   * loaded at 0x7fe1b2dc4000.  This base address is used to
   * translate an address in the segment to the corresponding
   * address in the ELF file.
   *
   * A loader would load an executable segment with the permission of `x`
   * (executable).  For example, the first block is with the
   * permission of `r-xp`.
   */
  uintptr_t base_address;
} blazesym_ssc_elf;

/**
 * The parameters to load symbols and debug information from a kernel.
 *
 * Use a kernel image and a snapshot of its kallsyms as a source of symbols and
 * debug information.
 */
typedef struct blazesym_ssc_kernel {
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
} blazesym_ssc_kernel;

/**
 * The parameters to load symbols and debug information from a process.
 *
 * Load all ELF files in a process as the sources of symbols and debug
 * information.
 */
typedef struct blazesym_ssc_process {
  /**
   * It is the PID of a process to symbolize.
   *
   * BlazeSym will parse `/proc/<pid>/maps` and load all the object
   * files.
   */
  uint32_t pid;
} blazesym_ssc_process;

/**
 * The parameters to load symbols and debug information from a gsym file.
 */
typedef struct blazesym_ssc_gsym {
  /**
   * The file name of a gsym file.
   */
  const char *file_name;
  /**
   * The base address is where the file's executable segment(s) is loaded.
   */
  uintptr_t base_address;
} blazesym_ssc_gsym;

/**
 * Parameters of a symbol source.
 */
typedef union blazesym_ssc_params {
  /**
   * The variant for [`blazesym_src_type::BLAZESYM_SRC_T_ELF`].
   */
  struct blazesym_ssc_elf elf;
  /**
   * The variant for [`blazesym_src_type::BLAZESYM_SRC_T_KERNEL`].
   */
  struct blazesym_ssc_kernel kernel;
  /**
   * The variant for [`blazesym_src_type::BLAZESYM_SRC_T_PROCESS`].
   */
  struct blazesym_ssc_process process;
  /**
   * The variant for [`blazesym_src_type::BLAZESYM_SRC_T_GSYM`].
   */
  struct blazesym_ssc_gsym gsym;
} blazesym_ssc_params;

/**
 * Description of a source of symbols and debug information for C API.
 */
typedef struct blazesym_sym_src_cfg {
  /**
   * A type of symbol source.
   */
  enum blazesym_src_type src_type;
  union blazesym_ssc_params params;
} blazesym_sym_src_cfg;

/**
 * Lookup symbol information in an ELF file.
 *
 * Return an array with the same size as the input names. The caller should
 * free the returned array by calling [`blaze_syms_free`].
 *
 * Every name in the input name list may have more than one address.
 * The respective entry in the returned array is an array containing
 * all addresses and ended with a null (0x0).
 *
 * The returned pointer should be freed by [`blaze_syms_free`].
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
void blaze_syms_free(const struct blaze_sym_info *const *syms);

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
 * Free an object as returned by [`blaze_normalized_user_addrs`].
 *
 * # Safety
 * The provided object should have been created by
 * [`blaze_normalize_user_addrs_sorted`].
 */
void blaze_user_addrs_free(struct blaze_normalized_user_addrs *addrs);

/**
 * Create an instance of blazesym a symbolizer for C API.
 */
blazesym *blaze_symbolizer_new(void);

/**
 * Create an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * `features` needs to be a valid pointer to `feature_cnt` elements.
 */
blazesym *blaze_symbolizer_new_opts(const struct blazesym_feature *features,
                                    size_t feature_cnt);

/**
 * Free an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * The pointer must have been returned by [`blaze_symbolizer_new`] or
 * [`blaze_symbolizer_new_opts`].
 */
void blaze_symbolizer_free(blazesym *symbolizer);

/**
 * Symbolize addresses with the sources of symbols and debug info.
 *
 * Return an array of [`blazesym_result`] with the same size as the
 * number of input addresses.  The caller should free the returned
 * array by calling [`blazesym_result_free()`].
 *
 * # Safety
 *
 * The returned pointer should be freed by [`blazesym_result_free()`].
 */
const struct blazesym_result *blaze_symbolize(blazesym *symbolizer,
                                              const struct blazesym_sym_src_cfg *cfg,
                                              const uintptr_t *addrs,
                                              size_t addr_cnt);

/**
 * Free an array returned by [`blaze_symbolize`].
 *
 * # Safety
 *
 * The pointer must have been returned by [`blaze_symbolize`].
 */
void blazesym_result_free(const struct blazesym_result *results);

#endif /* __blazesym_h_ */
