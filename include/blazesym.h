#ifndef __blazesym_h_
#define __blazesym_h_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Feature names of looking up addresses of symbols.
 */
typedef enum blazesym_faf_type {
  /**
   * Return the offset in the file. (enable)
   */
  BLAZESYM_FAF_T_OFFSET_IN_FILE,
  /**
   * Return the file name of the shared object. (enable)
   */
  BLAZESYM_FAF_T_OBJ_FILE_NAME,
  /**
   * Return symbols having the given type. (sym_type)
   */
  BLAZESYM_FAF_T_SYMBOL_TYPE,
} blazesym_faf_type;

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
 * The types of symbols.
 *
 * This type is used to choice what type of symbols you like to find
 * and indicate the types of symbols found.
 */
typedef enum blazesym_sym_type {
  /**
   * You want to find a symbol of any type.
   */
  BLAZESYM_SYM_T_UNKNOWN,
  /**
   * The returned symbol is a function, or you want to find a function.
   */
  BLAZESYM_SYM_T_FUNC,
  /**
   * The returned symbol is a variable, or you want to find a variable.
   */
  BLAZESYM_SYM_T_VAR,
} blazesym_sym_type;

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
 * A placeholder symbolizer for C API.
 *
 * It is returned by [`blazesym_new()`] and should be free by
 * [`blazesym_free()`].
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
 * [`blazesym_symbolize()`].  They should be free by calling
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

typedef struct blazesym_sym_info {
  const char *name;
  uintptr_t address;
  size_t size;
  uint64_t file_offset;
  const char *obj_file_name;
  enum blazesym_sym_type sym_type;
} blazesym_sym_info;

/**
 * The parameter parts of `blazesym_faddr_feature`.
 */
typedef union blazesym_faf_param {
  bool enable;
  enum blazesym_sym_type sym_type;
} blazesym_faf_param;

/**
 * Switches and settings of features of looking up addresses of
 * symbols.
 *
 * See [`FindAddrFeature`] for details.
 */
typedef struct blazesym_faddr_feature {
  enum blazesym_faf_type ftype;
  union blazesym_faf_param param;
} blazesym_faddr_feature;

/**
 * Create an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * Free the pointer with [`blazesym_free()`].
 *
 */
blazesym *blazesym_new(void);

/**
 * Create an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * Free the pointer with [`blazesym_free()`].
 */
blazesym *blazesym_new_opts(const struct blazesym_feature *aFeatures,
                            size_t aNfeatures);

/**
 * Free an instance of blazesym a symbolizer for C API.
 *
 * # Safety
 *
 * The pointer must be returned by [`blazesym_new()`].
 *
 */
void blazesym_free(blazesym *aSymbolizer);

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
const struct blazesym_result *blazesym_symbolize(blazesym *aSymbolizer,
                                                 const struct blazesym_sym_src_cfg *aSymSrcs,
                                                 size_t aSymSrcsLen,
                                                 const uintptr_t *aAddrs,
                                                 size_t aAddrCnt);

/**
 * Free an array returned by blazesym_symbolize.
 *
 * # Safety
 *
 * The pointer must be returned by [`blazesym_symbolize()`].
 *
 */
void blazesym_result_free(const struct blazesym_result *aResults);

/**
 * Find the addresses of symbols matching a pattern.
 *
 * Return an array of `blazesym_sym_info` ending with an item having a null address.
 * input names.  The caller should free the returned array by calling
 * [`blazesym_syms_free()`].
 *
 * It works the same as [`blazesym_find_address_regex()`] with
 * additional controls on features.
 *
 * # Safety
 *
 * The returned pointer should be free by [`blazesym_syms_free()`].
 */
const struct blazesym_sym_info *blazesym_find_address_regex_opt(blazesym *aSymbolizer,
                                                                const struct blazesym_sym_src_cfg *aSymSrcs,
                                                                size_t aSymSrcsLen,
                                                                const char *aPattern,
                                                                const struct blazesym_faddr_feature *aFeatures,
                                                                size_t aNumFeatures);

/**
 * Find the addresses of symbols matching a pattern.
 *
 * Return an array of `blazesym_sym_info` ending with an item having a null address.
 * input names.  The caller should free the returned array by calling
 * [`blazesym_syms_free()`].
 *
 * # Safety
 *
 * The returned pointer should be free by [`blazesym_syms_free()`].
 */
const struct blazesym_sym_info *blazesym_find_address_regex(blazesym *aSymbolizer,
                                                            const struct blazesym_sym_src_cfg *aSymSrcs,
                                                            size_t aSymSrcsLen,
                                                            const char *aPattern);

/**
 * Free an array returned by blazesym_find_addr_regex() or
 * blazesym_find_addr_regex_opt().
 *
 * # Safety
 *
 * The `syms` pointer should have been allocated by one of the
 * `blazesym_find_address*` variants.
 */
void blazesym_syms_free(const struct blazesym_sym_info *aSyms);

/**
 * Find the addresses of a list of symbols.
 *
 * Return an array with the same size as the input names. The caller should
 * free the returned array by calling [`blazesym_syms_list_free()`].
 *
 * Every name in the input name list may have more than one address.
 * The respective entry in the returned array is an array containing
 * all addresses and ended with a null (0x0).
 *
 * # Safety
 *
 * The returned pointer should be free by [`blazesym_syms_list_free()`].
 */
const struct blazesym_sym_info *const *blazesym_find_addresses_opt(blazesym *aSymbolizer,
                                                                   const struct blazesym_sym_src_cfg *aSymSrcs,
                                                                   size_t aSymSrcsLen,
                                                                   const char *const *aNames,
                                                                   size_t aNameCnt,
                                                                   const struct blazesym_faddr_feature *aFeatures,
                                                                   size_t aNumFeatures);

/**
 * Find addresses of a symbol name.
 *
 * A symbol may have multiple addressses.
 *
 * # Safety
 *
 * The returned data should be free by [`blazesym_syms_list_free()`].
 */
const struct blazesym_sym_info *const *blazesym_find_addresses(blazesym *aSymbolizer,
                                                               const struct blazesym_sym_src_cfg *aSymSrcs,
                                                               size_t aSymSrcsLen,
                                                               const char *const *aNames,
                                                               size_t aNameCnt);

/**
 * Free an array returned by [`blazesym_find_addresses`].
 *
 * # Safety
 *
 * The pointer must be returned by [`blazesym_find_addresses`].
 *
 */
void blazesym_syms_list_free(const struct blazesym_sym_info *const *aSymsList);

#endif /* __blazesym_h_ */
