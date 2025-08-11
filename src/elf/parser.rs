use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io;
use std::io::Seek as _;
use std::io::SeekFrom;
use std::mem;
use std::mem::MaybeUninit;
use std::ops::ControlFlow;
use std::ops::Deref as _;
use std::path::Path;
use std::slice;
use std::str;

use crate::inspect::FindAddrOpts;
use crate::inspect::ForEachFn;
use crate::inspect::SymInfo;
use crate::mmap::Mmap;
use crate::once::OnceCell;
use crate::pathlike::PathLike;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::symbolize::Symbolize;
use crate::util::find_match_or_lower_bound_by_key;
use crate::util::Pod;
use crate::util::ReadRaw as _;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;
use crate::SymType;

use super::types::Elf32_Chdr;
use super::types::Elf32_Ehdr;
use super::types::Elf32_Phdr;
use super::types::Elf32_Shdr;
use super::types::Elf32_Sym;
use super::types::Elf64_Chdr;
use super::types::Elf64_Ehdr;
use super::types::Elf64_Phdr;
use super::types::Elf64_Shdr;
use super::types::Elf64_Sym;
use super::types::ElfN_Ehdr;
use super::types::ElfN_Phdrs;
use super::types::ElfN_Shdr;
use super::types::ElfN_Shdrs;
use super::types::ElfN_Sym;
use super::types::ElfN_Syms;
use super::types::EI_NIDENT;
use super::types::ELFCLASS32;
use super::types::ELFCLASS64;
use super::types::ELFCOMPRESS_ZLIB;
use super::types::ELFCOMPRESS_ZSTD;
use super::types::PN_XNUM;
use super::types::PT_LOAD;
use super::types::SHF_COMPRESSED;
use super::types::SHN_ABS;
use super::types::SHN_LORESERVE;
use super::types::SHN_UNDEF;
use super::types::SHN_XINDEX;
use super::types::SHT_NOBITS;


pub(crate) type StaticMem = &'static [u8];


fn read_pod<T, R>(reader: &mut R) -> Result<T, io::Error>
where
    T: Pod,
    R: io::Read,
{
    let mut value = MaybeUninit::<T>::uninit();
    let ptr = value.as_mut_ptr().cast::<u8>();
    let len = mem::size_of::<T>();
    // Make sure to zero out everything, including potential padding
    // bytes. `std::io::Read` requires fully initialized memory, for
    // better or worse.
    // SAFETY: `T` is a `Pod` and hence valid for any bit pattern,
    //         including all zeroes.
    let () = unsafe { ptr.write_bytes(0, len) };
    // SAFETY: `value` is a buffer of `len` bytes.
    let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
    let () = reader.read_exact(slice)?;
    // SAFETY: `T` is a `Pod` and hence valid for any bit pattern,
    //         including all zeroes.
    Ok(unsafe { value.assume_init() })
}


fn read_pod_vec<T, R>(reader: &mut R, count: usize) -> Result<Vec<T>, io::Error>
where
    T: Pod,
    R: io::Read,
{
    let mut vec = Vec::<T>::with_capacity(count);
    let ptr = vec.as_mut_ptr().cast::<u8>();
    let len = count * mem::size_of::<T>();
    // Make sure to zero out everything, including potential padding
    // bytes. `std::io::Read` requires fully initialized memory, for
    // better or worse.
    // SAFETY: `T` is a `Pod` and hence valid for any bit pattern,
    //         including all zeroes.
    let () = unsafe { ptr.write_bytes(0, len) };
    // SAFETY: `vec` is a buffer of `len` bytes.
    let slice = unsafe { slice::from_raw_parts_mut(ptr, len) };
    let () = reader.read_exact(slice)?;
    // SAFETY: The `Vec` is guaranteed to have capacity for `count`
    //         objects and we made sure to initialize all of them.
    let () = unsafe { vec.set_len(count) };
    Ok(vec)
}


fn symbol_name<'elf>(strtab: &'elf [u8], sym: &Elf64_Sym) -> Result<&'elf str> {
    let name = strtab
        .get(sym.st_name as usize..)
        .ok_or_invalid_input(|| "string table index out of bounds")?
        .read_cstr()
        .ok_or_invalid_input(|| "no valid string found in string table")?
        .to_str()
        .map_err(Error::with_invalid_data)
        .context("invalid symbol name")?;

    Ok(name)
}

fn find_sym<'elf>(
    syms: &ElfN_Syms<'_>,
    module: Option<&'elf OsStr>,
    by_addr_idx: &[usize],
    strtab: &'elf [u8],
    addr: Addr,
    type_: SymType,
) -> Result<Option<ResolvedSym<'elf>>> {
    let idx = find_match_or_lower_bound_by_key(by_addr_idx, addr, |&idx| {
        // SANITY: The index originates in our code and is known to be
        //         in bounds.
        syms.get(idx).unwrap().value()
    });

    match idx {
        None => Ok(None),
        Some(idx) => {
            for idx in &by_addr_idx[idx..] {
                // SANITY: The index originates in our code and is known
                //         to be in bounds.
                let sym = syms.get(*idx).unwrap().to_64bit();
                if sym.st_value > addr {
                    // Once we are seeing start addresses past the provided
                    // address, we can no longer be dealing with a match and
                    // stop the search.
                    break
                }

                // In ELF, a symbol size of 0 indicates "no size or an unknown
                // size" (see elf(5)). We take our chances and report these on a
                // best-effort basis.
                if sym.matches(type_)
                    && sym.st_shndx != SHN_UNDEF
                    && (sym.st_size == 0 || addr < sym.st_value + sym.st_size)
                {
                    let sym = ResolvedSym {
                        name: symbol_name(strtab, &sym)?,
                        module,
                        addr: sym.st_value,
                        size: if sym.st_size == 0 {
                            None
                        } else {
                            Some(usize::try_from(sym.st_size).unwrap_or(usize::MAX))
                        },
                        // ELF does not carry any source code language
                        // information.
                        lang: SrcLang::Unknown,
                        // ELF doesn't carry source code location
                        // information.
                        code_info: None,
                        inlined: Box::new([]),
                    };
                    return Ok(Some(sym))
                }
            }
            Ok(None)
        }
    }
}


/// Calculate the file offset of the given symbol.
///
/// # Notes
/// It is the caller's responsibility to ensure that the symbol's section
/// index is not `SHN_UNDEF`.
fn file_offset(shdrs: &ElfN_Shdrs<'_>, sym: &Elf64_Sym) -> Result<Option<u64>> {
    debug_assert_ne!(sym.st_shndx, SHN_UNDEF);

    if sym.st_shndx >= SHN_LORESERVE {
        return Ok(None)
    }

    if sym.st_shndx == SHN_ABS {
        return Ok(None)
    }

    let shdr = shdrs
        .get(usize::from(sym.st_shndx))
        .ok_or_invalid_input(|| {
            format!(
                "ELF section index ({}) of symbol at {:#x} out of bounds",
                sym.st_shndx, sym.st_value
            )
        })?;

    // If the section doesn't have in-file data, there can't be a proper
    // file offset (elf(5) refers to a "conceptual placement in the
    // file", but that concept has no meaning for us).
    if shdr.type_() == SHT_NOBITS {
        return Ok(None)
    }

    let offset = sym
        .st_value
        .wrapping_sub(shdr.addr())
        .wrapping_add(shdr.offset());
    let limit = shdr.offset() + shdr.size();
    if offset < limit || (offset == limit && sym.st_size == 0) {
        Ok(Some(offset))
    } else {
        Ok(None)
    }
}


#[cfg(feature = "zlib")]
fn decompress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use miniz_oxide::inflate::decompress_to_vec_zlib;

    match decompress_to_vec_zlib(data) {
        Ok(data) => Ok(data),
        Err(err) => Err(Error::with_invalid_data(format!(
            "zlib decompression failed: {err}"
        ))),
    }
}

#[cfg(not(feature = "zlib"))]
fn decompress_zlib(_data: &[u8]) -> Result<Vec<u8>> {
    Err(Error::with_unsupported(
        "ELF section is zlib compressed but zlib compression support is not enabled",
    ))
}

#[cfg(feature = "zstd")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    use zstd::stream::decode_all;
    decode_all(data).context("zstd decompression failed")
}

#[cfg(not(feature = "zstd"))]
fn decompress_zstd(_data: &[u8]) -> Result<Vec<u8>> {
    Err(Error::with_unsupported(
        "ELF section is zstd compressed but zstd compression support is not enabled",
    ))
}


#[derive(Debug)]
struct EhdrExt<'elf> {
    /// The ELF header.
    ehdr: ElfN_Ehdr<'elf>,
    /// Override of `ehdr.e_shnum`, handling of which is special-cased by
    /// the ELF standard.
    shnum: usize,
    /// Override of `ehdr.e_phnum`, handling of which is special-cased by
    /// the ELF standard.
    phnum: usize,
}

impl EhdrExt<'_> {
    fn is_32bit(&self) -> bool {
        self.ehdr.is_32bit()
    }
}


#[derive(Debug)]
struct SymName {
    /// The index of the first byte of the name.
    idx: usize,
    /// The length of the name.
    len: usize,
}

impl SymName {
    fn bytes<'strs>(&self, strs: &'strs [u8]) -> &'strs [u8] {
        &strs[self.idx..self.idx + self.len]
    }

    fn name<'strs>(&self, strs: &'strs [u8]) -> Result<&'strs str> {
        let bytes = self.bytes(strs);
        str::from_utf8(bytes)
            .ok()
            .ok_or_invalid_data(|| "symbol name `{bytes:?}` is invalid")
    }
}


#[derive(Debug)]
struct SymbolTableCache<'elf> {
    /// The cached symbols.
    ///
    /// Note that these are the symbols as they appear in the file,
    /// without any filtering applied.
    syms: ElfN_Syms<'elf>,
    /// An index over `syms` that is sorted by address and that only
    /// contains a relevant subset of symbols.
    by_addr_idx: OnceCell<Box<[usize]>>,
    /// The string table.
    strs: Cow<'elf, [u8]>,
    /// The cached name to symbol index table (in dictionary order).
    str2sym: OnceCell<Box<[(SymName, usize)]>>,
}

impl<'elf> SymbolTableCache<'elf> {
    fn new(syms: ElfN_Syms<'elf>, strs: Cow<'elf, [u8]>) -> Self {
        Self {
            syms,
            by_addr_idx: OnceCell::new(),
            strs,
            str2sym: OnceCell::new(),
        }
    }

    fn create_by_addr_idx(&self) -> Box<[usize]> {
        let mut by_addr_idx = self
            .syms
            .iter(0)
            .enumerate()
            // Filter out any symbols that we do not support.
            .filter(|(_idx, sym)| sym.matches(SymType::Undefined))
            .map(|(idx, _sym)| idx)
            .collect::<Box<[_]>>();

        // Order symbols by address and those with equal address descending by
        // size.
        let () = by_addr_idx.sort_by(|idx1, idx2| {
            // SANITY: Both indexes originate in our code and are known
            //         to be in bounds.
            let sym1 = self.syms.get(*idx1).unwrap();
            let sym2 = self.syms.get(*idx2).unwrap();
            sym1.value()
                .cmp(&sym2.value())
                .then_with(|| sym1.size().cmp(&sym2.size()).reverse())
        });

        by_addr_idx
    }

    fn ensure_by_addr_idx(&self) -> &[usize] {
        self.by_addr_idx.get_or_init(|| self.create_by_addr_idx())
    }

    fn create_str2sym<F>(&self, mut filter: F) -> Result<Box<[(SymName, usize)]>>
    where
        F: FnMut(&ElfN_Sym<'_>) -> bool,
    {
        let by_addr_idx = self.ensure_by_addr_idx();

        // We use `by_addr_idx` as the base, because we want the
        // filtering that had been applied to it to be in effect.
        let mut str2sym = by_addr_idx
            .iter()
            // SANITY: The index originates in our code and is known to
            //         be in bounds.
            .map(|&idx| (self.syms.get(idx).unwrap(), idx))
            .filter(|(sym, _idx)| filter(sym))
            .map(|(sym, idx)| {
                let name_idx = sym.name() as usize;
                let cname = self
                    .strs
                    .get(name_idx..)
                    .ok_or_invalid_input(|| "ELF string table index out of bounds")?
                    .read_cstr()
                    .ok_or_invalid_input(|| "no valid string found in ELF string table")?;
                let name = SymName {
                    idx: name_idx,
                    // TODO: May want to use `CStr::count_bytes` once
                    //       our MSRV is >=1.79.
                    len: cname.to_bytes().len(),
                };
                Ok((name, idx))
            })
            .collect::<Result<Box<[_]>>>()?;

        let () = str2sym.sort_by_key(|(name, _i)| name.bytes(&self.strs));
        Ok(str2sym)
    }

    fn ensure_str2sym<F>(&self, filter: F) -> Result<&[(SymName, usize)]>
    where
        F: FnMut(&ElfN_Sym<'_>) -> bool,
    {
        let str2sym = self
            .str2sym
            .get_or_try_init(|| {
                let str2sym = self.create_str2sym(filter)?;
                Result::<_, Error>::Ok(str2sym)
            })?
            .deref();

        Ok(str2sym)
    }
}


struct Cache<'elf, B> {
    /// The backend being used for reading ELF data.
    backend: B,
    /// The cached ELF header.
    ehdr: OnceCell<EhdrExt<'elf>>,
    /// The cached ELF section headers.
    shdrs: OnceCell<ElfN_Shdrs<'elf>>,
    shstrtab: OnceCell<Cow<'elf, [u8]>>,
    /// The cached ELF program headers.
    phdrs: OnceCell<ElfN_Phdrs<'elf>>,
    /// The cached symbol table.
    symtab: OnceCell<SymbolTableCache<'elf>>,
    /// The cached dynamic symbol table.
    dynsym: OnceCell<SymbolTableCache<'elf>>,
    /// The section data.
    section_data: OnceCell<Box<[OnceCell<Cow<'elf, [u8]>>]>>,
}

impl<'elf, B> Cache<'elf, B>
where
    B: BackendImpl<'elf>,
{
    /// Create a new `Cache` using the provided raw ELF object data.
    fn new(backend: B) -> Self {
        Self {
            backend,
            ehdr: OnceCell::new(),
            shdrs: OnceCell::new(),
            shstrtab: OnceCell::new(),
            phdrs: OnceCell::new(),
            symtab: OnceCell::new(),
            dynsym: OnceCell::new(),
            section_data: OnceCell::new(),
        }
    }

    /// A convenience helper for retrieving a given ELF section header.
    fn section_hdr(&self, idx: usize) -> Result<ElfN_Shdr<'_>> {
        let shdrs = self.ensure_shdrs()?;
        let shdr = shdrs
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF section index ({idx}) out of bounds"))?;
        Ok(shdr)
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`.
    ///
    /// # Notes
    /// This method returns potentially compressed data, but is able to
    /// do so with the `'elf` lifetime. To transparently decompress, use
    /// [`Cache::section_data`] instead.
    fn section_data_raw(&self, idx: usize) -> Result<Cow<'elf, [u8]>> {
        let shdr = self.section_hdr(idx)?;
        if shdr.type_() != SHT_NOBITS {
            self.backend
                .read_pod_slice::<u8>(shdr.offset(), shdr.size() as usize)
                .context("failed to read ELF section data")
        } else {
            Ok(Cow::Borrowed(&[]))
        }
    }

    /// Retrieve the raw section data for the ELF section at index
    /// `idx`, along with its section header.
    ///
    /// If the section is compressed the resulting decompressed data
    /// will be cached for the life time of this object.
    fn section_data(&self, idx: usize) -> Result<&[u8]> {
        let shdr = self.section_hdr(idx)?;
        if shdr.type_() != SHT_NOBITS {
            let datas = self.section_data.get_or_try_init(|| {
                let shdrs = self.ensure_shdrs()?;
                let datas = (0..shdrs.len())
                    .map(|_| OnceCell::new())
                    .collect::<Box<[_]>>();
                Result::<_, Error>::Ok(datas)
            })?;

            datas
                .get(idx)
                .ok_or_invalid_input(|| format!("ELF section index ({idx}) out of bounds"))?
                .get_or_try_init(|| -> Result<Cow<'elf, [u8]>> {
                    let data = self
                                .backend
                                .read_pod_slice::<u8>(shdr.offset(), shdr.size() as usize)
                                .context("failed to read ELF section data")?;

                    if shdr.flags() & SHF_COMPRESSED != 0 {
                        let mut data = data.deref();
                        // Compression header is contained in the actual section
                        // data.
                        let (ch_type, ch_size) = if shdr.is_32bit() {
                            let chdr = data
                                .read_pod::<Elf32_Chdr>()
                                .ok_or_invalid_data(|| "failed to read ELF compression header")?;
                            (chdr.ch_type, chdr.ch_size.into())
                        } else {
                            let chdr = data
                                .read_pod::<Elf64_Chdr>()
                                .ok_or_invalid_data(|| "failed to read ELF compression header")?;
                            (chdr.ch_type, chdr.ch_size)
                        };

                        let decompressed = match ch_type {
                            t if t == ELFCOMPRESS_ZLIB => decompress_zlib(data),
                            t if t == ELFCOMPRESS_ZSTD => decompress_zstd(data),
                            _ => Err(Error::with_unsupported(format!(
                                "ELF section is compressed with unknown compression algorithm ({ch_type})",
                            ))),
                        }?;
                        debug_assert_eq!(
                            decompressed.len(),
                            ch_size as usize,
                            "decompressed ELF section data does not have expected length"
                        );
                        Ok(Cow::Owned(decompressed))
                    } else {
                        Ok(data)
                    }
                }).map(Cow::deref)
        } else {
            Ok(&[])
        }
    }

    /// Read the very first section header.
    ///
    /// ELF contains a couple of clauses that special case data ranges
    /// of certain member variables to reference data from this header,
    /// which otherwise is zeroed out.
    #[inline]
    fn read_first_shdr(&self, ehdr: &ElfN_Ehdr<'_>) -> Result<ElfN_Shdr<'elf>> {
        let shdr = if ehdr.is_32bit() {
            self.backend
                .read_pod_obj::<Elf32_Shdr>(ehdr.shoff())
                .map(ElfN_Shdr::B32)
        } else {
            self.backend
                .read_pod_obj::<Elf64_Shdr>(ehdr.shoff())
                .map(ElfN_Shdr::B64)
        }
        .context("failed to read ELF section header")?;

        Ok(shdr)
    }

    fn parse_ehdr(&self) -> Result<EhdrExt<'elf>> {
        let e_ident = self
            .backend
            .read_pod_slice::<u8>(0, EI_NIDENT)
            .context("failed to read ELF e_ident information")?;
        if !(e_ident[0] == 0x7f && e_ident[1] == b'E' && e_ident[2] == b'L' && e_ident[3] == b'F') {
            return Err(Error::with_invalid_data(format!(
                "encountered unexpected e_ident: {:x?}",
                &e_ident[0..4]
            )))
        }

        let class = e_ident[4];
        if ![ELFCLASS32, ELFCLASS64].contains(&class) {
            return Err(Error::with_unsupported(format!(
                "ELF class ({class}) is not currently supported"
            )))
        }

        let bit32 = class == ELFCLASS32;
        let ehdr = if bit32 {
            self.backend
                .read_pod_obj::<Elf32_Ehdr>(0)
                .map(ElfN_Ehdr::B32)
                .context("failed to read ELF header")?
        } else {
            self.backend
                .read_pod_obj::<Elf64_Ehdr>(0)
                .map(ElfN_Ehdr::B64)
                .context("failed to read ELF header")?
        };

        // "If the number of entries in the section header table is larger than
        // or equal to SHN_LORESERVE, e_shnum holds the value zero and the real
        // number of entries in the section header table is held in the sh_size
        // member of the initial entry in section header table."
        let shnum = if ehdr.shnum() == 0 {
            let shdr = self.read_first_shdr(&ehdr)?.to_64bit();
            usize::try_from(shdr.sh_size).ok().ok_or_invalid_data(|| {
                format!(
                    "ELF file contains unsupported number of sections ({})",
                    shdr.sh_size
                )
            })?
        } else {
            ehdr.shnum().into()
        };

        // "If the number of entries in the program header table is
        // larger than or equal to PN_XNUM (0xffff), this member holds
        // PN_XNUM (0xffff) and the real number of entries in the
        // program header table is held in the sh_info member of the
        // initial entry in section header table."
        let phnum = if ehdr.phnum() == PN_XNUM {
            let shdr = self.read_first_shdr(&ehdr)?.to_64bit();
            usize::try_from(shdr.sh_info).ok().ok_or_invalid_data(|| {
                format!(
                    "ELF file contains unsupported number of program headers ({})",
                    shdr.sh_info
                )
            })?
        } else {
            ehdr.phnum().into()
        };

        let ehdr = EhdrExt { ehdr, shnum, phnum };
        Ok(ehdr)
    }

    fn ensure_ehdr(&self) -> Result<&EhdrExt<'elf>> {
        self.ehdr.get_or_try_init(|| self.parse_ehdr())
    }

    fn parse_shdrs(&self) -> Result<ElfN_Shdrs<'elf>> {
        let ehdr = self.ensure_ehdr()?;
        let e_shoff = ehdr.ehdr.shoff();

        let shdrs = if ehdr.is_32bit() {
            self.backend
                .read_pod_slice::<Elf32_Shdr>(e_shoff, ehdr.shnum)
                .map(ElfN_Shdrs::B32)
        } else {
            self.backend
                .read_pod_slice::<Elf64_Shdr>(e_shoff, ehdr.shnum)
                .map(ElfN_Shdrs::B64)
        }
        .context("failed to read ELF section headers")?;

        Ok(shdrs)
    }

    fn ensure_shdrs(&self) -> Result<&ElfN_Shdrs<'elf>> {
        self.shdrs.get_or_try_init(|| self.parse_shdrs())
    }

    fn parse_phdrs(&self) -> Result<ElfN_Phdrs<'elf>> {
        let ehdr = self.ensure_ehdr()?;
        let e_phoff = ehdr.ehdr.phoff();

        let phdrs = if ehdr.is_32bit() {
            self.backend
                .read_pod_slice::<Elf32_Phdr>(e_phoff, ehdr.phnum)
                .map(ElfN_Phdrs::B32)
        } else {
            self.backend
                .read_pod_slice::<Elf64_Phdr>(e_phoff, ehdr.phnum)
                .map(ElfN_Phdrs::B64)
        }
        .context("failed to read ELF program headers")?;

        Ok(phdrs)
    }

    fn ensure_phdrs(&self) -> Result<&ElfN_Phdrs<'elf>> {
        self.phdrs.get_or_try_init(|| self.parse_phdrs())
    }

    fn shstrndx(&self, ehdr: &ElfN_Ehdr<'_>) -> Result<usize> {
        let e_shstrndx = ehdr.shstrndx();
        // "If the index of section name string table section is larger
        // than or equal to SHN_LORESERVE (0xff00), this member holds
        // SHN_XINDEX (0xffff) and  the real index of the section name
        // string table section is held in the sh_link member of the
        // initial entry in section header table."
        let shstrndx = if e_shstrndx == SHN_XINDEX {
            self.read_first_shdr(ehdr)?.link()
        } else {
            u32::from(e_shstrndx)
        };

        let shstrndx = usize::try_from(shstrndx).ok().ok_or_invalid_data(|| {
            format!("ELF file contains unsupported section name string table index ({shstrndx})")
        })?;
        Ok(shstrndx)
    }

    fn parse_shstrtab(&self) -> Result<Cow<'elf, [u8]>> {
        let ehdr = self.ensure_ehdr()?;
        let shstrndx = self.shstrndx(&ehdr.ehdr)?;
        let shstrtab = self.section_data_raw(shstrndx)?;
        Ok(shstrtab)
    }

    fn ensure_shstrtab(&self) -> Result<&Cow<'elf, [u8]>> {
        self.shstrtab.get_or_try_init(|| self.parse_shstrtab())
    }

    /// Get the name of the section at a given index.
    fn section_name(&self, idx: usize) -> Result<&str> {
        let shdr = self.section_hdr(idx)?;
        let shstrtab = self.ensure_shstrtab()?;

        let name = shstrtab
            .get(shdr.name() as usize..)
            .ok_or_invalid_input(|| "ELF string table index out of bounds")?
            .read_cstr()
            .ok_or_invalid_input(|| "no valid string found in ELF string table")?
            .to_str()
            .map_err(Error::with_invalid_data)
            .context("invalid section name")?;
        Ok(name)
    }

    #[cfg(test)]
    fn symbol(&self, idx: usize) -> Result<ElfN_Sym<'_>> {
        let symtab = self.ensure_symtab()?;
        let symbol = symtab
            .get(idx)
            .ok_or_invalid_input(|| format!("ELF symbol index ({idx}) out of bounds"))?;

        Ok(symbol)
    }

    /// Find the section of a given name.
    ///
    /// This function return the index of the section if found.
    fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let ehdr = self.ensure_ehdr()?;
        for i in 1..ehdr.shnum {
            if self.section_name(i)? == name {
                return Ok(Some(i))
            }
        }
        Ok(None)
    }

    fn parse_syms(&self, section: &str) -> Result<ElfN_Syms<'elf>> {
        let ehdr = self.ensure_ehdr()?;
        let idx = if let Some(idx) = self.find_section(section)? {
            idx
        } else {
            // The symbol table does not exists. Fake an empty one.
            return Ok(ElfN_Syms::empty(ehdr.is_32bit()))
        };

        let shdr = self.section_hdr(idx)?;
        // There may be no data in case of certain split debug binaries,
        // which may only preserve (some) meta data but no section
        // contents.
        if shdr.type_() == SHT_NOBITS {
            return Ok(ElfN_Syms::empty(ehdr.is_32bit()))
        }

        let sh_size = shdr.size();
        let sh_offset = shdr.offset();

        let sym_size = if ehdr.is_32bit() {
            mem::size_of::<Elf32_Sym>()
        } else {
            mem::size_of::<Elf64_Sym>()
        } as u64;

        if sh_size % sym_size != 0 {
            return Err(Error::with_invalid_data(
                "size of ELF symbol table section is invalid",
            ))
        }

        let count = (sh_size / sym_size) as usize;
        // Short-circuit if there are no symbols. The data may not actually be
        // properly aligned in this case either, so don't attempt to even read.
        if count == 0 {
            return Ok(ElfN_Syms::empty(ehdr.is_32bit()))
        }

        let syms = if ehdr.is_32bit() {
            self.backend
                .read_pod_slice::<Elf32_Sym>(sh_offset, count)
                .map(ElfN_Syms::B32)
        } else {
            self.backend
                .read_pod_slice::<Elf64_Sym>(sh_offset, count)
                .map(ElfN_Syms::B64)
        }
        .with_context(|| format!("failed to read ELF {section} symbol table contents"))?;

        Ok(syms)
    }

    fn ensure_symtab_cache(&self) -> Result<&SymbolTableCache<'elf>> {
        self.symtab.get_or_try_init(|| {
            let syms = self.parse_syms(".symtab")?;
            let strtab = self.parse_strs(".strtab")?;
            let cache = SymbolTableCache::new(syms, strtab);
            Ok(cache)
        })
    }

    fn ensure_dynsym_cache(&self) -> Result<&SymbolTableCache<'elf>> {
        self.dynsym.get_or_try_init(|| {
            // TODO: We really should check the `.dynamic` section for
            //       information on what symbol and string tables to
            //       use instead of hard coding names here.
            let syms = self.parse_syms(".dynsym")?;
            let dynstr = self.parse_strs(".dynstr")?;
            let cache = SymbolTableCache::new(syms, dynstr);
            Ok(cache)
        })
    }

    #[cfg(test)]
    fn ensure_symtab(&self) -> Result<&ElfN_Syms<'_>> {
        let symtab = self.ensure_symtab_cache()?;
        Ok(&symtab.syms)
    }

    fn parse_strs(&self, section: &str) -> Result<Cow<'elf, [u8]>> {
        let strs = if let Some(idx) = self.find_section(section)? {
            self.section_data_raw(idx)?
        } else {
            Cow::Borrowed([].as_slice())
        };
        Ok(strs)
    }

    fn ensure_str2symtab(&self) -> Result<&[(SymName, usize)]> {
        let symtab = self.ensure_symtab_cache()?;
        let str2sym = symtab.ensure_str2sym(|_sym| true)?;
        Ok(str2sym)
    }

    fn ensure_str2dynsym(&self) -> Result<&[(SymName, usize)]> {
        let symtab = self.ensure_symtab_cache()?;
        let symtab_by_addr_idx = symtab.ensure_by_addr_idx();

        let dynsym = self.ensure_dynsym_cache()?;
        let str2sym = dynsym.ensure_str2sym(|sym| {
            // We filter out all the symbols that already exist in symtab,
            // to prevent any duplicates from showing up.

            // The actual module path doesn't matter for the filtering
            // to be correct, so just fake it.
            let module = None;
            let result = find_sym(
                &symtab.syms,
                module,
                symtab_by_addr_idx,
                &symtab.strs,
                sym.value(),
                // SANITY: We filter out all unsupported symbol types,
                //         so this conversion should always succeed.
                SymType::try_from(sym).unwrap(),
            );
            !matches!(result, Ok(Some(_)))
        })?;
        Ok(str2sym)
    }
}

impl<B> Debug for Cache<'_, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Cache")
    }
}


pub(crate) trait Backend {
    type ObjTy;
    type ImplTy<'bcknd>: BackendImpl<'bcknd>;
}

impl Backend for Mmap {
    type ObjTy = Mmap;
    type ImplTy<'bcknd> = &'bcknd [u8];
}

impl Backend for StaticMem {
    type ObjTy = StaticMem;
    type ImplTy<'bcknd> = &'bcknd [u8];
}

impl Backend for File {
    type ObjTy = Box<File>;
    type ImplTy<'bcknd> = &'bcknd File;
}


pub(crate) trait BackendImpl<'elf> {
    fn read_pod_obj<T>(&self, offset: u64) -> Result<Cow<'elf, T>, Error>
    where
        T: Pod + 'elf;

    fn read_pod_slice<T>(&self, offset: u64, count: usize) -> Result<Cow<'elf, [T]>, Error>
    where
        T: Pod + 'elf;
}

impl<'elf> BackendImpl<'elf> for &'elf [u8] {
    fn read_pod_obj<T>(&self, offset: u64) -> Result<Cow<'elf, T>, Error>
    where
        T: Pod + 'elf,
    {
        let value = self
            .get(offset as _..)
            .ok_or_invalid_data(|| "failed to read data: invalid offset")?
            .read_pod_ref::<T>()
            .ok_or_invalid_data(|| "failed to read value")?;
        Ok(Cow::Borrowed(value))
    }

    fn read_pod_slice<T>(&self, offset: u64, count: usize) -> Result<Cow<'elf, [T]>, Error>
    where
        T: Pod + 'elf,
    {
        let value = self
            .get(offset as _..)
            .ok_or_invalid_data(|| "failed to read slice data: invalid offset")?
            .read_pod_slice_ref::<T>(count)
            .ok_or_invalid_data(|| "failed to read slice from mmap")?;
        Ok(Cow::Borrowed(value))
    }
}

impl<'elf> BackendImpl<'elf> for &File {
    fn read_pod_obj<T>(&self, offset: u64) -> Result<Cow<'elf, T>, Error>
    where
        T: Pod + 'elf,
    {
        let mut slf = *self;
        let _pos = slf.seek(SeekFrom::Start(offset))?;
        let obj = read_pod::<T, _>(&mut slf).map(Cow::Owned)?;
        Ok(obj)
    }

    fn read_pod_slice<T>(&self, offset: u64, count: usize) -> Result<Cow<'elf, [T]>, Error>
    where
        T: Pod + 'elf,
    {
        let mut slf = *self;
        let _pos = slf.seek(SeekFrom::Start(offset))?;
        let vec = read_pod_vec::<T, _>(&mut slf, count).map(Cow::Owned)?;
        Ok(vec)
    }
}


/// A parser for ELF64 files.
pub(crate) struct ElfParser<B = Mmap>
where
    B: Backend,
{
    /// A cache for relevant parts of the ELF file.
    // SAFETY: We must not hand out references with a 'static lifetime to
    //         this member. Rather, they should never outlive `self`.
    //         Furthermore, this member has to be listed before `_mmap`
    //         to make sure we never end up with a dangling reference.
    cache: Cache<'static, B::ImplTy<'static>>,
    /// The "module" that this parser represents.
    ///
    /// This can be an actual path or a more or less symbolic name.
    module: Option<OsString>,
    /// The backend used.
    _backend: B::ObjTy,
}

impl ElfParser<File> {
    /// Create an `ElfParser` that uses regular file I/O on the provided
    /// file.
    fn from_file_io(file: File, module: OsString) -> Self {
        let _backend = Box::new(file);
        let file_ref = unsafe { mem::transmute::<&File, &'static File>(_backend.deref()) };

        let parser = Self {
            cache: Cache::new(file_ref),
            module: Some(module),
            _backend,
        };
        parser
    }

    /// Create an `ElfParser` employing regular file I/O, opening the
    /// file at `path`.
    pub(crate) fn open_file_io<P>(path: &P) -> Result<Self>
    where
        P: ?Sized + PathLike,
    {
        fn open_impl(path: &Path, module: OsString) -> Result<ElfParser<File>> {
            let file =
                File::open(path).with_context(|| format!("failed to open `{}`", path.display()))?;
            let slf = ElfParser::from_file_io(file, module);
            Ok(slf)
        }

        let module = path.represented_path().as_os_str().to_os_string();
        let path = path.actual_path();
        open_impl(path, module)
    }

    /// Retrieve a reference to the backend in use.
    pub(crate) fn backend(&self) -> &File {
        &self._backend
    }
}

impl ElfParser<Mmap> {
    /// Create an `ElfParser` from an open file.
    pub(crate) fn from_file(file: &File, module: OsString) -> Result<Self> {
        let mmap = Mmap::map(file).context("failed to memory map file")?;
        Ok(Self::from_mmap(mmap, Some(module)))
    }

    /// Create an `ElfParser` from mmap'ed data.
    pub(crate) fn from_mmap(mmap: Mmap, module: Option<OsString>) -> Self {
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        let data = unsafe { mem::transmute::<&[u8], &'static [u8]>(mmap.deref()) };
        let _backend = mmap;

        let parser = Self {
            cache: Cache::new(data),
            module,
            _backend,
        };
        parser
    }

    /// Create an `ElfParser` for a path.
    pub(crate) fn open<P>(path: &P) -> Result<ElfParser>
    where
        P: ?Sized + PathLike,
    {
        fn open_impl(path: &Path, module: OsString) -> Result<ElfParser> {
            let file =
                File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
            ElfParser::from_file(&file, module)
        }

        let module = path.represented_path().as_os_str().to_os_string();
        let path = path.actual_path();
        open_impl(path, module)
    }
}

impl ElfParser<StaticMem> {
    /// Create an `ElfParser` from a region of static memory.
    pub(crate) fn from_mem(mem: StaticMem) -> Self {
        Self {
            cache: Cache::new(mem),
            // TODO: Should provide the module.
            module: None,
            _backend: mem,
        }
    }
}

impl<B> ElfParser<B>
where
    B: Backend,
{
    /// Retrieve the data corresponding to the ELF section at index
    /// `idx`, optionally decompressing it if it is compressed.
    pub(crate) fn section_data(&self, idx: usize) -> Result<&[u8]> {
        self.cache
            .section_data(idx)
            .with_context(|| format!("failed to read ELF section with index {idx}"))
    }

    /// Find the section of a given name.
    ///
    /// This function returns the index of the section if found.
    pub(crate) fn find_section(&self, name: &str) -> Result<Option<usize>> {
        let index = self.cache.find_section(name)?;
        Ok(index)
    }

    fn find_addr_impl<'slf>(
        &'slf self,
        name: &str,
        opts: &FindAddrOpts,
        shdrs: &ElfN_Shdrs<'_>,
        syms: &ElfN_Syms,
        strs: &'slf [u8],
        str2sym: &'slf [(SymName, usize)],
    ) -> Result<Vec<SymInfo<'slf>>> {
        let r = find_match_or_lower_bound_by_key(str2sym, name.as_bytes(), |(name, _i)| {
            name.bytes(strs)
        });
        match r {
            Some(idx) => {
                let mut found = vec![];
                for (name_visit, sym_i) in str2sym.iter().skip(idx) {
                    if name_visit.bytes(strs) != name.as_bytes() {
                        break
                    }
                    let sym_ref = &syms.get(*sym_i).ok_or_invalid_input(|| {
                        format!("ELF symbol table index ({sym_i}) out of bounds")
                    })?;
                    let sym = sym_ref.to_64bit();
                    if sym.st_shndx != SHN_UNDEF {
                        found.push(SymInfo {
                            name: Cow::Borrowed(name_visit.name(strs)?),
                            addr: sym.st_value,
                            size: Some(sym.st_size as usize),
                            // SANITY: We filter out all unsupported symbol
                            //         types, so this conversion should always
                            //         succeed.
                            sym_type: SymType::try_from(&sym).unwrap(),
                            file_offset: opts
                                .file_offset
                                .then(|| file_offset(shdrs, &sym))
                                .transpose()?
                                .flatten(),
                            module: self.module.as_deref().map(Cow::Borrowed),
                            _non_exhaustive: (),
                        });
                    }
                }
                Ok(found)
            }
            None => Ok(vec![]),
        }
    }

    pub(crate) fn find_addr<'slf>(
        &'slf self,
        name: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymInfo<'slf>>> {
        let shdrs = self.cache.ensure_shdrs()?;
        let cache = self.cache.ensure_symtab_cache()?;
        let symtab = &cache.syms;
        let strs = &cache.strs;
        let str2symtab = self.cache.ensure_str2symtab()?;
        let syms = self.find_addr_impl(name, opts, shdrs, symtab, strs, str2symtab)?;
        if !syms.is_empty() {
            return Ok(syms)
        }

        let cache = self.cache.ensure_dynsym_cache()?;
        let dynsym = &cache.syms;
        let strs = &cache.strs;
        let str2dynsym = self.cache.ensure_str2dynsym()?;
        let syms = self.find_addr_impl(name, opts, shdrs, dynsym, strs, str2dynsym)?;
        Ok(syms)
    }

    fn for_each_sym_impl(
        &self,
        opts: &FindAddrOpts,
        syms: &ElfN_Syms<'_>,
        strs: &[u8],
        str2sym: &[(SymName, usize)],
        f: &mut ForEachFn<'_>,
    ) -> Result<()> {
        let shdrs = self.cache.ensure_shdrs()?;

        for (name, idx) in str2sym {
            let sym = &syms
                .get(*idx)
                .ok_or_invalid_input(|| format!("symbol table index ({idx}) out of bounds"))?;
            let sym = sym.to_64bit();

            if sym.matches(opts.sym_type) && sym.st_shndx != SHN_UNDEF {
                let sym_info = SymInfo {
                    name: Cow::Borrowed(name.name(strs)?),
                    addr: sym.st_value,
                    size: Some(sym.st_size as usize),
                    // SANITY: We filter out all unsupported symbol
                    //         types, so this conversion should always
                    //         succeed.
                    sym_type: SymType::try_from(&sym).unwrap(),
                    file_offset: opts
                        .file_offset
                        .then(|| file_offset(shdrs, &sym))
                        .transpose()?
                        .flatten(),
                    module: None,
                    _non_exhaustive: (),
                };
                if let ControlFlow::Break(()) = f(&sym_info) {
                    return Ok(())
                }
            }
        }

        Ok(())
    }

    /// Perform an operation on each symbol.
    #[allow(clippy::needless_borrows_for_generic_args)]
    pub(crate) fn for_each(&self, opts: &FindAddrOpts, f: &mut ForEachFn) -> Result<()> {
        let cache = self.cache.ensure_symtab_cache()?;
        let symtab = &cache.syms;
        let strs = &cache.strs;
        let str2symtab = self.cache.ensure_str2symtab()?;
        let () = self.for_each_sym_impl(opts, symtab, strs, str2symtab, f)?;

        let cache = self.cache.ensure_dynsym_cache()?;
        let dynsym = &cache.syms;
        let strs = &cache.strs;
        let str2dynsym = self.cache.ensure_str2dynsym()?;
        let () = self.for_each_sym_impl(opts, dynsym, strs, str2dynsym, f)?;

        Ok(())
    }

    /// Find the file offset of the symbol at address `addr`.
    // If possible, use the constant-time [`file_offset`] function
    // instead.
    pub(crate) fn find_file_offset(&self, addr: Addr, size: usize) -> Result<Option<u64>> {
        let phdrs = self.program_headers()?;
        let offset = phdrs.iter(0).find_map(|phdr| {
            let phdr = phdr.to_64bit();

            if phdr.p_type == PT_LOAD {
                let limit = phdr.p_vaddr + phdr.p_filesz;
                if (phdr.p_vaddr..limit).contains(&addr) || (addr == limit && size == 0) {
                    return Some(addr - phdr.p_vaddr + phdr.p_offset)
                }
            }
            None
        });
        Ok(offset)
    }

    #[cfg(test)]
    fn get_symbol_name(&self, idx: usize) -> Result<&str> {
        let symtab_cache = self.cache.ensure_symtab_cache()?;
        let sym = self.cache.symbol(idx)?;
        let name = symbol_name(&symtab_cache.strs, &sym.to_64bit())?;
        Ok(name)
    }

    pub(crate) fn section_headers(&self) -> Result<&ElfN_Shdrs<'_>> {
        let shdrs = self.cache.ensure_shdrs()?;
        Ok(shdrs)
    }

    pub(crate) fn program_headers(&self) -> Result<&ElfN_Phdrs<'_>> {
        let phdrs = self.cache.ensure_phdrs()?;
        Ok(phdrs)
    }

    /// Translate a file offset into a virtual offset.
    pub(crate) fn file_offset_to_virt_offset(&self, offset: u64) -> Result<Option<Addr>> {
        let phdrs = self.program_headers()?;
        let addr = phdrs.iter(0).find_map(|phdr| {
            let phdr = phdr.to_64bit();
            if phdr.p_type == PT_LOAD {
                if (phdr.p_offset..phdr.p_offset + phdr.p_filesz).contains(&offset) {
                    return Some(offset - phdr.p_offset + phdr.p_vaddr)
                }
            }
            None
        });

        Ok(addr)
    }

    #[cfg(test)]
    fn pick_symtab_addr(&self) -> (&str, Addr, usize) {
        let cache = self.cache.ensure_symtab_cache().unwrap();
        let by_addr_idx = cache.ensure_by_addr_idx();

        let mut idx = by_addr_idx.len() / 2;
        let (addr, size) = loop {
            let sym = cache.syms.get(by_addr_idx[idx]).unwrap();
            if sym.matches(SymType::Function) {
                if let Some(idx_) = idx.checked_sub(1).and_then(|idx| by_addr_idx.get(idx)) {
                    let sym_ = cache.syms.get(*idx_).unwrap();
                    if sym_.value() == sym.value() {
                        idx += 1;
                        continue
                    }
                }
                if let Some(idx_) = idx.checked_add(1).and_then(|idx| by_addr_idx.get(idx)) {
                    let sym_ = cache.syms.get(*idx_).unwrap();
                    if sym_.value() == sym.value() {
                        idx += 1;
                        continue
                    }
                }
                if sym.shndx() != SHN_UNDEF {
                    break (sym.value(), sym.size())
                }
            }
            idx += 1;
        };

        let idx = by_addr_idx.get(idx).unwrap();
        let sym_name = self.get_symbol_name(*idx).unwrap();
        (sym_name, addr, usize::try_from(size).unwrap_or(usize::MAX))
    }

    pub(crate) fn cache(&self) -> Result<()> {
        let _cache = self.cache.ensure_symtab_cache()?;
        let _str2symtab = self.cache.ensure_str2symtab()?;
        let _cache = self.cache.ensure_dynsym_cache()?;
        let _str2dynsym = self.cache.ensure_str2dynsym()?;
        Ok(())
    }

    /// Retrieve the path to the file this object operates on.
    #[inline]
    pub(crate) fn module(&self) -> Option<&OsStr> {
        self.module.as_deref()
    }
}

// TODO: Ideally we wouldn't have to implement this trait for this type,
//       but right now we need it because `ElfResolver` is not generic
//       over the backend in use.
impl<B> Symbolize for ElfParser<B>
where
    B: Backend,
{
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        // ELF doesn't carry any source code or inlining information.
        let _opts = opts;

        let symtab_cache = self.cache.ensure_symtab_cache()?;
        let symtab_by_addr_idx = symtab_cache.ensure_by_addr_idx();

        if let Some(sym) = find_sym(
            &symtab_cache.syms,
            self.module.as_deref(),
            symtab_by_addr_idx,
            &symtab_cache.strs,
            addr,
            SymType::Undefined,
        )? {
            return Ok(Ok(sym))
        }

        let dynsym_cache = self.cache.ensure_dynsym_cache()?;
        let dynsym_by_addr_idx = dynsym_cache.ensure_by_addr_idx();
        if let Some(sym) = find_sym(
            &dynsym_cache.syms,
            self.module.as_deref(),
            dynsym_by_addr_idx,
            &dynsym_cache.strs,
            addr,
            SymType::Undefined,
        )? {
            return Ok(Ok(sym))
        }

        // At this point we haven't found a symbol for the given
        // address. The emptiness of `dynsym` has no bearing on the
        // reason we report -- for all intents and purposes it is either
        // required or not at all necessary.
        let reason = if symtab_cache.syms.is_empty() {
            Reason::MissingSyms
        } else {
            Reason::UnknownAddr
        };
        Ok(Err(reason))
    }
}

impl<B> Debug for ElfParser<B>
where
    B: Backend,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let module = self
            .module
            .as_deref()
            .unwrap_or_else(|| OsStr::new("<unknown>"));
        write!(f, "ElfParser({module:?})")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use super::super::types::SHN_LORESERVE;

    use std::env::current_exe;
    #[cfg(feature = "nightly")]
    use std::hint::black_box;
    use std::io::Write as _;
    use std::mem::size_of;
    use std::path::Path;
    use std::slice;

    use miniz_oxide::deflate::compress_to_vec_zlib;

    use tempfile::NamedTempFile;

    use test_log::test;
    use test_tag::tag;

    #[cfg(feature = "nightly")]
    use test::Bencher;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let ehdr = Elf64_Ehdr {
            e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            e_type: 3,
            e_machine: 62,
            e_version: 1,
            e_entry: 4208,
            e_phoff: 64,
            e_shoff: size_of::<Elf64_Ehdr>() as _,
            e_flags: 0,
            e_ehsize: 64,
            e_phentsize: 56,
            e_phnum: PN_XNUM,
            e_shentsize: 64,
            e_shnum: 0,
            e_shstrndx: 29,
        };
        let ehdr = EhdrExt {
            ehdr: ElfN_Ehdr::B64(Cow::Borrowed(&ehdr)),
            shnum: 42,
            phnum: 0,
        };
        assert_ne!(format!("{ehdr:?}"), "");

        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        assert_ne!(format!("{parser:?}"), "");
    }

    /// Check that we can read Pod style objects from a reader without
    /// triggering undefined behavior.
    #[tag(miri)]
    #[test]
    fn pod_obj_reading() {
        #[repr(C)]
        #[derive(Clone, Debug)]
        struct Foo {
            x: u32,
            y: u8,
            z: u64,
        }

        unsafe impl Pod for Foo {}

        let buf = [42u8; mem::size_of::<Foo>()];
        let foo = read_pod::<Foo, _>(&mut buf.as_slice()).unwrap();
        assert_eq!(foo.y, 42);

        let buf = [42u8; 2 * mem::size_of::<Foo>()];
        let vec = read_pod_vec::<Foo, _>(&mut buf.as_slice(), 2).unwrap();
        assert_eq!(vec[0].y, 42);
        assert_eq!(vec[1].y, 42);
    }

    /// Check that our `ElfParser` can handle more than 0xff00 section
    /// headers and more than 0xffff program headers properly.
    #[test]
    fn excessive_section_and_program_headers() {
        const SHNUM: u16 = SHN_LORESERVE + 0x42;
        const PHNUM: u32 = 0xffff + 0x43;

        #[repr(C)]
        struct Elf {
            ehdr: Elf64_Ehdr,
            shdrs: [Elf64_Shdr; 2],
        }

        // Data extracted from an actual binary; section header related
        // information adjusted.
        let elf = Elf {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: 64,
                e_shoff: size_of::<Elf64_Ehdr>() as _,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: PN_XNUM,
                e_shentsize: 64,
                e_shnum: 0,
                e_shstrndx: 29,
            },
            shdrs: [
                Elf64_Shdr {
                    sh_name: 0,
                    sh_type: 0,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: 0,
                    sh_size: SHNUM.into(),
                    sh_link: 0,
                    sh_info: PHNUM,
                    sh_addralign: 0,
                    sh_entsize: 0,
                },
                Elf64_Shdr {
                    sh_name: 27,
                    sh_type: 1,
                    sh_flags: 2,
                    sh_addr: 792,
                    sh_offset: 792,
                    sh_size: 28,
                    sh_link: 0,
                    sh_info: 0,
                    sh_addralign: 1,
                    sh_entsize: 0,
                },
            ],
        };

        let mut file = NamedTempFile::new().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        fn test<B>(parser: ElfParser<B>)
        where
            B: Backend,
        {
            let ehdr = parser.cache.ensure_ehdr().unwrap();
            assert_eq!(ehdr.shnum, usize::from(SHNUM));
            assert_eq!(ehdr.phnum, usize::try_from(PHNUM).unwrap());
        }

        let module = file.path().as_os_str().to_os_string();
        let parser_mmap = ElfParser::from_file(file.as_file(), module.clone()).unwrap();
        let () = test(parser_mmap);

        let parser_io = ElfParser::from_file_io(file.into_file(), module);
        let () = test(parser_io);
    }

    /// Test that our `ElfParser` can handle a `shstrndx` larger than
    /// 0xff00.
    #[test]
    fn large_e_shstrndx() {
        const SHSTRNDX: u16 = SHN_LORESERVE + 0x42;

        #[repr(C)]
        struct Elf {
            ehdr: Elf64_Ehdr,
            shdrs: [Elf64_Shdr; 1],
        }

        // Data extracted from an actual binary; `e_shstrndx` related
        // information adjusted.
        let elf = Elf {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: 64,
                e_shoff: size_of::<Elf64_Ehdr>() as _,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: 13,
                e_shentsize: 64,
                e_shnum: 0,
                e_shstrndx: SHN_XINDEX,
            },
            shdrs: [Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: SHSTRNDX.into(),
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            }],
        };

        let mut file = NamedTempFile::new().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        fn test<B>(parser: ElfParser<B>)
        where
            B: Backend,
        {
            let ehdr = parser.cache.ensure_ehdr().unwrap();
            let shstrndx = parser.cache.shstrndx(&ehdr.ehdr).unwrap();
            assert_eq!(shstrndx, usize::from(SHSTRNDX));
        }

        let module = file.path().as_os_str().to_os_string();
        let parser_mmap = ElfParser::from_file(file.as_file(), module.clone()).unwrap();
        let () = test(parser_mmap);

        let parser_io = ElfParser::from_file_io(file.into_file(), module);
        let () = test(parser_io);
    }


    #[test]
    fn test_elf64_parser() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());
    }

    #[test]
    fn test_elf64_symtab() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (name, addr, size) = parser.pick_symtab_addr();

        let sym = parser.find_sym(addr, &FindSymOpts::Basic).unwrap().unwrap();
        assert_eq!(sym.addr, addr);
        assert_eq!(sym.name, name);
        assert!(sym.size.is_none() && size == 0 || sym.size.unwrap() == size);
    }

    #[test]
    fn elf64_lookup_symbol_random() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-no-debug.bin");

        let parser = ElfParser::open(bin_name.as_path()).unwrap();
        assert!(parser.find_section(".shstrtab").is_ok());

        let (name, addr, size) = parser.pick_symtab_addr();

        println!("{name}");
        let opts = FindAddrOpts::default();
        let addr_r = parser.find_addr(name, &opts).unwrap();
        assert_eq!(addr_r.len(), 1);
        assert!(addr_r
            .iter()
            .any(|x| x.addr == addr && x.size == Some(size)));
    }

    /// Validate our two methods of symbol file offset calculation against each
    /// other.
    #[test]
    fn file_offset_calculation() {
        fn test(path: &Path) {
            let opts = FindAddrOpts {
                file_offset: true,
                sym_type: SymType::Function,
            };
            let parser = ElfParser::open(path).unwrap();
            let () = parser
                .for_each(&opts, &mut |sym| {
                    let file_offset = parser
                        .find_file_offset(sym.addr, sym.size.unwrap())
                        .unwrap();
                    assert_eq!(sym.file_offset, file_offset, "{sym:#x?}");
                    ControlFlow::Continue(())
                })
                .unwrap();
        }

        let exe = current_exe().unwrap();
        test(&exe);

        let so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        test(&so);
    }

    /// Check that we don't underflow during file offset calculation.
    #[test]
    fn file_offset_underflow() {
        let shdrs = [
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0x2e0,
                sh_offset: 0x2e0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        ];
        let shdrs = ElfN_Shdrs::B64(Cow::Borrowed(shdrs.as_slice()));

        let sym = Elf64_Sym {
            st_name: 0x0,
            st_info: 0x0,
            st_other: 0x0,
            st_shndx: 1,
            st_value: 0x0,
            st_size: 0x0,
        };

        let offset = file_offset(&shdrs, &sym).unwrap().unwrap();
        assert_eq!(offset, 0);
    }

    /// Check that we can correctly convert a file offset into a virtual
    /// offset.
    ///
    /// This is a regression test for the case that a program header
    /// with a memory size greater than file size is located before a
    /// program header that would otherwise match the file offset. Refer
    /// to commit 1a4e10740652 ("Use file size in file offset -> virtual
    /// offset translation").
    #[test]
    fn virtual_offset_calculation() {
        #[repr(C)]
        struct Elf {
            ehdr: Elf64_Ehdr,
            phdrs: [Elf64_Phdr; 2],
        }

        // Data is mostly made up, except for relevant program headers,
        // which were copied from a real binary.
        let elf = Elf {
            ehdr: Elf64_Ehdr {
                e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                e_type: 3,
                e_machine: 62,
                e_version: 1,
                e_entry: 4208,
                e_phoff: size_of::<Elf64_Ehdr>() as _,
                e_shoff: 0,
                e_flags: 0,
                e_ehsize: 64,
                e_phentsize: 56,
                e_phnum: 2,
                e_shentsize: 0,
                e_shnum: 1,
                e_shstrndx: 0,
            },
            phdrs: [
                Elf64_Phdr {
                    p_type: 1,
                    p_flags: 6,
                    p_offset: 455231872,
                    p_vaddr: 457337216,
                    p_paddr: 457337216,
                    p_filesz: 3422344,
                    p_memsz: 13261132,
                    p_align: 4096,
                },
                Elf64_Phdr {
                    p_type: 1,
                    p_flags: 5,
                    p_offset: 459276288,
                    p_vaddr: 471859200,
                    p_paddr: 471859200,
                    p_filesz: 77813932,
                    p_memsz: 77813932,
                    p_align: 2097152,
                },
            ],
        };

        let mut file = NamedTempFile::new().unwrap();
        let dump =
            unsafe { slice::from_raw_parts((&elf as *const Elf).cast::<u8>(), size_of::<Elf>()) };
        let () = file.write_all(dump).unwrap();
        let () = file.rewind().unwrap();

        fn test<B>(parser: ElfParser<B>)
        where
            B: Backend,
        {
            // A file offset as produced by normalization.
            let file_offset = 0x1b63b4d0;
            let virt_offset = parser
                .file_offset_to_virt_offset(file_offset)
                .unwrap()
                .unwrap();
            assert_eq!(virt_offset, 0x1c23b4d0);
        }

        let module = file.path().as_os_str().to_os_string();
        let parser_mmap = ElfParser::from_file(file.as_file(), module.clone()).unwrap();
        let () = test(parser_mmap);

        let parser_io = ElfParser::from_file_io(file.into_file(), module);
        let () = test(parser_io);
    }

    /// Make sure that we can look up a symbol in an ELF file.
    #[test]
    fn lookup_symbol() {
        fn test(path: &Path) {
            let parser = ElfParser::open(path).unwrap();
            let opts = FindAddrOpts::default();
            let syms = parser.find_addr("factorial", &opts).unwrap();
            assert_eq!(syms.len(), 1);
            let sym = &syms[0];
            assert_eq!(sym.name, "factorial");
            assert_eq!(sym.addr, 0x2000200);

            let syms = parser.find_addr("factorial_wrapper", &opts).unwrap();
            assert_eq!(syms.len(), 2);
            assert_eq!(syms[0].name, "factorial_wrapper");
            assert_eq!(syms[1].name, "factorial_wrapper");
            assert_ne!(syms[0].addr, syms[1].addr);
        }

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-no-dwarf.bin");
        let () = test(&path);

        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs-32-no-dwarf.bin");
        let () = test(&path);
    }

    /// Make sure that we do not report a symbol if there is no conceivable
    /// match.
    #[test]
    fn lookup_symbol_without_match() {
        let strs = b"\x00_glapi_tls_Context\x00_glapi_get_dispatch_table_size\x00";
        let syms = ElfN_Syms::B64(Cow::Borrowed(&[
            Elf64_Sym {
                st_name: 0x21,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xe,
                st_value: 0x1a4a0,
                st_size: 0xa,
            },
            Elf64_Sym {
                st_name: 0x1,
                // Note: the type is *not* `STT_FUNC`.
                st_info: 0x16,
                st_other: 0x0,
                st_shndx: 0x14,
                st_value: 0x8,
                st_size: 0x8,
            },
            Elf64_Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
        ]));
        let by_addr_idx = [2, 1, 0];

        let result = find_sym(&syms, None, &by_addr_idx, strs, 0x10d20, SymType::Function).unwrap();
        assert_eq!(result, None);
    }

    /// Check that we report a symbol with an unknown `st_size` value is
    /// reported, if it is the only conceivable match.
    #[test]
    fn lookup_symbol_with_unknown_size() {
        fn test(syms: &ElfN_Syms<'_>, by_addr_idx: &[usize]) {
            let strs = b"\x00__libc_init_first\x00versionsort64\x00";
            let sym = find_sym(syms, None, by_addr_idx, strs, 0x29d00, SymType::Function)
                .unwrap()
                .unwrap();
            assert_eq!(sym.name, "__libc_init_first");
            assert_eq!(sym.addr, 0x29d00);
            assert_eq!(sym.size, None);

            // Because the symbol has a size of 0 and is the only conceivable
            // match, we report it on the basis that ELF reserves these for "no
            // size or an unknown size" cases.
            let sym = find_sym(syms, None, by_addr_idx, strs, 0x29d90, SymType::Function)
                .unwrap()
                .unwrap();
            assert_eq!(sym.name, "__libc_init_first");
            assert_eq!(sym.addr, 0x29d00);
            assert_eq!(sym.size, None);

            // Note that despite of the first symbol (the invalid one; present
            // by default and reserved by ELF), is not being reported here
            // because it has an `st_shndx` value of `SHN_UNDEF`.
            let result = find_sym(syms, None, by_addr_idx, strs, 0x1, SymType::Function).unwrap();
            assert_eq!(result, None);
        }

        let syms = ElfN_Syms::B64(Cow::Borrowed(&[
            Elf64_Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Elf64_Sym {
                st_name: 0xdeadbeef,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xf,
                st_value: 0x29dc0,
                st_size: 0x148,
            },
            Elf64_Sym {
                st_name: 0x1,
                st_info: 0x12,
                st_other: 0x0,
                st_shndx: 0xf,
                st_value: 0x29d00,
                st_size: 0x0,
            },
        ]));
        let by_addr_idx = [0, 2, 1];

        test(&syms, &by_addr_idx);
        test(&syms, &by_addr_idx[0..2]);
    }

    /// Check that we can properly read empty symbol tables, even if not
    /// correctly aligned, as long as it is empty.
    #[test]
    fn empty_symbol_table_reading() {
        let ehdr = Elf64_Ehdr {
            e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            e_type: 3,
            e_machine: 62,
            e_version: 1,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 3,
            e_shstrndx: 1,
        };
        let ehdr = EhdrExt {
            ehdr: ElfN_Ehdr::B64(Cow::Borrowed(&ehdr)),
            shnum: 3,
            phnum: 0,
        };
        let shdrs = [
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            Elf64_Shdr {
                sh_name: 10,
                // The section contains no actual data.
                sh_type: SHT_NOBITS,
                sh_flags: 0,
                sh_addr: 0,
                // One byte into an aligned buffer we will always end up at an
                // unaligned address. This should result in a failed read of an
                // Elf64_Sym slice, if we were to actually read data (which we
                // should not).
                sh_offset: 1,
                sh_size: mem::size_of::<Elf64_Sym>() as _,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        ];
        let mut aligned_data = [0u8; 1024].as_slice();
        let () = aligned_data.align(8).unwrap();

        let cache = Cache {
            backend: aligned_data,
            ehdr: OnceCell::from(ehdr),
            shdrs: OnceCell::from(ElfN_Shdrs::B64(Cow::Borrowed(shdrs.as_slice()))),
            shstrtab: OnceCell::from(Cow::Borrowed(b".shstrtab\x00.symtab\x00".as_slice())),
            phdrs: OnceCell::new(),
            symtab: OnceCell::new(),
            dynsym: OnceCell::new(),
            section_data: OnceCell::new(),
        };

        assert_eq!(cache.find_section(".symtab").unwrap(), Some(2));

        let symtab = cache.ensure_symtab().unwrap();
        assert!(symtab.is_empty());
    }

    /// Check that we can decompress ELF section data with an unaligned
    /// compression header.
    #[test]
    fn unaligned_compression_header_reading() {
        let ehdr = Elf64_Ehdr {
            e_ident: [127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            e_type: 3,
            e_machine: 62,
            e_version: 1,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 2,
            e_shstrndx: 1,
        };
        let ehdr = EhdrExt {
            ehdr: ElfN_Ehdr::B64(Cow::Borrowed(&ehdr)),
            shnum: 2,
            phnum: 0,
        };

        let data = [];
        let zlib_hdr = compress_to_vec_zlib(&data, 0);
        let chdr = Elf64_Chdr {
            ch_type: ELFCOMPRESS_ZLIB,
            ch_reserved: 0,
            ch_size: 0,
            ch_addralign: 1,
        };
        let shdrs = [
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
            Elf64_Shdr {
                sh_name: 0,
                sh_type: 0,
                sh_flags: SHF_COMPRESSED,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: (mem::size_of_val(&chdr) + zlib_hdr.len()) as _,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            },
        ];

        let mut aligned_data = [0u64; 128];

        // Write a compression header at an unaligned address, followed
        // by the zlib data.
        let () = unsafe {
            aligned_data
                .as_mut_ptr()
                .cast::<u8>()
                .add(1)
                .cast::<Elf64_Chdr>()
                .write_unaligned(chdr)
        };
        let () = unsafe {
            aligned_data
                .as_mut_ptr()
                .cast::<u8>()
                .add(1)
                .add(mem::size_of::<Elf64_Chdr>())
                .copy_from(zlib_hdr.as_ptr(), zlib_hdr.len())
        };
        let aligned_data = unsafe {
            slice::from_raw_parts(
                aligned_data.as_ptr().cast::<u8>(),
                aligned_data.len() * size_of_val(&aligned_data[0]),
            )
        };
        let unaligned_data = &aligned_data[1..];

        let cache = Cache {
            backend: unaligned_data,
            ehdr: OnceCell::from(ehdr),
            shdrs: OnceCell::from(ElfN_Shdrs::B64(Cow::Borrowed(shdrs.as_slice()))),
            shstrtab: OnceCell::from(Cow::Borrowed(b".debug_info\x00".as_slice())),
            phdrs: OnceCell::new(),
            symtab: OnceCell::new(),
            dynsym: OnceCell::new(),
            section_data: OnceCell::from(vec![OnceCell::new(), OnceCell::new()].into_boxed_slice()),
        };

        let new_data = cache.section_data(1).unwrap();
        assert_eq!(new_data, data);
    }

    /// Benchmark creation of our "str2symtab" table.
    ///
    /// Creating this table exercises a lot of the parser code paths and
    /// is expected to be a somewhat reasonable approximation of overall
    /// end-to-end performance.
    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_str2sym_creation(b: &mut Bencher) {
        let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("vmlinux-5.17.12-100.fc34.x86_64.elf");
        let parser = ElfParser::open(path.as_path()).unwrap();
        let mmap = &parser._backend;

        // Our memory mapping is created only once and criterion does a
        // few warm up runs that should make sure that everything is
        // paged in. So we expect to benchmark parsing & data structure
        // traversing performance here.

        let () = b.iter(|| {
            let cache = Cache::new(mmap.deref());
            let syms = cache.ensure_str2symtab().unwrap();
            let _syms = black_box(syms);
        });
    }
}
