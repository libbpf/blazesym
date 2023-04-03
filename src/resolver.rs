use std::ffi::OsStr;
use std::fmt::Debug;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::cfg;
use crate::elf::ElfBackend;
use crate::elf::ElfCache;
use crate::elf::ElfParser;
use crate::elf::ElfResolver;
use crate::gsym::GsymResolver;
use crate::kernel::KernelResolver;
use crate::ksym::KSymCache;
use crate::ksym::KALLSYMS;
use crate::log;
use crate::maps;
use crate::maps::Pid;
use crate::util;
use crate::util::uname_release;
use crate::zip;
use crate::Addr;
use crate::AddressLineInfo;
use crate::FindAddrOpts;
use crate::SymbolInfo;
use crate::SymbolSrcCfg;


fn create_apk_elf_path(apk: &Path, elf: &Path) -> Result<PathBuf> {
    let mut extension = apk
        .extension()
        .unwrap_or_else(|| OsStr::new("apk"))
        .to_os_string();
    // Append '!' to indicate separation from archive internal contents
    // that follow. This is an Android convention.
    let () = extension.push("!");

    let mut apk = apk.to_path_buf();
    if !apk.set_extension(extension) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("path {} is not valid", apk.display()),
        ))
    }

    let path = apk.join(elf);
    Ok(path)
}


/// The trait of symbol resolvers.
///
/// An symbol resolver usually provides information from one symbol
/// source; e.g., a symbol file.
pub(crate) trait SymResolver
where
    Self: Debug,
{
    /// Return the range that this resolver serves in an address space.
    fn get_address_range(&self) -> (Addr, Addr);
    /// Find the names and the start addresses of a symbol found for
    /// the given address.
    fn find_symbols(&self, addr: Addr) -> Vec<(&str, Addr)>;
    /// Find the address and size of a symbol name.
    fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the addresses and sizes of the symbols matching a given pattern.
    fn find_address_regex(&self, pattern: &str, opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>>;
    /// Find the file name and the line number of an address.
    fn find_line_info(&self, addr: Addr) -> Option<AddressLineInfo>;
    /// Translate an address (virtual) in a process to the file offset
    /// in the object file.
    fn addr_file_off(&self, addr: Addr) -> Option<u64>;
    /// Get the file name of the shared object.
    fn get_obj_file_name(&self) -> &Path;
}


type ResolverList = Vec<((Addr, Addr), Box<dyn SymResolver>)>;


pub(crate) struct ResolverMap {
    pub resolvers: ResolverList,
}

impl ResolverMap {
    fn build_resolvers_proc_maps(
        pid: Pid,
        resolvers: &mut ResolverList,
        elf_cache: &ElfCache,
    ) -> Result<()> {
        let entries = maps::parse(pid)?;
        for entry in entries {
            let entry = entry?;
            if maps::is_symbolization_relevant(&entry) {
                let extension = entry.path.extension().unwrap_or_else(|| OsStr::new(""));
                log::trace!("processing proc maps entry: {entry:#x?}");
                if extension == OsStr::new("apk") || extension == OsStr::new("zip") {
                    let () = Self::create_apk_resolvers(
                        &entry.path,
                        entry.range.start - entry.offset as usize,
                        resolvers,
                    )?;
                } else {
                    let backend = elf_cache.find(&entry.path)?;
                    let resolver = ElfResolver::new(&entry.path, entry.range.start, backend)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
            }
        }

        Ok(())
    }

    fn create_elf_resolver(cfg: &cfg::Elf, elf_cache: &ElfCache) -> Result<ElfResolver> {
        let cfg::Elf {
            file_name,
            base_address,
        } = cfg;

        let backend = elf_cache.find(file_name)?;
        let resolver = ElfResolver::new(file_name, *base_address, backend)?;
        Ok(resolver)
    }

    fn create_kernel_resolver(
        cfg: &cfg::Kernel,
        ksym_cache: &KSymCache,
        elf_cache: &ElfCache,
    ) -> Result<KernelResolver> {
        let cfg::Kernel {
            kallsyms,
            kernel_image,
        } = cfg;

        let ksym_resolver = if let Some(kallsyms) = kallsyms {
            let ksym_resolver = ksym_cache.get_resolver(kallsyms)?;
            Some(ksym_resolver)
        } else {
            let kallsyms = Path::new(KALLSYMS);
            let result = ksym_cache.get_resolver(kallsyms);
            match result {
                Ok(resolver) => Some(resolver),
                Err(err) => {
                    log::warn!(
                        "failed to load kallsyms from {}: {err}; ignoring...",
                        kallsyms.display()
                    );
                    None
                }
            }
        };

        let elf_resolver = if let Some(image) = kernel_image {
            let backend = elf_cache.find(image)?;
            let elf_resolver = ElfResolver::new(image, 0, backend)?;
            Some(elf_resolver)
        } else {
            let release = uname_release()?.to_str().unwrap().to_string();
            let basename = "vmlinux-";
            let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
            let kernel_image = dirs.iter().find_map(|dir| {
                let path = dir.join(format!("{basename}{release}"));
                path.exists().then_some(path)
            });

            if let Some(image) = kernel_image {
                let result = elf_cache.find(&image);
                match result {
                    Ok(backend) => {
                        let result = ElfResolver::new(&image, 0, backend);
                        match result {
                            Ok(resolver) => Some(resolver),
                            Err(err) => {
                                log::warn!("failed to create ELF resolver for kernel image {}: {err}; ignoring...", image.display());
                                None
                            }
                        }
                    }
                    Err(err) => {
                        log::warn!(
                            "failed to load kernel image {}: {err}; ignoring...",
                            image.display()
                        );
                        None
                    }
                }
            } else {
                None
            }
        };

        let resolver = KernelResolver::new(ksym_resolver, elf_resolver)?;
        Ok(resolver)
    }

    fn create_apk_resolvers(
        path: &Path,
        base_address: Addr,
        resolvers: &mut ResolverList,
    ) -> Result<()> {
        // An APK is nothing but a fancy zip archive.
        let apk = zip::Archive::open(path)?;

        let () = apk.entries().try_for_each(|entry| {
            let entry = entry?;
            let parser = ElfParser::from_mmap(apk.mmap(), entry.data_offset)?;
            let backend = ElfBackend::Elf(Rc::new(parser));
            let path = create_apk_elf_path(path, entry.path)?;
            let result = ElfResolver::new(&path, base_address + entry.data_offset, backend);
            // TODO: This kind of eager processing of APK entries is a
            //       kludge, but required by the current library design.
            //       Once we decouple of resolvers from the base address
            //       and make everything work with normalized addresses
            //       we should only need to symbolize files in which
            //       addresses were recorded, which eliminates this
            //       weird ignoring of errors.
            match result {
                Ok(resolver) => {
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                Err(err) => {
                    log::debug!(
                        "ignoring entry {} of {}: {err}",
                        entry.path.display(),
                        path.display()
                    );
                }
            }
            Result::Ok(())
        })?;
        Ok(())
    }

    pub fn new(
        sym_srcs: &[SymbolSrcCfg],
        ksym_cache: &KSymCache,
        elf_cache: &ElfCache,
    ) -> Result<ResolverMap> {
        let mut resolvers = ResolverList::new();
        for cfg in sym_srcs {
            match cfg {
                SymbolSrcCfg::Elf(elf) => {
                    let resolver = Self::create_elf_resolver(elf, elf_cache)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Kernel(kernel) => {
                    let resolver = Self::create_kernel_resolver(kernel, ksym_cache, elf_cache)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
                SymbolSrcCfg::Process(cfg::Process { pid }) => {
                    let pid = Pid::from(pid.unwrap_or(0));
                    let () = Self::build_resolvers_proc_maps(pid, &mut resolvers, elf_cache)?;
                }
                SymbolSrcCfg::Gsym(cfg::Gsym {
                    file_name,
                    base_address,
                }) => {
                    let resolver = GsymResolver::new(file_name.clone(), *base_address)?;
                    let () = resolvers.push((resolver.get_address_range(), Box::new(resolver)));
                }
            }
        }
        resolvers.sort_by_key(|x| x.0 .0); // sorted by the loaded addresses

        log::debug!("built resolver list: {resolvers:#x?}");
        Ok(ResolverMap { resolvers })
    }

    pub fn find_resolver(&self, address: Addr) -> Option<&dyn SymResolver> {
        let idx = util::find_match_or_lower_bound_by(&self.resolvers, address, |x| x.0 .0)?;
        let (loaded_begin, loaded_end) = self.resolvers[idx].0;
        if loaded_begin != loaded_end && address >= loaded_end {
            // `begin == end` means this ELF file may have only
            // symbols and debug information.  For this case, we
            // always use this resolver if the given address is just
            // above its loaded address.
            None
        } else {
            Some(self.resolvers[idx].1.as_ref())
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::mem::transmute;

    use test_log::test;

    use crate::elf::ElfParser;
    use crate::mmap::Mmap;
    use crate::zip;
    use crate::BlazeSymbolizer;
    use crate::SymbolType;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf).unwrap();
        assert_eq!(path, Path::new("/root/test.apk!/subdir/libc.so"));
    }

    /// Check that we can symbolize an address using DWARF.
    #[test]
    fn symbolize_apk() {
        let test_apk = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test.zip");

        let mmap = Mmap::builder().exec().open(test_apk).unwrap();
        let mmap = Rc::new(mmap);
        let archive = zip::Archive::with_mmap(mmap.clone()).unwrap();
        let so = archive
            .entries()
            .find_map(|entry| {
                let entry = entry.unwrap();
                (entry.path == Path::new("libtest-so.so")).then_some(entry)
            })
            .unwrap();

        // We found the ELF shared object inside the archive. Now look
        // up the address of the `the_answer` function inside of it.
        let elf_parser = ElfParser::from_mmap(mmap.clone(), so.data_offset).unwrap();
        let opts = FindAddrOpts {
            sym_type: SymbolType::Function,
            ..Default::default()
        };
        let symbols = elf_parser.find_address("the_answer", &opts).unwrap();
        // There is only one symbol with this address in the shared
        // object.
        assert_eq!(symbols.len(), 1);
        let symbol = symbols.first().unwrap();

        let the_answer_addr = unsafe {
            mmap.as_ptr()
                .add(so.data_offset)
                // The address as reported by ELF is just an offset for
                // our intents and purposes, because the symbol is
                // relative to the beginning of the file.
                .add(symbol.address)
        };

        // Now just double check that everything worked out and the function
        // is actually where it was meant to be.
        let the_answer_fn =
            unsafe { transmute::<_, extern "C" fn() -> libc::c_int>(the_answer_addr) };
        let answer = the_answer_fn();
        assert_eq!(answer, 42);

        // Now symbolize the address we just looked up. It should be
        // correctly mapped to the `the_answer` function within our
        // process.
        let srcs = [SymbolSrcCfg::Process(cfg::Process { pid: None })];
        let symbolizer = BlazeSymbolizer::new().unwrap();
        let results = symbolizer
            .symbolize(&srcs, &[the_answer_addr as usize])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = results.first().unwrap();
        assert_eq!(result.symbol, "the_answer");
        assert_eq!(result.start_address, the_answer_addr as Addr);
    }
}
