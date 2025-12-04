use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::log;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::Symbolize;
use crate::util::bytes_to_os_str;
#[cfg(linux)]
use crate::util::uname_release;
use crate::Addr;
use crate::Error;
use crate::IntoError as _;
use crate::MaybeDefault;
use crate::Result;

use super::ksym::KsymResolver;
use super::KernelCache;
use super::KALLSYMS;


pub(crate) struct KernelResolver<'cache> {
    _cache: &'cache KernelCache,
    ksym_resolver: Option<Rc<KsymResolver>>,
    vmlinux_resolver: Option<Rc<ElfResolver>>,
    kaslr_offset: u64,
}

impl<'cache> KernelResolver<'cache> {
    #[cfg(linux)]
    pub(crate) fn new(
        kallsyms: &MaybeDefault<PathBuf>,
        vmlinux: &MaybeDefault<PathBuf>,
        kaslr_offset: Option<u64>,
        debug_syms: bool,
        cache: &'cache KernelCache,
    ) -> Result<Self> {
        let ksym_resolver = match kallsyms {
            MaybeDefault::Some(kallsyms) => {
                let ksym_resolver = cache.ksym_resolver(kallsyms)?;
                Some(ksym_resolver)
            }
            MaybeDefault::Default => {
                let kallsyms = Path::new(KALLSYMS);
                let result = cache.ksym_resolver(kallsyms);
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
            }
            MaybeDefault::None => None,
        };

        let vmlinux_resolver = match vmlinux {
            MaybeDefault::Some(vmlinux) => {
                let resolver = cache.elf_resolver(vmlinux, debug_syms)?;
                Some(resolver)
            }
            MaybeDefault::Default => {
                let release = uname_release()?;
                let release = bytes_to_os_str(release.as_bytes())?;
                let basename = OsStr::new("vmlinux-");
                let dirs = [Path::new("/boot/"), Path::new("/usr/lib/debug/boot/")];
                let vmlinux = dirs.iter().find_map(|dir| {
                    let mut file = basename.to_os_string();
                    let () = file.push(release);
                    let path = dir.join(file);
                    path.exists().then_some(path)
                });

                if let Some(vmlinux) = vmlinux {
                    let result = cache.elf_resolver(&vmlinux, debug_syms);
                    match result {
                        Ok(resolver) => {
                            log::debug!("found suitable vmlinux file `{}`", vmlinux.display());
                            Some(resolver)
                        }
                        Err(err) => {
                            log::warn!(
                                "failed to load vmlinux `{}`: {err}; ignoring...",
                                vmlinux.display()
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            }
            MaybeDefault::None => None,
        };

        let ksym_resolver = ksym_resolver.map(Rc::clone);
        let vmlinux_resolver = vmlinux_resolver.map(Rc::clone);
        let kaslr_offset = kaslr_offset
            .map(Ok)
            .unwrap_or_else(|| cache.kaslr_offset())?;

        if ksym_resolver.is_none() && vmlinux_resolver.is_none() {
            return Err(Error::with_not_found(
                "failed to create kernel resolver: neither kallsyms nor vmlinux symbol source are present",
            ))
        }

        Ok(KernelResolver {
            _cache: cache,
            ksym_resolver,
            vmlinux_resolver,
            kaslr_offset,
        })
    }
}

impl Symbolize for KernelResolver<'_> {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        match (self.vmlinux_resolver.as_ref(), self.ksym_resolver.as_ref()) {
            (Some(vmlinux_resolver), ksym_resolver) => {
                let elf_addr = addr
                    .checked_sub(self.kaslr_offset)
                    .ok_or_invalid_input(|| {
                        format!(
                            "address {addr:#x} is less than KASLR offset ({:#x})",
                            self.kaslr_offset
                        )
                    })?;

                // We give preference to vmlinux, because it is likely
                // to report more information. If it could not find an
                // address, though, we fall back to kallsyms. This is
                // helpful for example for kernel modules, which
                // naturally are not captured by vmlinux.
                let result = vmlinux_resolver.find_sym(elf_addr, opts)?;
                if result.is_ok() {
                    Ok(result)
                } else if let Some(ksym_resolver) = ksym_resolver {
                    ksym_resolver.find_sym(addr, opts)
                } else {
                    Ok(result)
                }
            }
            (None, Some(ksym_resolver)) => ksym_resolver.find_sym(addr, opts),
            // SANITY: We ensure that at least one resolver is present at
            //         construction time.
            (None, None) => unreachable!(),
        }
    }
}

impl Debug for KernelResolver<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "KernelResolver({:?} {:?})",
            self.ksym_resolver, self.vmlinux_resolver,
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let cache = KernelCache::new(Rc::new([]));
        let kernel = KernelResolver {
            _cache: &cache,
            ksym_resolver: None,
            vmlinux_resolver: None,
            kaslr_offset: 0,
        };
        assert_ne!(format!("{kernel:?}"), "");
    }
}
