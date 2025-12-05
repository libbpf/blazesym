use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
#[cfg(any(feature = "xz", feature = "zlib", feature = "zstd"))]
use std::fs::File;
#[cfg(any(feature = "xz", feature = "zlib", feature = "zstd"))]
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use tempfile::NamedTempFile;

use crate::elf::ElfResolver;
use crate::error::ErrorExt as _;
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


#[cfg(any(feature = "xz", feature = "zlib", feature = "zstd"))]
fn decompress_into_tmp(decoder: &mut dyn io::Read, path: &Path) -> Result<NamedTempFile> {
    use std::io::copy;
    use std::io::Write as _;

    let mut out = NamedTempFile::new().context("failed to create temporary file")?;
    let _cnt = copy(decoder, &mut out)
        .with_context(|| format!("failed to zlib-decode `{}` contents", path.display()))?;
    let () = out
        .flush()
        .context("failed to flush temporary file contents")?;
    Ok(out)
}


#[cfg(feature = "zlib")]
fn decompress_zlib(path: &Path) -> Result<NamedTempFile> {
    use flate2::read::GzDecoder;

    let file = File::open(path).with_context(|| format!("failed to open `{}`", path.display()))?;
    let mut decoder = GzDecoder::new(file);

    decompress_into_tmp(&mut decoder, path)
}

#[cfg(not(feature = "zlib"))]
fn decompress_zlib(_path: &Path) -> Result<NamedTempFile> {
    Err(Error::with_unsupported(
        "Kernel module is zlib compressed but zlib compression support is not enabled",
    ))
}

#[cfg(feature = "xz")]
fn decompress_xz(path: &Path) -> Result<NamedTempFile> {
    use xz2::read::XzDecoder;

    let file = File::open(path).with_context(|| format!("failed to open `{}`", path.display()))?;
    let mut decoder = XzDecoder::new(file);

    decompress_into_tmp(&mut decoder, path)
}

#[cfg(not(feature = "xz"))]
fn decompress_xz(_path: &Path) -> Result<NamedTempFile> {
    Err(Error::with_unsupported(
        "Kernel module is xz compressed but xz compression support is not enabled",
    ))
}

#[cfg(feature = "zstd")]
fn decompress_zstd(path: &Path) -> Result<NamedTempFile> {
    use zstd::stream::read::Decoder;

    let file = File::open(path).with_context(|| format!("failed to open `{}`", path.display()))?;
    let mut decoder = Decoder::new(file).context("failed to create zstd decoder")?;

    decompress_into_tmp(&mut decoder, path)
}

#[cfg(not(feature = "zstd"))]
fn decompress_zstd(_path: &Path) -> Result<NamedTempFile> {
    Err(Error::with_unsupported(
        "Kernel module is zstd compressed but zstd compression support is not enabled",
    ))
}


pub(crate) struct KernelResolver<'cache> {
    cache: &'cache KernelCache,
    ksym_resolver: Option<Rc<KsymResolver>>,
    vmlinux_resolver: Option<Rc<ElfResolver>>,
    kaslr_offset: u64,
    debug_syms: bool,
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
            cache,
            ksym_resolver,
            vmlinux_resolver,
            kaslr_offset,
            debug_syms,
        })
    }
}

impl Symbolize for KernelResolver<'_> {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        match (self.vmlinux_resolver.as_ref(), self.ksym_resolver.as_ref()) {
            (Some(vmlinux_resolver), ksym_resolver) => {
                // We start off with checking whether the address belongs
                // to a kernel module. The response should be 100% reliable.
                let modmap = self.cache.modmap()?;
                if let Ok((mod_name, mod_base)) = modmap.find_module(addr) {
                    log::debug!("address {addr:#x} belongs to module `{mod_name}` (base address: {mod_base:#x})");
                    // TODO: Should probably handle a non-present file more
                    //       gracefully.
                    let depmod = self.cache.depmod()?;

                    if let Some(mod_path) = depmod.find_path(mod_name)? {
                        log::debug!("module `{mod_name}` has path `{}`", mod_path.display());

                        // The kernel module may be stored in compressed
                        // form. If so, decompress it transparently into
                        // a temporary file.
                        let ext = mod_path.extension().unwrap_or_else(|| OsStr::new(""));
                        let path;
                        let mod_resolver = match ext.to_str() {
                            Some("gz") | Some("xz") | Some("zstd") => {
                                let tmpfile = match ext.to_str() {
                                    Some("gz") => decompress_zlib(&mod_path)?,
                                    Some("xz") => decompress_xz(&mod_path)?,
                                    Some("zstd") => decompress_zstd(&mod_path)?,
                                    _ => unreachable!(),
                                };
                                // The temporary file *represents* `mod_path` without the
                                // `.xz` extension.
                                path = (tmpfile, mod_path.with_extension(""));
                                self.cache.elf_resolver(&path, self.debug_syms)?
                            }
                            _ => self.cache.elf_resolver(&mod_path, self.debug_syms)?,
                        };

                        let elf_addr = addr.checked_sub(mod_base).ok_or_invalid_input(|| {
                            format!(
                            "address {addr:#x} is less than module base address ({mod_base:#x})",
                        )
                        })?;
                        let result = mod_resolver.find_sym(elf_addr, opts)?;
                        if result.is_ok() {
                            return Ok(result)
                        }
                    } else {
                        log::info!("module `{mod_name}` not found in depmod");
                    }
                }

                // Next check the core kernel via its vmlinux file.
                let vmlinux_addr =
                    addr.checked_sub(self.kaslr_offset)
                        .ok_or_invalid_input(|| {
                            format!(
                                "address {addr:#x} is less than KASLR offset ({:#x})",
                                self.kaslr_offset
                            )
                        })?;

                let result = vmlinux_resolver.find_sym(vmlinux_addr, opts)?;
                if result.is_ok() {
                    return Ok(result)
                }

                if let Some(ksym_resolver) = ksym_resolver {
                    // If all else failed we use kallsyms.
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
            cache: &cache,
            ksym_resolver: None,
            vmlinux_resolver: None,
            kaslr_offset: 0,
            debug_syms: false,
        };
        assert_ne!(format!("{kernel:?}"), "");
    }
}
