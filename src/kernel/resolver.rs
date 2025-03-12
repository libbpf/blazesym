use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Result;

use super::kaslr::find_kalsr_offset;
use super::ksym::KsymResolver;


pub(crate) struct KernelResolver {
    ksym_resolver: Option<Rc<KsymResolver>>,
    elf_resolver: Option<Rc<ElfResolver>>,
    kaslr_offset: u64,
}

impl KernelResolver {
    pub(crate) fn new(
        ksym_resolver: Option<Rc<KsymResolver>>,
        elf_resolver: Option<Rc<ElfResolver>>,
        kaslr_offset: Option<u64>,
    ) -> Result<KernelResolver> {
        if ksym_resolver.is_none() && elf_resolver.is_none() {
            return Err(Error::with_not_found(
                "failed to create kernel resolver: neither kallsyms nor vmlinux symbol source are present",
            ))
        }

        let kaslr_offset = if let Some(kaslr_offset) = kaslr_offset {
            kaslr_offset
        } else {
            find_kalsr_offset()
                .context("failed to query system KASLR offset")?
                .unwrap_or_default()
        };

        Ok(KernelResolver {
            ksym_resolver,
            elf_resolver,
            kaslr_offset,
        })
    }
}

impl Symbolize for KernelResolver {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        let elf_addr = || {
            addr.checked_sub(self.kaslr_offset).ok_or_invalid_input(|| {
                format!(
                    "address {addr:#x} is less than KASLR offset ({:#x})",
                    self.kaslr_offset
                )
            })
        };

        match (self.elf_resolver.as_ref(), self.ksym_resolver.as_ref()) {
            (Some(elf_resolver), None) => elf_resolver.find_sym(elf_addr()?, opts),
            (None, Some(ksym_resolver)) => ksym_resolver.find_sym(addr, opts),
            (Some(elf_resolver), Some(ksym_resolver)) => {
                // We give preference to vmlinux, because it is likely
                // to report more information. If it could not find an
                // address, though, we fall back to kallsyms. This is
                // helpful for example for kernel modules, which
                // naturally are not captured by vmlinux.
                let result = elf_resolver.find_sym(elf_addr()?, opts)?;
                if result.is_ok() {
                    Ok(result)
                } else {
                    ksym_resolver.find_sym(addr, opts)
                }
            }
            // SANITY: We ensure that at least one resolver is present at
            //         construction time.
            (None, None) => unreachable!(),
        }
    }
}

impl Debug for KernelResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "KernelResolver({:?} {:?})",
            self.ksym_resolver, self.elf_resolver,
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::kernel::KALLSYMS;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let ksym = Rc::new(KsymResolver::load_file_name(Path::new(KALLSYMS)).unwrap());
        let kernel = KernelResolver::new(Some(ksym), None, Some(0)).unwrap();
        assert_ne!(format!("{kernel:?}"), "");
    }
}
