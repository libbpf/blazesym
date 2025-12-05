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
use crate::IntoError as _;
use crate::Result;

use super::ksym::KsymResolver;


pub(crate) struct KernelResolver {
    ksym_resolver: Option<Rc<KsymResolver>>,
    vmlinux_resolver: Option<Rc<ElfResolver>>,
    kaslr_offset: u64,
}

impl KernelResolver {
    pub(crate) fn new(
        ksym_resolver: Option<Rc<KsymResolver>>,
        vmlinux_resolver: Option<Rc<ElfResolver>>,
        kaslr_offset: u64,
    ) -> Result<KernelResolver> {
        if ksym_resolver.is_none() && vmlinux_resolver.is_none() {
            return Err(Error::with_not_found(
                "failed to create kernel resolver: neither kallsyms nor vmlinux symbol source are present",
            ))
        }

        Ok(KernelResolver {
            ksym_resolver,
            vmlinux_resolver,
            kaslr_offset,
        })
    }
}

impl Symbolize for KernelResolver {
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

impl Debug for KernelResolver {
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

    use std::path::Path;

    use crate::kernel::KALLSYMS;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let ksym = Rc::new(KsymResolver::load_file_name(Path::new(KALLSYMS)).unwrap());
        let kernel = KernelResolver::new(Some(ksym), None, 0).unwrap();
        assert_ne!(format!("{kernel:?}"), "");
    }
}
