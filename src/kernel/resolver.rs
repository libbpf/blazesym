use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::Error;
use crate::Result;

use super::ksym::KSymResolver;


pub(crate) struct KernelResolver {
    pub ksym_resolver: Option<Rc<KSymResolver>>,
    pub elf_resolver: Option<Rc<ElfResolver>>,
}

impl KernelResolver {
    pub(crate) fn new(
        ksym_resolver: Option<Rc<KSymResolver>>,
        elf_resolver: Option<Rc<ElfResolver>>,
    ) -> Result<KernelResolver> {
        if ksym_resolver.is_none() && elf_resolver.is_none() {
            return Err(Error::with_not_found(
                    "failed to create kernel resolver: neither ksym resolver nor kernel image ELF resolver are present",
            ))
        }

        Ok(KernelResolver {
            ksym_resolver,
            elf_resolver,
        })
    }
}

impl Symbolize for KernelResolver {
    fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
        if let Some(elf_resolver) = self.elf_resolver.as_ref() {
            elf_resolver.find_sym(addr, opts)
        } else {
            self.ksym_resolver.as_ref().unwrap().find_sym(addr, opts)
        }
    }
}

impl Debug for KernelResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "KernelResolver {} {}",
            self.ksym_resolver
                .as_ref()
                .map(|resolver| resolver.file_name())
                .unwrap_or_else(|| Path::new(""))
                .display(),
            self.elf_resolver
                .as_ref()
                .and_then(|resolver| resolver.path())
                .unwrap_or_else(|| Path::new(""))
                .display(),
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::kernel::KALLSYMS;
    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let ksym = Rc::new(KSymResolver::load_file_name(Path::new(KALLSYMS)).unwrap());
        let kernel = KernelResolver::new(Some(ksym), None).unwrap();
        assert_ne!(format!("{kernel:?}"), "");
    }

    /// Exercise the error path when no sub-resolver is provided.
    #[test]
    fn no_sub_resolver() {
        let err = KernelResolver::new(None, None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}
