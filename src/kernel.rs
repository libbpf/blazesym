use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::path::Path;
use std::rc::Rc;

use crate::elf::ElfResolver;
use crate::ksym::KSymResolver;
use crate::symbolize::FindSymOpts;
use crate::symbolize::Reason;
use crate::symbolize::ResolvedSym;
use crate::symbolize::Symbolize;
use crate::Addr;
use crate::Error;
use crate::Result;


pub(crate) struct KernelResolver {
    pub ksym_resolver: Option<Rc<KSymResolver>>,
    pub elf_resolver: Option<Rc<ElfResolver>>,
}

impl KernelResolver {
    pub fn new(
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
        // TODO: If an `ElfResolver` is available we probably should give
        //       preference to it, if for no other reason than the fact that it
        //       may report source code location information.
        if let Some(ksym_resolver) = self.ksym_resolver.as_ref() {
            ksym_resolver.find_sym(addr, opts)
        } else {
            self.elf_resolver.as_ref().unwrap().find_sym(addr, opts)
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
