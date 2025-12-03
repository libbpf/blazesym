use std::cell::OnceCell;
use std::fs::File;
use std::path::Path;
use std::rc::Rc;

use crate::file_cache::FileCache;
use crate::util::OnceCellExt as _;
use crate::ErrorExt as _;
use crate::Result;

use super::kaslr::find_kalsr_offset;
use super::KsymResolver;


/// A cache for kernel related data.
#[derive(Debug, Default)]
pub(crate) struct KernelCache {
    /// `/proc/kallsyms` cache.
    ksym_cache: FileCache<Rc<KsymResolver>>,
    /// The system's KASLR offset.
    kaslr_offset: OnceCell<u64>,
}

impl KernelCache {
    fn create_ksym_resolver(&self, path: &Path, file: &File) -> Result<Rc<KsymResolver>> {
        let resolver = KsymResolver::load_from_reader(file, path)?;
        let resolver = Rc::new(resolver);
        Ok(resolver)
    }

    pub fn ksym_resolver<'slf>(&'slf self, path: &Path) -> Result<&'slf Rc<KsymResolver>> {
        let (file, cell) = self.ksym_cache.entry(path)?;
        let resolver = cell.get_or_try_init_(|| self.create_ksym_resolver(path, file))?;
        Ok(resolver)
    }

    pub fn kaslr_offset(&self) -> Result<u64> {
        self.kaslr_offset
            .get_or_try_init_(|| {
                find_kalsr_offset()
                    .context("failed to query system KASLR offset")
                    .map(Option::unwrap_or_default)
            })
            .copied()
    }
}
