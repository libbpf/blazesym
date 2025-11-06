use std::fs::File;
use std::mem;
use std::ops::Deref as _;
use std::path::PathBuf;
use std::str;

use crate::util::bytes_to_path;
#[cfg(linux)]
use crate::util::uname_release;
use crate::util::ReadRaw as _;
use crate::Error;
use crate::ErrorExt as _;
use crate::Mmap;
use crate::Result;

const INDEX_NODE_MASK: u32 = 0x0fffffff;
const INDEX_NODE_CHILDS: u32 = 0x20000000;
const INDEX_NODE_VALUES: u32 = 0x40000000;
const INDEX_NODE_PREFIX: u32 = 0x80000000;


/// Represents a memory-mapped depmod index file.
#[derive(Debug)]
pub struct DepmodIndex {
    base_dir: PathBuf,
    // SAFETY: We must not hand out references with a 'static lifetime to
    //         this member. Rather, they should never outlive `self`.
    //         Furthermore, this member has to be listed before `_mmap`
    //         to make sure we never end up with a dangling reference.
    data: &'static [u8],
    _mmap: Option<Mmap>,
}

impl DepmodIndex {
    /// Create a `DepmodIndex` object assuming the system's "default"
    /// location of `modules.dep.bin`.
    #[cfg(linux)]
    pub fn with_system_default() -> Result<Self> {
        let uname_r = uname_release().context("failed to query uname release string")?;
        let uname_r = uname_r
            .to_str()
            .map_err(Error::with_invalid_data)
            .context("uname release string is not valid Unicode")?;
        let kernel_dir = PathBuf::from(format!("/lib/modules/{uname_r}"));
        let depmod = kernel_dir.join("modules.dep.bin");
        let file = File::open(&depmod)
            .with_context(|| format!("failed to open depmod file `{}`", depmod.display()))?;
        Self::new(kernel_dir, file)
    }

    /// Create a new `DepmodIndex` from a file descriptor
    pub fn new(base_dir: PathBuf, file: File) -> Result<Self> {
        let mmap = Mmap::map(&file)?;
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references to cache
        //         data.
        let data = unsafe { mem::transmute::<&[u8], &'static [u8]>(mmap.deref()) };

        let depmod = Self {
            base_dir,
            data,
            _mmap: Some(mmap),
        };

        let () = depmod.validate()?;
        Ok(depmod)
    }

    /// Validate the depmod index file format
    fn validate(&self) -> Result<()> {
        let mut reader = self.data;

        let magic = reader
            .read_u32()
            .map(u32::from_be)
            .ok_or_else(|| Error::with_invalid_data("failed to read magic"))?;
        if magic != 0xb007f457 {
            return Err(Error::with_invalid_data(format!(
                "invalid magic {magic:#08x}"
            )));
        }

        let version = reader
            .read_u32()
            .map(u32::from_be)
            .ok_or_else(|| Error::with_invalid_data("failed to read version"))?;

        if version != 0x00020001 {
            return Err(Error::with_invalid_data(format!(
                "unknown version {version:#08x}"
            )));
        }
        Ok(())
    }

    /// Look up the path of the kernel module with the given name.
    ///
    /// Returns the path relative to `/lib/modules/$(uname -r)`, or
    /// `None` if not found.
    pub fn find_path(&self, name: &str) -> Result<Option<PathBuf>> {
        let mut reader = self.data;

        // Skip magic and version (already validated)
        let () = reader
            .advance(8)
            .ok_or_else(|| Error::with_invalid_data("failed to skip header"))?;

        let mut name_bytes = name.as_bytes();
        let mut offset;

        loop {
            offset = reader
                .read_u32()
                .map(u32::from_be)
                .ok_or_else(|| Error::with_invalid_data("failed to read offset"))?;

            let node_offset = (offset & INDEX_NODE_MASK) as usize;
            if node_offset > self.data.len() {
                return Err(Error::with_invalid_data("offset is out of bounds"));
            }

            reader = &self.data[node_offset..];

            if offset & INDEX_NODE_PREFIX != 0 {
                let prefix_cstr = reader
                    .read_cstr()
                    .ok_or_else(|| Error::with_invalid_data("failed to read prefix"))?;
                let prefix = prefix_cstr.to_bytes();

                if !name_bytes.starts_with(prefix) {
                    return Ok(None);
                }
                name_bytes = &name_bytes[prefix.len()..];
            }

            if offset & INDEX_NODE_CHILDS != 0 {
                let first = reader
                    .read_u8()
                    .ok_or_else(|| Error::with_invalid_data("failed to read first child"))?;
                let last = reader
                    .read_u8()
                    .ok_or_else(|| Error::with_invalid_data("failed to read last child"))?;

                if !name_bytes.is_empty() {
                    let cur = name_bytes[0];
                    if cur < first || cur > last {
                        return Ok(None);
                    }
                    let () = reader
                        .advance(4 * (cur - first) as usize)
                        .ok_or_else(|| Error::with_invalid_data("failed to skip to child"))?;
                    name_bytes = &name_bytes[1..];
                    continue;
                } else {
                    let () = reader
                        .advance(4 * (last - first + 1) as usize)
                        .ok_or_else(|| Error::with_invalid_data("failed to skip children"))?;
                    break;
                }
            } else if !name_bytes.is_empty() {
                return Ok(None);
            } else {
                break;
            }
        }

        if offset & INDEX_NODE_VALUES == 0 {
            return Ok(None);
        }

        let value_count = reader
            .read_u32()
            .map(u32::from_be)
            .ok_or_else(|| Error::with_invalid_data("failed to read value count"))?;

        if value_count == 0 {
            return Ok(None);
        }

        // Skip priority
        let () = reader
            .advance(4)
            .ok_or_else(|| Error::with_invalid_data("failed to skip priority"))?;

        // Find the colon in the value string
        let colon_pos = reader
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| Error::with_invalid_data("expected string containing ':'"))?;

        let path_bytes = &reader[..colon_pos];
        let path = bytes_to_path(path_bytes)?;

        Ok(Some(self.base_dir.join(path)))
    }
}


#[cfg(test)]
mod tests {
    use crate::ErrorKind;

    use super::*;

    use std::path::Path;


    /// Check that we can load a depmod file and query it.
    #[test]
    fn load_depmod() {
        let depmod = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("modules.dep.bin");
        let file = File::open(&depmod).unwrap();
        let depmod = DepmodIndex::new(PathBuf::from("/"), file).unwrap();

        #[rustfmt::skip]
        let test_values = [
            ("ecdh_generic", "/kernel/crypto/ecdh_generic.ko"),
            ("intel_pch_thermal", "/kernel/drivers/thermal/intel/intel_pch_thermal.ko"),
            ("libarc4", "/kernel/lib/crypto/libarc4.ko"),
            ("snd_sof", "/kernel/sound/soc/sof/snd-sof.ko"),
        ];

        for (name, path) in test_values {
            let mod_path = depmod.find_path(name).unwrap().unwrap();
            assert_eq!(mod_path, Path::new(path));
        }

        let result = depmod.find_path("xyz").unwrap();
        assert_eq!(result, None);
    }

    /// Check that we can load the system's depmod file.
    #[cfg(linux)]
    #[test]
    #[ignore = "test requires discoverable depmod file present"]
    fn load_system_depmod() {
        let result = DepmodIndex::with_system_default();
        let depmod = match result {
            Ok(depmod) => depmod,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("{err}"),
        };

        // We don't know which modules are available. So we just pick a
        // few possible ones and search for them, just making sure that
        // we don't err out while doing so.
        let mods = ["ecdh_generic", "intel_pch_thermal", "libarc4", "snd_sof"];
        for name in mods {
            let _result = depmod.find_path(name).unwrap().unwrap();
        }
    }
}
