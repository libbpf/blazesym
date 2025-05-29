use std::ops::Range;

use crate::maps;
use crate::Addr;
use crate::Pid;
use crate::Result;


/// The name of the "component" representing the vDSO inside
/// `/proc/<pid>/maps`.
pub(crate) const VDSO_MAPS_COMPONENT: &str = "[vdso]";


pub(crate) fn find_vdso_maps(pid: Pid) -> Result<Option<Range<Addr>>> {
    let entries = maps::parse_filtered(pid)?;
    for result in entries {
        let entry = result?;
        if matches!(entry.path_name, Some(maps::PathName::Component(c)) if c == VDSO_MAPS_COMPONENT)
        {
            return Ok(Some(entry.range))
        }
    }
    Ok(None)
}

pub(crate) fn find_vdso() -> Result<Option<Range<Addr>>> {
    // Note that we could also use `getauxval(3)` for retrieval of the
    // vDSO address. However, that function does not report the size and
    // so we end up either guessing (definitely bad; though severity
    // depends on use case), cobbling something together using
    // `ElfParser` on the first page, in an attempt to determine the
    // full ELF size, or using `/proc/<pid>/maps` as we already do. In
    // the end what we have is the most straight forward...

    find_vdso_maps(Pid::Slf)
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Make sure that we can look up the address of the process' vDSO.
    #[cfg(linux)]
    #[test]
    fn vdso_addr_finding() {
        let _range = find_vdso().unwrap();
    }
}
