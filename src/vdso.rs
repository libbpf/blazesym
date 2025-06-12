use std::ops::Range;
use std::slice;

use crate::elf::ElfParser;
use crate::elf::StaticMem;
use crate::maps;
use crate::Addr;
use crate::Error;
use crate::Pid;
use crate::Result;


/// The special module string that we report for symbols inside the
/// vDSO.
pub(crate) const VDSO_MODULE: &str = "[vdso]";
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


#[cfg(linux)]
pub(crate) fn create_vdso_parser(pid: Pid, range: &Range<Addr>) -> Result<ElfParser<StaticMem>> {
    use std::ffi::OsString;

    let vdso_range = if pid == Pid::Slf {
        range.clone()
    } else {
        if let Some(vdso_range) = find_vdso()? {
            vdso_range
        } else {
            return Err(Error::with_not_found("failed to find vDSO"))
        }
    };

    let data = vdso_range.start as *const u8;
    let len = vdso_range.end.saturating_sub(vdso_range.start);
    // SAFETY: Everything points to `vdso_range` representing the
    //         memory range of the vDSO, which is statically
    //         allocated by the kernel and will never vanish.
    let mem = unsafe { slice::from_raw_parts(data, len as _) };
    let parser = ElfParser::from_mem(mem, OsString::from(VDSO_MODULE));
    Ok(parser)
}

#[cfg(not(linux))]
pub(crate) fn create_vdso_parser(_pid: Pid, _range: &Range<Addr>) -> Result<ElfParser<StaticMem>> {
    Err(Error::with_unsupported(
        "vDSO address symbolization is unsupported on operating systems other than Linux",
    ))
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
