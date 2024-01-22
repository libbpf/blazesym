/// A module for working with Perf Map files.
///
/// See <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/Documentation/jit-interface.txt>
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::mem::transmute;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;
use std::str;

use crate::Addr;
use crate::Error;
use crate::ErrorExt as _;
use crate::IntoError as _;
use crate::Pid;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::mmap::Mmap;
use crate::resolver::SymResolver;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Result;

use crate::symbolize::AddrCodeInfo;
use crate::symbolize::IntSym;
use crate::symbolize::Reason;

use super::SrcLang;


#[derive(Debug, Eq, PartialEq)]
struct Function<'mmap> {
    /// The name of the function.
    name: &'mmap str,
    /// The function's start address.
    addr: Addr,
    /// The size of the function.
    size: usize,
}


/// Split a byte slice at the first byte for which `check` returns
/// `true`.
///
/// # Notes
/// The byte at which the split happens is not included in either of the
/// returned sliced.
fn split_bytes<F>(bytes: &[u8], mut check: F) -> Option<(&[u8], &[u8])>
where
    F: FnMut(u8) -> bool,
{
    let (idx, _) = bytes.iter().enumerate().find(|(_idx, b)| check(**b))?;
    let (left, right) = bytes.split_at(idx);
    Some((left, &right[1..]))
}


/// Parse a line of a perf map file.
fn parse_perf_map_line<'line>(line: &'line [u8]) -> Result<Function<'_>> {
    let full_line = line;

    let split_once = |line: &'line [u8], component| -> Result<(&'line [u8], &'line [u8])> {
        split_bytes(line, |b| b.is_ascii_whitespace()).ok_or_invalid_data(|| {
            format!(
                "failed to find {component} in perf map line: {}\n{}",
                String::from_utf8_lossy(line),
                String::from_utf8_lossy(full_line)
            )
        })
    };

    // Lines have the following format:
    // > START SIZE symbolname

    // START and SIZE are hex numbers without 0x. symbolname is the rest of the
    // line, so it could contain special characters.
    let (addr_slice, line) = split_once(line, "address")?;
    let addr_str = str::from_utf8(addr_slice).map_err(|err| {
        Error::with_invalid_data(format!(
            "encountered malformed start address in perf map line: {}: {err}",
            String::from_utf8_lossy(full_line)
        ))
    })?;
    let addr = Addr::from_str_radix(addr_str, 16).map_err(|err| {
        Error::with_invalid_data(format!(
            "encountered malformed start address in perf map line: {}: {err}",
            String::from_utf8_lossy(full_line)
        ))
    })?;

    let (size_slice, line) = split_once(line, "size")?;
    let size_str = str::from_utf8(size_slice).map_err(|err| {
        Error::with_invalid_data(format!(
            "encountered malformed size component in perf map line: {}: {err}",
            String::from_utf8_lossy(full_line)
        ))
    })?;
    let size = usize::from_str_radix(size_str, 16).map_err(|err| {
        Error::with_invalid_data(format!(
            "encountered malformed size component in perf map line: {}: {err}",
            String::from_utf8_lossy(full_line)
        ))
    })?;

    let symbol_slice = line;
    let symbol = str::from_utf8(symbol_slice).map_err(|err| {
        Error::with_invalid_data(format!(
            "encountered malformed symbol component in perf map line: {}: {err}",
            String::from_utf8_lossy(full_line)
        ))
    })?;

    let function = Function {
        name: symbol,
        addr,
        size,
    };
    Ok(function)
}


fn parse_perf_map(data: &[u8]) -> Result<Vec<Function>> {
    let mut functions = data
        .split(|&b| b == b'\n' || b == b'\r')
        .filter(|line| !line.is_empty())
        .map(parse_perf_map_line)
        .collect::<Result<Vec<_>>>()?;
    let () = functions.sort_by_key(|x| (x.addr, x.size));
    Ok(functions)
}


pub(crate) struct PerfMap {
    /// All functions found in the perf map, ordered by start address.
    // SAFETY: We must not hand out references with a 'static lifetime to
    //         this member. Rather, they should never outlive `self`.
    //         Furthermore, this member has to be listed before `_mmap`
    //         to make sure we never end up with a dangling reference.
    functions: Vec<Function<'static>>,
    /// The memory mapped file.
    _mmap: Mmap,
}

impl PerfMap {
    /// Retrieve the path to a perf map file representing the process with the
    /// given `pid`.
    pub fn path(pid: Pid) -> PathBuf {
        let pid = pid.resolve();
        // The documentation mentions /tmp by name specifically, ignoring
        // `TMPDIR` et al, so that is what we work with as well.
        let path = Path::new("/tmp").join(format!("perf-{pid}.map"));
        path
    }

    /// Load the [`PerfMap`] for the process with the given `pid`, if any.
    pub fn from_file(path: &Path, file: &File) -> Result<Self> {
        let mmap = Mmap::map(file)
            .with_context(|| format!("failed to mmap perf map `{}`", path.display()))?;
        // We transmute the mmap's lifetime to static here as that is a
        // necessity for self-referentiality.
        // SAFETY: We never hand out any 'static references later on.
        let data = unsafe { transmute(mmap.deref()) };
        let functions = parse_perf_map(data)
            .with_context(|| format!("failed to parse perf map `{}`", path.display()))?;

        let slf = Self {
            functions,
            _mmap: mmap,
        };
        Ok(slf)
    }
}

impl SymResolver for PerfMap {
    fn find_sym(&self, addr: Addr) -> Result<Result<IntSym<'_>, Reason>> {
        let result = find_match_or_lower_bound_by_key(&self.functions, addr, |l| l.addr);
        match result {
            Some(idx) => {
                for function in &self.functions[idx..] {
                    if function.addr > addr {
                        break
                    }

                    if (function.addr == addr && function.size == 0)
                        || (function.addr <= addr && addr < function.addr + function.size as Addr)
                    {
                        let Function { name, addr, size } = function;
                        let sym = IntSym {
                            name,
                            addr: *addr,
                            size: Some(*size),
                            lang: SrcLang::Unknown,
                        };
                        return Ok(Ok(sym))
                    }
                }
                Ok(Err(Reason::UnknownAddr))
            }
            None => Ok(Err(Reason::UnknownAddr)),
        }
    }

    fn find_addr<'slf>(
        &'slf self,
        _name: &str,
        _opts: &FindAddrOpts,
    ) -> Result<Vec<SymInfo<'slf>>> {
        Err(Error::with_unsupported(
            "Perf map resolver does not currently support lookup by name",
        ))
    }

    fn find_code_info(&self, _addr: Addr, _inlined_fns: bool) -> Result<Option<AddrCodeInfo<'_>>> {
        // Perf maps don't carry any source code information.
        Ok(None)
    }
}

impl Debug for PerfMap {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("PerfMap").finish()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::ffi::OsString;
    use std::io::Read as _;
    use std::io::Write as _;
    use std::process::Command;
    use std::process::Stdio;

    use libc::kill;
    use libc::SIGKILL;

    use scopeguard::defer;

    use tempfile::tempfile;

    use crate::symbolize::Input;
    use crate::symbolize::Process;
    use crate::symbolize::Source;
    use crate::symbolize::Symbolizer;
    use crate::ErrorKind;


    const SAMPLE_PERF_MAP: &[u8] = br#"7fbf1fc21000 b py::_find_and_load:<frozen importlib._bootstrap>
7fbf1fc2100b b py::_ModuleLockManager.__init__:<frozen importlib._bootstrap>
7fbf1fc21016 b py::_ModuleLockManager.__enter__:<frozen importlib._bootstrap>
7fbf1fc21021 b py::_get_module_lock:<frozen importlib._bootstrap>
7fbf1fc2113f b py::ModuleSpec.has_location:<frozen importlib._bootstrap>
7fbf1fc2114a b py::FrozenImporter.exec_module:<frozen importlib._bootstrap>
7fbf1fc21155 b py::<module>:<frozen io>
7fbf1fc213a7 b py::Set:<frozen _collections_abc>
7fbf1fc213b2 b py::Collection.__subclasshook__:<frozen _collections_abc>
7fbf1fc213bd b py::MutableSet:<frozen _collections_abc>
7fbf1fc213c8 b py::Mapping:<frozen _collections_abc>
7fbf1fc213d3 b py::MappingView:<frozen _collections_abc>
7fbf1fc213de b py::KeysView:<frozen _collections_abc>
7fbf1fc213e9 b py::ItemsView:<frozen _collections_abc>
7fbf1fc213f4 b py::ValuesView:<frozen _collections_abc>
7fbf1fc213ff b py::MutableMapping:<frozen _collections_abc>
7fbf1fc2140a b py::Sequence:<frozen _collections_abc>
7fbf1fc21415 b py::Reversible.__subclasshook__:<frozen _collections_abc>
7fbf1fc21420 b py::_DeprecateByteStringMeta:<frozen _collections_abc>
7fbf1fc2142b b py::ByteString:<frozen _collections_abc>
7fbf1fc21436 b py::_DeprecateByteStringMeta.__new__:<frozen _collections_abc>
7fbf1fc21441 b py::MutableSequence:<frozen _collections_abc>
7fbf1fc2144c b py::<module>:<frozen posixpath>
7fbf1fc215ee b py::_getuserbase.<locals>.joinuser:<frozen sitej7fbf1fc215f9 b py::expanduser:<frozen posixpath>
7fbf1fc21604 b py::Mapping.__contains__:<frozen _collections_abc>
7fbf1fc2160f b py::_createenviron.<locals>.decode:<frozen os>
7fbf1fc21743 b py::FileFinder._fill_cache:<frozen importlib._bootstrap_external>
7fbf1fc2174e b py::execusercustomize:<frozen site>
7fbf1fc21759 b py::_read_directory:<frozen zipimport>
7fbf1fc21764 b py::FileLoader.__init__:<frozen importlib._bootstrap_external>
"#;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let func = Function {
            name: "foobar",
            addr: 0x1337,
            size: 0x42,
        };
        assert_ne!(format!("{func:?}"), "");

        let mut file = tempfile().unwrap();
        let () = file.write_all(SAMPLE_PERF_MAP).unwrap();
        let perf_map = PerfMap::from_file(Path::new("SAMPLE_PERF_MAP"), &file).unwrap();
        assert_ne!(format!("{perf_map:?}"), "");
    }

    /// Exercise various error paths of the perf map line parsing logic.
    #[test]
    fn perf_map_line_parsing_errors() {
        let result = parse_perf_map_line(b"123");
        assert!(result.is_err(), "{result:?}");

        let result = parse_perf_map_line(b"xxxx b py::foobar");
        assert!(result.is_err(), "{result:?}");

        let result = parse_perf_map_line(b"x\xFFxx b py::foobar");
        assert!(result.is_err(), "{result:?}");

        let result = parse_perf_map_line(b"1234 yyy py::foobar");
        assert!(result.is_err(), "{result:?}");

        let result = parse_perf_map_line(b"1234 y\xFFyy py::foobar");
        assert!(result.is_err(), "{result:?}");

        let result = parse_perf_map_line(b"1234 b py::\xFFfoobar");
        assert!(result.is_err(), "{result:?}");
    }

    /// Make sure that we can parse a valid perf map successfully.
    #[test]
    fn perf_map_parsing() {
        let functions = parse_perf_map(SAMPLE_PERF_MAP).unwrap();
        assert_eq!(functions.len(), 30);
    }

    /// Check that [`PerfMap::find_addr`] behaves as expected.
    #[test]
    fn unsupported_find_addr() {
        let mut file = tempfile().unwrap();
        let () = file.write_all(SAMPLE_PERF_MAP).unwrap();
        let perf_map = PerfMap::from_file(Path::new("SAMPLE_PERF_MAP"), &file).unwrap();

        let err = perf_map
            .find_addr("factorial", &FindAddrOpts::default())
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    /// Check that we can load a perf map and use it to symbolize an address.
    #[test]
    fn perf_map_symbolization() {
        let mut file = tempfile().unwrap();
        let () = file.write_all(SAMPLE_PERF_MAP).unwrap();
        let perf_map = PerfMap::from_file(Path::new("SAMPLE_PERF_MAP"), &file).unwrap();

        for offset in 0..0xb {
            let sym = perf_map.find_sym(0x7fbf1fc2144c + offset).unwrap().unwrap();
            assert_eq!(sym.name, "py::<module>:<frozen posixpath>");
            assert_eq!(sym.addr, 0x7fbf1fc2144c);
            assert_eq!(sym.size, Some(0xb));
        }
    }

    /// Check that we can symbolize an address using a perf map.
    #[test]
    #[ignore = "test requires python 3.12 or higher"]
    fn symbolize_perf_map() {
        let script = r#"
import sys

sys.activate_stack_trampoline("perf")

def main():
  print()
  input()
  return 0

if __name__ == "__main__":
  main()
"#;

        let mut child =
            Command::new(env::var_os("PYTHON").unwrap_or_else(|| OsString::from("python")))
                .args(["-c", script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
        let pid = child.id();
        defer!({
            let _rc = unsafe { kill(pid as _, SIGKILL) };
        });

        // Wait for the process to have activated its stack trampoline
        // functionality.
        let mut buf = [0u8; 8];
        let _count = child
            .stdout
            .as_mut()
            .unwrap()
            .read(&mut buf)
            .expect("failed to read child output");

        let path = PerfMap::path(Pid::from(pid));
        let file = File::open(&path).unwrap();
        let perf_map = PerfMap::from_file(&path, &file).unwrap();
        let function = &perf_map.functions[perf_map.functions.len() / 2];

        let src = Source::Process(Process::new(Pid::from(child.id())));
        let symbolizer = Symbolizer::new();

        let addrs = (function.addr..function.addr + function.size as Addr).collect::<Vec<_>>();
        let results = symbolizer
            .symbolize(&src, Input::AbsAddr(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), function.size as _);
        let () = results.into_iter().for_each(|symbolized| {
            let result = symbolized.into_sym().unwrap();
            assert_eq!(result.name, function.name);
            assert_eq!(result.addr, function.addr);
            assert_eq!(result.size, Some(function.size));
        });

        // "Signal" the child to terminate gracefully.
        let () = child.stdin.as_ref().unwrap().write_all(&[b'\n']).unwrap();
        let _status = child.wait().unwrap();
    }
}
