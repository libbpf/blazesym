use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem::size_of;
use std::str::FromStr;

use crate::inspect::SymInfo;
use crate::symbolize::FindSymOpts;
use crate::symbolize::ResolvedSym;
use crate::symbolize::SrcLang;
use crate::Addr;
use crate::Error;
use crate::Result;
use crate::SymType;

/// BPF kernel programs show up with this prefix followed by a tag and
/// some other meta-data.
const BPF_PROG_PREFIX: &str = "bpf_prog_";


#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct BpfTag([u8; 8]);

impl Display for BpfTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for b in self.0 {
            let () = write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 8]> for BpfTag {
    fn from(other: [u8; 8]) -> Self {
        Self(other)
    }
}

impl FromStr for BpfTag {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().len() != 2 * size_of::<BpfTag>() {
            return Err(())
        }

        let mut tag = [0; size_of::<BpfTag>()];
        (0..s.len())
            .step_by(2)
            .enumerate()
            .try_for_each(|(i, idx)| {
                tag[i] = u8::from_str_radix(&s[idx..idx + 2], 16).map_err(|_| ())?;
                Ok(())
            })?;

        Ok(Self(tag))
    }
}


/// Information about a BPF program.
#[derive(Debug)]
pub struct BpfProg {
    addr: Addr,
    name: Box<str>,
    tag: BpfTag,
}

impl BpfProg {
    /// Parse information about a BPF program from part of a `kallsyms`
    /// line.
    pub fn parse(s: &str, addr: Addr) -> Option<Self> {
        let s = s.strip_prefix(BPF_PROG_PREFIX)?;
        // The name is "optional".
        let (tag, name) = if let Some(idx) = s.find('_') {
            let (tag, name) = s.split_at(idx);
            // Strip leading underscore from name.
            (tag, &name[1..])
        } else {
            (s, "")
        };

        let tag = BpfTag::from_str(tag).ok()?;
        let prog = BpfProg {
            addr,
            name: Box::from(name),
            tag,
        };
        Some(prog)
    }

    pub fn resolve(&self, _addr: Addr, _opts: &FindSymOpts) -> Result<ResolvedSym<'_>> {
        // TODO: Need to look up BPF specific information.
        let BpfProg { name, addr, .. } = self;
        let sym = ResolvedSym {
            name,
            addr: *addr,
            size: None,
            lang: SrcLang::Unknown,
            code_info: None,
            inlined: Box::new([]),
        };
        Ok(sym)
    }

    /// Retrieve the program's start address.
    pub fn addr(&self) -> Addr {
        self.addr
    }

    /// Retrieve the program's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieve the program's tag.
    pub fn tag(&self) -> BpfTag {
        self.tag
    }
}

impl<'prog> TryFrom<&'prog BpfProg> for SymInfo<'prog> {
    type Error = Error;

    fn try_from(other: &'prog BpfProg) -> Result<Self, Self::Error> {
        let BpfProg { addr, name, .. } = other;
        let sym = SymInfo {
            name: Cow::Borrowed(name),
            addr: *addr,
            size: 0,
            sym_type: SymType::Function,
            file_offset: None,
            obj_file_name: None,
        };
        Ok(sym)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;
    use test_tag::tag;


    /// Test that we can parse a BPF program string as it may appear in
    /// `kallsyms` successfully.
    #[tag(miri)]
    #[test]
    fn bpf_prog_str_parsing() {
        let addr = 0x1337;
        let name = "bpf_prog_30304e82b4033ea3_kprobe__cap_capable";
        let bpf_prog = BpfProg::parse(name, addr).unwrap();
        assert_eq!(bpf_prog.addr, addr);
        assert_eq!(&*bpf_prog.name, "kprobe__cap_capable");
        assert_eq!(
            bpf_prog.tag,
            BpfTag::from([0x30, 0x30, 0x4e, 0x82, 0xb4, 0x03, 0x3e, 0xa3])
        );
        assert_eq!(bpf_prog.tag.to_string(), "30304e82b4033ea3");

        let name = "bpf_prog_30304e82b4033ea3";
        let bpf_prog = BpfProg::parse(name, addr).unwrap();
        assert_eq!(bpf_prog.addr, addr);
        assert_eq!(&*bpf_prog.name, "");
        assert_eq!(bpf_prog.tag.to_string(), "30304e82b4033ea3");

        let name = "bpf_prog_run";
        assert!(BpfProg::parse(name, addr).is_none());

        let name = "bpf_prog_get_curr_or_next";
        assert!(BpfProg::parse(name, addr).is_none());
    }
}
