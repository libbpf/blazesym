// Based on rust-minidump (https://github.com/rust-minidump/rust-minidump):
// > Copyright 2015 Ted Mielczarek.
// >
// > Copyright (c) 2015-2023 rust-minidump contributors
// >
// > Permission is hereby granted, free of charge, to any person
// > obtaining a copy of this software and associated documentation
// > files (the "Software"), to deal in the Software without
// > restriction, including without limitation the rights to use, copy,
// > modify, merge, publish, distribute, sublicense, and/or sell
// > copies of the Software, and to permit persons to whom the
// > Software is furnished to do so, subject to the following
// > conditions:
// > The above copyright notice and this permission notice shall be
// > included in all copies or substantial portions of the Software.
// >
// > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// > FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// > DEALINGS IN THE SOFTWARE.

use std::collections::HashMap;

use crate::util::find_match_or_lower_bound_by_key;


/// A publicly visible linker symbol.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PublicSymbol {
    /// The symbol's address relative to the module's load address.
    ///
    /// This field is declared first so that the derived Ord implementation
    /// sorts by address first. We take advantage of the sort order during
    /// address lookup.
    pub addr: u64,
    /// The name of the symbol.
    pub name: String,
    /// The size of parameters passed to the function.
    pub parameter_size: u32,
}

/// A mapping from machine code bytes to source line and file.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SourceLine {
    /// The start address relative to the module's load address.
    pub addr: u64,
    /// The size of this range of instructions in bytes.
    pub size: u32,
    /// The source file name that generated this machine code.
    ///
    /// This is an index into `SymbolFile::files`.
    pub file: u32,
    /// The line number in `file` that generated this machine code.
    pub line: u32,
}

/// A single range which is covered by an inlined function call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Inlinee {
    /// The depth of the inline call.
    pub depth: u32,
    /// The start address relative to the module's load address.
    pub addr: u64,
    /// The size of this range of instructions in bytes.
    pub size: u32,
    /// The source file which contains the function call.
    ///
    /// This is an index into `SymbolFile::files`.
    pub call_file: u32,
    /// The line number in `call_file` for the function call.
    pub call_line: u32,
    /// The function name, as an index into `SymbolFile::inline_origins`.
    pub origin_id: u32,
}

/// A source-language function.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Function {
    /// The function's start address relative to the module's load address.
    pub addr: u64,
    /// The size of the function in bytes.
    pub size: u32,
    /// The size of parameters passed to the function.
    pub parameter_size: u32,
    /// The name of the function as declared in the source.
    pub name: String,
    /// Source line information for this function, sorted by start
    /// address.
    pub lines: Vec<SourceLine>,
    /// Inlinee information for this function, sorted by (depth, address).
    ///
    /// Essentially this can be considered as "one vec per depth", just with
    /// all those vecs concatenated into one.
    ///
    /// Inlinees form a nested structure, you can think of them like a flame
    /// graph.
    pub inlinees: Vec<Inlinee>,
}

impl Function {
    pub(super) fn find_line(&self, addr: u64) -> Option<&SourceLine> {
        let idx = find_match_or_lower_bound_by_key(&self.lines, addr, |l| l.addr)?;
        for line in &self.lines[idx..] {
            if line.addr > addr {
                break
            }

            if (line.addr == addr && line.size == 0)
                || (line.addr <= addr && addr < line.addr + u64::from(line.size))
            {
                return Some(line)
            }
        }
        None
    }

    /// Returns `(call_file_id, call_line, address, inline_origin)` of the
    /// inlinee record that covers the given address at the given depth.
    #[cfg(test)]
    pub(super) fn get_inlinee_at_depth(
        &self,
        depth: u32,
        addr: u64,
    ) -> Option<(u32, u32, u64, u32)> {
        self.find_inlinee_at_depth(depth, addr).map(|inlinee| {
            (
                inlinee.call_file,
                inlinee.call_line,
                inlinee.addr,
                inlinee.origin_id,
            )
        })
    }

    /// Find an inlinee record record that covers the given address at the given
    /// depth.
    ///
    /// We start at depth zero. For example, if we have an "inline call stack"
    /// A -> B -> C at an address, i.e. both the call to B and the call to C
    /// have been inlined all the way into A (A being the "outer function"),
    /// then the call A -> B is at level zero, and the call B -> C is at
    /// level one.
    pub fn find_inlinee_at_depth(&self, depth: u32, addr: u64) -> Option<&Inlinee> {
        let inlinee = match self
            .inlinees
            .binary_search_by_key(&(depth, addr), |inlinee| (inlinee.depth, inlinee.addr))
        {
            // Exact match
            Ok(index) => &self.inlinees[index],
            // No match, insertion index is zero => before first element
            Err(0) => return None,
            // No exact match, insertion index points after inlinee whose (depth, addr) is < what
            // were looking for => subtract 1 to get candidate
            Err(index) => &self.inlinees[index - 1],
        };
        if inlinee.depth != depth {
            return None
        }
        let end_address = inlinee.addr.checked_add(inlinee.size as u64)?;
        if addr < end_address {
            Some(inlinee)
        } else {
            None
        }
    }

    pub fn find_inlinees(&self, addr: u64) -> Vec<&Inlinee> {
        let mut inlinees = Vec::new();
        while let Some(inlinee) = self.find_inlinee_at_depth(inlinees.len() as _, addr) {
            let () = inlinees.push(inlinee);
        }
        inlinees
    }
}


/// A parsed .sym file containing debug symbols.
#[derive(Debug)]
pub(crate) struct SymbolFile {
    /// The set of source files involved in compilation.
    pub files: HashMap<u32, String>,
    /// Functions.
    pub functions: Vec<Function>,
    /// Function names for inlined functions.
    pub inline_origins: HashMap<u32, String>,
}

impl SymbolFile {
    pub fn find_function(&self, addr: u64) -> Option<&Function> {
        let idx = find_match_or_lower_bound_by_key(&self.functions, addr, |f| f.addr)?;
        for func in &self.functions[idx..] {
            if func.addr > addr {
                break
            }

            if (func.addr == addr && func.size == 0)
                || (func.addr <= addr && addr < func.addr + u64::from(func.size))
            {
                return Some(func)
            }
        }
        None
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let file = SymbolFile {
            files: HashMap::new(),
            functions: Vec::new(),
            inline_origins: HashMap::new(),
        };
        assert_ne!(format!("{file:?}"), "");
    }
}
