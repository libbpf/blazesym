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

use std::fs::File;
use std::io::Read;

use crate::log::trace;
use crate::Error;
use crate::Result;

use super::parser::SymbolParser;
use super::types::SymbolFile;


// # Streaming
//
// This parser streams the input to avoid the need to materialize all of
// it into memory at once (symbol files can be a gigabyte!). As a result,
// we need to iteratively parse.
//
// We do this by repeatedly filling up a buffer with input and asking the
// parser to parse it. The parser will return how much of the input it
// consumed, which we can use to clear space in our buffer and to tell
// if it successfully consumed the whole input when the Reader runs dry.
//
//
// # Handling EOF / Capacity
//
// Having a fix-sized buffer has one fatal issue: if one atomic step
// of the parser needs more than this amount of data, then we won't
// be able to parse it.
//
// This can result in `buf` filling up and `buf.space()` becoming an
// empty slice. This in turn will make the reader yield 0 bytes, and
// we'll treat it like EOF and fail the parse. When this happens, we
// try to double the buffer's size and request more bytes. If we get
// more, hooray! If we don't, then it's a "real" EOF.
//
// The "atom" of our parser is a line, so we need our buffer to be able
// to fit any line. However we actually only have roughly
// *half* this value as our limit, as circular::Buffer will only
// `shift` the buffer's contents if over half of its capacity has been
// drained by `consume` -- and `space()` only grows when a `shift` happens.
//
// I have in fact seen 8kb function names from Rust (thanks generic
// combinators!) and 82kb function names from C++ (thanks 'auto' returns!), so
// we need a buffer size that can grow to at least 200KB. This is a *very* large
// amount to backshift repeatedly, so to keep this under control, we start
// with only a 10KB buffer, which is generous but tolerable.
//
// We should still have *SOME* limit on this to avoid nasty death spirals,
// so let's go with 2MB (MAX_BUFFER_CAPACITY), letting you have a horrifying 1MB
// symbol.
//
// But just *dying* when we hit this point is terrible, so lets have an
// extra layer of robustness: if we ever hit the limit, enter "panic recovery"
// and just start discarding bytes until we hit a newline. Then resume normal
// parsing. The net effect of this is that we just treat this one line as
// corrupt (because statistically it won't even be needed!).

// Allows for at least 80KB symbol names, at most 160KB symbol names (fuzzy
// because of circular).
const MAX_BUFFER_CAPACITY: usize = 1024 * 160;
const INITIAL_BUFFER_CAPACITY: usize = 1024 * 10;


// TODO: We should consider adjusting the parser to just work with a
//       memory mapped file instead and remove the `circular` based
//       logic.
impl SymbolFile {
    /// Parse a [`SymbolFile`] from the given Reader.
    ///
    /// The reader is wrapped in a buffer reader so you shouldn't
    /// buffer the input yourself.
    fn parse<R: Read>(mut input_reader: R) -> Result<SymbolFile> {
        let mut buf = circular::Buffer::with_capacity(INITIAL_BUFFER_CAPACITY);
        let mut parser = SymbolParser::new();
        let mut fully_consumed = false;
        let mut tried_to_grow = false;
        let mut in_panic_recovery = false;
        let mut just_finished_recovering = false;
        let mut total_consumed = 0u64;
        loop {
            if in_panic_recovery {
                // PANIC RECOVERY MODE! DISCARD BYTES UNTIL NEWLINE.
                let input = buf.data();
                if let Some(new_line_idx) = input.iter().position(|&byte| byte == b'\n') {
                    // Hooray, we found a new line! Consume up to and including that, and resume.
                    let amount = new_line_idx + 1;
                    buf.consume(amount);
                    total_consumed += amount as u64;

                    // Back to normal!
                    in_panic_recovery = false;
                    fully_consumed = false;
                    just_finished_recovering = true;
                    parser.lines += 1;
                    trace!("RECOVERY: complete!");
                } else {
                    // No newline, discard everything
                    let amount = input.len();
                    buf.consume(amount);
                    total_consumed += amount as u64;

                    // If the next read returns 0 bytes, then that's a proper EOF!
                    fully_consumed = true;
                }
            }

            // Read the data in, and tell the circular buffer about the new data
            let size = input_reader.read(buf.space())?;
            buf.fill(size);

            if size == 0 {
                // If the reader returned no more bytes, this can be either mean
                // EOF or the buffer is out of capacity. There are a lot of cases
                // to consider, so let's go through them one at a time...
                if just_finished_recovering && !buf.data().is_empty() {
                    // We just finished PANIC RECOVERY, but there's still bytes
                    // in the buffer. Assume that is
                    // parseable and resume normal parsing
                    // (do nothing, fallthrough to normal path).
                } else if fully_consumed {
                    // Success! The last iteration cleared the buffer and we still got
                    // no more bytes, so that's a proper EOF with a complete parse!
                    return Ok(parser.finish())
                } else if !tried_to_grow {
                    // We still have some stuff in the buffer, assume this is because
                    // the buffer is full, and try to make it BIGGER and ask for more again.
                    let new_cap = buf.capacity().saturating_mul(2);
                    if new_cap > MAX_BUFFER_CAPACITY {
                        // TIME TO PANIC!!! This line is catastrophically big, just start
                        // discarding bytes until we hit a newline.
                        trace!("RECOVERY: discarding enormous line {}", parser.lines);
                        in_panic_recovery = true;
                        continue
                    }
                    trace!("parser out of space? trying more ({}KB)", new_cap / 1024);
                    buf.grow(new_cap);
                    tried_to_grow = true;
                    continue
                } else if total_consumed == 0 {
                    // We grew the buffer and still got no more bytes, so it's a proper EOF.
                    // But actually, we never consumed any bytes, so this is an empty file?
                    // Give a better error message for that.
                    return Err(Error::with_invalid_input(
                        "empty SymbolFile (probably something wrong with your debuginfo tooling?)",
                    ))
                } else {
                    // Ok give up, this input is just impossible.
                    return Err(Error::with_invalid_input(
                        "unexpected EOF during parsing of SymbolFile (or a line was too long?)",
                    ))
                }
            } else {
                tried_to_grow = false;
            }

            if in_panic_recovery {
                // Don't run the normal parser while we're still recovering!
                continue
            }
            just_finished_recovering = false;

            // Ask the parser to parse more of the input
            let input = buf.data();
            let consumed = parser.parse_more(input)?;
            total_consumed += consumed as u64;

            // Remember for the next iteration if all the input was consumed.
            fully_consumed = input.len() == consumed;
            buf.consume(consumed);
        }
    }

    /// Parse a [`SymbolFile`] from bytes.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<SymbolFile> {
        Self::parse(bytes)
    }

    /// Parse a [`SymbolFile`] from a file.
    pub fn from_file(file: &File) -> Result<SymbolFile> {
        Self::parse(file)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_symbolfile_from_bytes(symbolfile_bytes: &[u8]) {
        let sym = SymbolFile::from_bytes(symbolfile_bytes).unwrap();

        assert_eq!(sym.files.len(), 1);
        assert_eq!(sym.functions.len(), 1);
    }

    #[test]
    fn symbolfile_from_bytes_with_lf() {
        test_symbolfile_from_bytes(
            b"MODULE Linux x86 ffff0000 bar\nFILE 53 bar.c\nPUBLIC 1234 10 some public\nFUNC 1000 30 10 another func\n1000 30 7 53\n",
        );
    }

    #[test]
    fn symbolfile_from_bytes_with_crlf() {
        test_symbolfile_from_bytes(
            b"MODULE Linux x86 ffff0000 bar\r\nFILE 53 bar.c\r\nPUBLIC 1234 10 some public\r\nFUNC 1000 30 10 another func\r\n1000 30 7 53\r\n",
        );
    }
}
