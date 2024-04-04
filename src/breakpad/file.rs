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

use crate::Error;
use crate::Result;

use super::parser::SymbolParser;
use super::types::SymbolFile;


impl SymbolFile {
    /// Parse a [`SymbolFile`] from the given Reader.
    ///
    /// The reader is wrapped in a buffer reader so you shouldn't
    /// buffer the input yourself.
    fn parse(input: &[u8]) -> Result<SymbolFile> {
        let mut parser = SymbolParser::new();
        let consumed = parser.parse(input)?;
        if consumed == 0 {
            return Err(Error::with_invalid_input(
                "empty SymbolFile (probably something wrong with your debuginfo tooling?)",
            ))
        }
        if consumed != input.len() {
            return Err(Error::with_invalid_input(
                "failed to parse input: parser expects more data",
            ))
        }

        let file = parser.finish();
        Ok(file)
    }

    /// Parse a [`SymbolFile`] from bytes.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<SymbolFile> {
        Self::parse(bytes)
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
