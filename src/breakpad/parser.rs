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

//! Parser for Breakpad files.
//!
//! See <https://github.com/google/breakpad/blob/main/docs/symbol_files.md>

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::mem;
use std::ops::BitOr;
use std::ops::Shl;
use std::str;

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_while;
use nom::character::complete::hex_digit1;
use nom::character::complete::multispace0;
use nom::character::complete::space1;
use nom::character::is_digit;
use nom::character::is_hex_digit;
use nom::combinator::cut;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::combinator::opt;
use nom::error::convert_error as stringify_error;
use nom::error::ErrorKind;
use nom::error::ParseError;
use nom::error::VerboseError;
use nom::multi::separated_list1;
use nom::sequence::preceded;
use nom::sequence::terminated;
use nom::sequence::tuple;
use nom::Err;
use nom::IResult;
use nom::Needed;

use super::types::*;

use crate::error::IntoCowStr;
use crate::once::OnceCell;
use crate::Error;
use crate::ErrorExt;
use crate::Result;


fn convert_verbose_nom_error(err: VerboseError<&[u8]>) -> VerboseError<Cow<'_, str>> {
    let errors = err
        .errors
        .into_iter()
        .map(|(err, kind)| (String::from_utf8_lossy(err), kind))
        .collect();
    VerboseError { errors }
}

fn convert_nom_err(err: Err<VerboseError<&[u8]>>) -> Err<VerboseError<Cow<'_, str>>> {
    err.map(convert_verbose_nom_error)
}

fn convert_num_err_to_error((input, err): (&[u8], Err<VerboseError<&[u8]>>)) -> Error {
    let err = convert_nom_err(err);
    match err {
        Err::Incomplete(needed) => match needed {
            Needed::Unknown => Error::with_invalid_input(
                "got incomplete input, additional bytes are necessary to parse",
            ),
            Needed::Size(num) => Error::with_invalid_input(format!(
                "got incomplete input, {num} additional bytes are necessary to parse"
            )),
        },
        Err::Error(err) | Err::Failure(err) => {
            Error::with_invalid_input(stringify_error(String::from_utf8_lossy(input), err))
        }
    }
}


impl ErrorExt for (&[u8], Err<VerboseError<&[u8]>>) {
    type Output = Error;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr,
    {
        convert_num_err_to_error(self).context(context)
    }

    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C,
    {
        convert_num_err_to_error(self).with_context(f)
    }
}


#[derive(Debug)]
enum Line {
    Module,
    Info(()),
    File(u32, String),
    InlineOrigin(u32, String),
    Public(PublicSymbol),
    Function(Function, Vec<SourceLine>, Vec<Inlinee>),
    StackWin(()),
    StackCfi(()),
}

/// Match a hex string, parse it to a u32 or a u64.
fn hex_str<T: Shl<T, Output = T> + BitOr<T, Output = T> + From<u8>>(
    input: &[u8],
) -> IResult<&[u8], T, VerboseError<&[u8]>> {
    // Consume up to max_len digits. For u32 that's 8 digits and for u64 that's 16
    // digits. Two hex digits form one byte.
    let max_len = mem::size_of::<T>() * 2;

    let mut res: T = T::from(0);
    let mut k = 0;
    for v in input.iter().take(max_len) {
        let digit = match (*v as char).to_digit(16) {
            Some(v) => v,
            None => break,
        };
        res = res << T::from(4);
        res = res | T::from(digit as u8);
        k += 1;
    }
    if k == 0 {
        return Err(Err::Error(VerboseError::from_error_kind(
            input,
            ErrorKind::HexDigit,
        )))
    }
    let remaining = &input[k..];
    Ok((remaining, res))
}

/// Match a decimal string, parse it to a u32.
///
/// This is doing everything manually so that we only look at each byte once.
/// With a naive implementation you might be looking at them three times: First
/// you might get a slice of acceptable characters from nom, then you might
/// parse that slice into a str (checking for utf-8 unnecessarily), and then you
/// might parse that string into a decimal number.
fn decimal_u32(input: &[u8]) -> IResult<&[u8], u32, VerboseError<&[u8]>> {
    const MAX_LEN: usize = 10; // u32::MAX has 10 decimal digits
    let mut res: u64 = 0;
    let mut k = 0;
    for v in input.iter().take(MAX_LEN) {
        let digit = *v as char;
        let digit_value = match digit.to_digit(10) {
            Some(v) => v,
            None => break,
        };
        res = res * 10 + digit_value as u64;
        k += 1;
    }
    if k == 0 {
        return Err(Err::Error(VerboseError::from_error_kind(
            input,
            ErrorKind::Digit,
        )))
    }
    let res = u32::try_from(res)
        .map_err(|_| Err::Error(VerboseError::from_error_kind(input, ErrorKind::TooLarge)))?;
    let remaining = &input[k..];
    Ok((remaining, res))
}

/// Take 0 or more non-space bytes.
fn non_space(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
    take_while(|c: u8| c != b' ')(input)
}

/// Accept `\n` with an arbitrary number of preceding `\r` bytes.
///
/// This is different from `line_ending` which doesn't accept `\r` if it isn't
/// followed by `\n`.
fn my_eol(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
    preceded(take_while(|b| b == b'\r'), tag(b"\n"))(input)
}

/// Accept everything except `\r` and `\n`.
///
/// This is different from `not_line_ending` which rejects its input if it's
/// followed by a `\r` which is not immediately followed by a `\n`.
fn not_my_eol(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
    take_while(|b| b != b'\r' && b != b'\n')(input)
}

/// Parse a single byte if it matches the predicate.
///
/// nom has `satisfy`, which is similar. It differs in the argument type of the
/// predicate: `satisfy`'s predicate takes `char`, whereas `single`'s predicate
/// takes `u8`.
fn single(predicate: fn(u8) -> bool) -> impl Fn(&[u8]) -> IResult<&[u8], u8, VerboseError<&[u8]>> {
    move |i: &[u8]| match i.split_first() {
        Some((b, rest)) if predicate(*b) => Ok((rest, *b)),
        _ => Err(Err::Error(VerboseError::from_error_kind(
            i,
            ErrorKind::Satisfy,
        ))),
    }
}

/// Matches a MODULE record.
fn module_line(input: &[u8]) -> IResult<&[u8], (), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("MODULE"), space1)(input)?;
    let (input, _) = cut(tuple((
        terminated(non_space, space1),  // os
        terminated(non_space, space1),  // cpu
        terminated(hex_digit1, space1), // debug id
        terminated(not_my_eol, my_eol), // filename
    )))(input)?;
    Ok((input, ()))
}

/// Matches an INFO URL record.
fn info_url(input: &[u8]) -> IResult<&[u8], (), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("INFO URL"), space1)(input)?;
    let (input, _url) = cut(terminated(map_res(not_my_eol, str::from_utf8), my_eol))(input)?;
    Ok((input, ()))
}

/// Matches other INFO records.
fn info_line(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("INFO"), space1)(input)?;
    cut(terminated(not_my_eol, my_eol))(input)
}

/// Matches a FILE record.
fn file_line(input: &[u8]) -> IResult<&[u8], (u32, String), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("FILE"), space1)(input)?;
    let (input, (id, filename)) = cut(tuple((
        terminated(decimal_u32, space1),
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;
    Ok((input, (id, filename.to_string())))
}

/// Matches an INLINE_ORIGIN record.
fn inline_origin_line(input: &[u8]) -> IResult<&[u8], (u32, String), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("INLINE_ORIGIN"), space1)(input)?;
    let (input, (id, function)) = cut(tuple((
        terminated(decimal_u32, space1),
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;
    Ok((input, (id, function.to_string())))
}

/// Matches a PUBLIC record.
fn public_line(input: &[u8]) -> IResult<&[u8], PublicSymbol, VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("PUBLIC"), space1)(input)?;
    let (input, (_multiple, addr, parameter_size, name)) = cut(tuple((
        opt(terminated(tag("m"), space1)),
        terminated(hex_str::<u64>, space1),
        terminated(hex_str::<u32>, space1),
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;
    Ok((
        input,
        PublicSymbol {
            addr,
            parameter_size,
            name: name.to_string(),
        },
    ))
}

/// Matches line data after a FUNC record.
fn func_line_data(input: &[u8]) -> IResult<&[u8], SourceLine, VerboseError<&[u8]>> {
    let (input, (addr, size, line, file)) = tuple((
        terminated(hex_str::<u64>, space1),
        terminated(hex_str::<u32>, space1),
        terminated(decimal_u32, space1),
        terminated(decimal_u32, my_eol),
    ))(input)?;
    Ok((
        input,
        SourceLine {
            addr,
            size,
            file,
            line,
        },
    ))
}

/// Matches a FUNC record.
fn func_line(input: &[u8]) -> IResult<&[u8], Function, VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("FUNC"), space1)(input)?;
    let (input, (_multiple, addr, size, parameter_size, name)) = cut(tuple((
        opt(terminated(tag("m"), space1)),
        terminated(hex_str::<u64>, space1),
        terminated(hex_str::<u32>, space1),
        terminated(hex_str::<u32>, space1),
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;
    Ok((
        input,
        Function {
            addr,
            size,
            parameter_size,
            name: name.to_string(),
            lines: Vec::new(),
            inlinees: Vec::new(),
        },
    ))
}

/// Matches one entry of the form <addr> <size> which is used at the end of
/// an INLINE record
fn inline_address_range(input: &[u8]) -> IResult<&[u8], (u64, u32), VerboseError<&[u8]>> {
    tuple((terminated(hex_str::<u64>, space1), hex_str::<u32>))(input)
}

/// Matches an INLINE record.
///
/// An INLINE record has the form `INLINE <inline_nest_level> <call_site_line>
/// <call_site_file_id> <origin_id> [<addr> <size>]+`.
fn inline_line(input: &[u8]) -> IResult<&[u8], impl Iterator<Item = Inlinee>, VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("INLINE"), space1)(input)?;
    let (input, (depth, call_line, call_file, origin_id)) = cut(tuple((
        terminated(decimal_u32, space1),
        terminated(decimal_u32, space1),
        terminated(decimal_u32, space1),
        terminated(decimal_u32, space1),
    )))(input)?;
    let (input, address_ranges) = cut(terminated(
        separated_list1(space1, inline_address_range),
        my_eol,
    ))(input)?;
    Ok((
        input,
        address_ranges.into_iter().map(move |(addr, size)| Inlinee {
            addr,
            size,
            call_file,
            call_line,
            depth,
            origin_id,
        }),
    ))
}

/// Matches a STACK WIN record.
fn stack_win_line(input: &[u8]) -> IResult<&[u8], (), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("STACK WIN"), space1)(input)?;
    let (
        input,
        (
            _ty,
            _address,
            _code_size,
            _prologue_size,
            _epilogue_size,
            _parameter_size,
            _saved_register_size,
            _local_size,
            _max_stack_size,
            _has_program_string,
            _rest,
        ),
    ) = cut(tuple((
        terminated(single(is_hex_digit), space1), // ty
        terminated(hex_str::<u64>, space1),       // addr
        terminated(hex_str::<u32>, space1),       // code_size
        terminated(hex_str::<u32>, space1),       // prologue_size
        terminated(hex_str::<u32>, space1),       // epilogue_size
        terminated(hex_str::<u32>, space1),       // parameter_size
        terminated(hex_str::<u32>, space1),       // saved_register_size
        terminated(hex_str::<u32>, space1),       // local_size
        terminated(hex_str::<u32>, space1),       // max_stack_size
        terminated(map(single(is_digit), |b| b == b'1'), space1), // has_program_string
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;

    Ok((input, ()))
}

/// Matches a STACK CFI record.
fn stack_cfi(input: &[u8]) -> IResult<&[u8], (), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("STACK CFI"), space1)(input)?;
    let (input, (_address, _rules)) = cut(tuple((
        terminated(hex_str::<u64>, space1),
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;

    Ok((input, ()))
}

/// Matches a STACK CFI INIT record.
fn stack_cfi_init(input: &[u8]) -> IResult<&[u8], (), VerboseError<&[u8]>> {
    let (input, _) = terminated(tag("STACK CFI INIT"), space1)(input)?;
    let (input, (_address, _size, _rules)) = cut(tuple((
        terminated(hex_str::<u64>, space1),
        terminated(hex_str::<u32>, space1),
        terminated(map_res(not_my_eol, str::from_utf8), my_eol),
    )))(input)?;

    Ok((input, ()))
}

/// Parse any of the line data that can occur in the body of a symbol file.
fn line(input: &[u8]) -> IResult<&[u8], Line, VerboseError<&[u8]>> {
    terminated(
        alt((
            map(info_url, Line::Info),
            map(info_line, |_| Line::Info(())),
            map(file_line, |(i, f)| Line::File(i, f)),
            map(inline_origin_line, |(i, f)| Line::InlineOrigin(i, f)),
            map(public_line, Line::Public),
            map(func_line, |f| Line::Function(f, Vec::new(), Vec::new())),
            map(stack_win_line, Line::StackWin),
            map(stack_cfi_init, Line::StackCfi),
            map(module_line, |_| Line::Module),
        )),
        multispace0,
    )(input)
}

/// A parser for Breakpad symbol files.
///
/// This is basically just a [`SymbolFile`] but with some extra state to handle
/// streaming parsing.
///
/// Use this by repeatedly calling [`parse_more`] until the
/// whole input is consumed. Then call [`finish`].
#[derive(Debug, Default)]
pub struct SymbolParser {
    files: HashMap<u32, String>,
    inline_origins: HashMap<u32, String>,
    publics: Vec<PublicSymbol>,
    functions: Vec<Function>,
    pub lines: u64,
    cur_item: Option<Line>,
}

impl SymbolParser {
    /// Creates a new [`SymbolParser`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses as much of the input as it can, and then returns
    /// how many bytes of the input was used. The *unused* portion of the
    /// input must be resubmitted on subsequent calls to parse_more
    /// (along with more data so we can make progress on the parse).
    pub fn parse_more(&mut self, mut input: &[u8]) -> Result<usize> {
        // We parse the input line-by-line, so trim away any part of the input
        // that comes after the last newline (this is necessary for streaming
        // parsing, as it can otherwise be impossible to tell if a line is
        // truncated.)
        input = if let Some(idx) = input.iter().rposition(|&x| x == b'\n') {
            &input[..idx + 1]
        } else {
            // If there's no newline, then we can't process anything!
            return Ok(0)
        };
        // Remember the (truncated) input so that we can tell how many bytes
        // we've consumed.
        let orig_input = input;

        loop {
            // If there's no more input, then we've consumed all of it
            // (except for the partial line we trimmed away).
            if input.is_empty() {
                return Ok(orig_input.len())
            }

            // First check if we're currently processing sublines of a
            // multi-line item like `FUNC` and `STACK CFI INIT`.
            // If we are, parse the next line as its subline format.
            //
            // If we encounter an error, this probably means we've
            // reached a new item (which ends this one). To handle this,
            // we can just finish off the current item and resubmit this
            // line to the top-level parser (below). If the line is
            // genuinely corrupt, then the top-level parser will also
            // fail to read it.
            //
            // We `take` and then reconstitute the item for borrowing/move
            // reasons.
            match self.cur_item.take() {
                Some(Line::Function(cur, mut lines, mut inlinees)) => {
                    match self.parse_func_subline(input, &mut lines, &mut inlinees) {
                        Ok((new_input, ())) => {
                            input = new_input;
                            self.cur_item = Some(Line::Function(cur, lines, inlinees));
                            self.lines += 1;
                            continue
                        }
                        Err(_) => {
                            self.finish_item(Line::Function(cur, lines, inlinees));
                            continue
                        }
                    }
                }
                Some(Line::StackCfi(cur)) => match stack_cfi(input) {
                    Ok((new_input, _line)) => {
                        input = new_input;
                        self.cur_item = Some(Line::StackCfi(cur));
                        self.lines += 1;
                        continue
                    }
                    Err(_) => {
                        self.finish_item(Line::StackCfi(cur));
                        continue
                    }
                },
                _ => {
                    // We're not parsing sublines, move on to top level parser!
                }
            }

            // Parse a top-level item, and first handle the Result
            let line = match line(input) {
                Ok((new_input, line)) => {
                    // Success! Advance the input.
                    input = new_input;
                    line
                }
                Err(err) => {
                    // The file has a completely corrupt line, conservatively
                    // reject the entire parse.
                    return Err((input, err)).context("failed to parse input")
                }
            };

            // Now store the item in our partial SymbolFile (or make it the cur_item
            // if it has potential sublines we need to parse first).
            match line {
                Line::Module => {
                    // We don't use this but it MUST be the first line
                    if self.lines != 0 {
                        return Err(Error::with_invalid_input(
                            "MODULE line found after the start of the file",
                        ))
                    }
                }
                Line::Info(()) => {}
                Line::File(id, filename) => {
                    self.files.insert(id, filename.to_string());
                }
                Line::InlineOrigin(id, function) => {
                    self.inline_origins.insert(id, function.to_string());
                }
                Line::Public(p) => {
                    self.publics.push(p);
                }
                Line::StackWin(..) => {}
                item @ Line::Function(..) => {
                    // More sublines to parse
                    self.cur_item = Some(item);
                }
                item @ Line::StackCfi(..) => {
                    // More sublines to parse
                    self.cur_item = Some(item);
                }
            }

            // Make note that we've consumed a line of input.
            self.lines += 1;
        }
    }

    /// Parses a single line which is following a FUNC line.
    fn parse_func_subline<'a>(
        &mut self,
        input: &'a [u8],
        lines: &mut Vec<SourceLine>,
        inlinees: &mut Vec<Inlinee>,
    ) -> IResult<&'a [u8], (), VerboseError<&'a [u8]>> {
        // We can have three different types of sublines: INLINE_ORIGIN, INLINE, or line
        // records. Check them one by one.
        // We're not using nom's `alt()` here because we'd need to find a common return
        // type.
        if input.starts_with(b"INLINE_ORIGIN ") {
            let (input, (id, function)) = inline_origin_line(input)?;
            self.inline_origins.insert(id, function);
            return Ok((input, ()))
        }
        if input.starts_with(b"INLINE ") {
            let (input, new_inlinees) = inline_line(input)?;
            inlinees.extend(new_inlinees);
            return Ok((input, ()))
        }
        let (input, line) = func_line_data(input)?;
        lines.push(line);
        Ok((input, ()))
    }

    /// Finish processing an item (cur_item) which had sublines.
    /// We now have all the sublines, so it's complete.
    fn finish_item(&mut self, item: Line) {
        match item {
            Line::Function(mut cur, mut lines, mut inlinees) => {
                let () = lines.sort_by_key(|x| (x.addr, x.size));
                cur.lines = lines;

                let () = inlinees.sort_by_key(|x| (x.depth, x.addr));
                cur.inlinees = inlinees;

                let () = self.functions.push(cur);
            }
            Line::StackCfi(..) => {}
            _ => {
                unreachable!()
            }
        }
    }

    /// Finish the parse and create the final [`SymbolFile`].
    ///
    /// Call this when the parser has consumed all the input.
    pub fn finish(mut self) -> SymbolFile {
        // If there's a pending multiline item, finish it now.
        if let Some(item) = self.cur_item.take() {
            self.finish_item(item);
        }

        // Now sort everything and bundle it up in its final format.
        let () = self
            .functions
            .sort_by(|x, y| x.addr.cmp(&y.addr).then_with(|| x.size.cmp(&y.size)));

        SymbolFile {
            files: self.files,
            functions: self.functions,
            by_name_idx: OnceCell::new(),
            inline_origins: self.inline_origins,
        }
    }
}


#[cfg(test)]
mod tests {
    use nom::error::VerboseErrorKind;

    use super::*;

    #[test]
    fn parse_module_line() {
        let line = b"MODULE Linux x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin\n";
        let rest = &b""[..];
        assert_eq!(module_line(line), Ok((rest, ())));
    }

    #[test]
    fn parse_module_line_filename_spaces() {
        let line = b"MODULE Windows x86_64 D3096ED481217FD4C16B29CD9BC208BA0 firefox x y z\n";
        let rest = &b""[..];
        assert_eq!(module_line(line), Ok((rest, ())));
    }

    /// Sometimes dump_syms on Windows does weird things and produces multiple
    /// carriage returns before the line feed.
    #[test]
    fn parse_module_line_crcrlf() {
        let line = b"MODULE Windows x86_64 D3096ED481217FD4C16B29CD9BC208BA0 firefox\r\r\n";
        let rest = &b""[..];
        assert_eq!(module_line(line), Ok((rest, ())));
    }

    #[test]
    fn parse_info_line() {
        let line = b"INFO blah blah blah\n";
        let bits = &b"blah blah blah"[..];
        let rest = &b""[..];
        assert_eq!(info_line(line), Ok((rest, bits)));
    }

    #[test]
    fn parse_info_line2() {
        let line = b"INFO   CODE_ID   abc xyz\n";
        let bits = &b"CODE_ID   abc xyz"[..];
        let rest = &b""[..];
        assert_eq!(info_line(line), Ok((rest, bits)));
    }

    #[test]
    fn parse_info_url() {
        let line = b"INFO URL https://www.example.com\n";
        let rest = &b""[..];
        assert_eq!(info_url(line), Ok((rest, ())));
    }

    #[test]
    fn parse_file_line() {
        let line = b"FILE 1 foo.c\n";
        let rest = &b""[..];
        assert_eq!(file_line(line), Ok((rest, (1, String::from("foo.c")))));
    }

    #[test]
    fn parse_file_line_spaces() {
        let line = b"FILE  1234  foo bar.xyz\n";
        let rest = &b""[..];
        assert_eq!(
            file_line(line),
            Ok((rest, (1234, String::from("foo bar.xyz"))))
        );
    }

    #[test]
    fn parse_public_line() {
        let line = b"PUBLIC f00d d00d some func\n";
        let rest = &b""[..];
        assert_eq!(
            public_line(line),
            Ok((
                rest,
                PublicSymbol {
                    addr: 0xf00d,
                    parameter_size: 0xd00d,
                    name: "some func".to_string(),
                }
            ))
        );
    }

    #[test]
    fn parse_public_with_m() {
        let line = b"PUBLIC m f00d d00d some func\n";
        let rest = &b""[..];
        assert_eq!(
            public_line(line),
            Ok((
                rest,
                PublicSymbol {
                    addr: 0xf00d,
                    parameter_size: 0xd00d,
                    name: "some func".to_string(),
                }
            ))
        );
    }

    #[test]
    fn parse_func_lines_no_lines() {
        let line =
            b"FUNC c184 30 0 nsQueryInterfaceWithError::operator()(nsID const&, void**) const\n";
        let rest = &b""[..];
        assert_eq!(
            func_line(line),
            Ok((
                rest,
                Function {
                    addr: 0xc184,
                    size: 0x30,
                    parameter_size: 0,
                    name: "nsQueryInterfaceWithError::operator()(nsID const&, void**) const"
                        .to_string(),
                    lines: Vec::new(),
                    inlinees: Vec::new(),
                }
            ))
        );
    }

    #[test]
    fn parse_truncated_func() {
        let line = b"FUNC 1000\n1000 10 42 7\n";
        assert_eq!(
            func_line(line),
            Err(Err::Failure(VerboseError {
                errors: vec![(&line[9..], VerboseErrorKind::Nom(ErrorKind::Space)),],
            }))
        );
    }

    #[test]
    fn parse_inline_line_single_range() {
        let line = b"INLINE 0 3082 52 1410 49200 10\n";
        assert_eq!(
            inline_line(line).unwrap().1.collect::<Vec<_>>(),
            vec![Inlinee {
                depth: 0,
                addr: 0x49200,
                size: 0x10,
                call_file: 52,
                call_line: 3082,
                origin_id: 1410
            }]
        )
    }

    #[test]
    fn parse_inline_line_multiple_ranges() {
        let line = b"INLINE 6 642 8 207 8b110 18 8b154 18\n";
        assert_eq!(
            inline_line(line).unwrap().1.collect::<Vec<_>>(),
            vec![
                Inlinee {
                    depth: 6,
                    addr: 0x8b110,
                    size: 0x18,
                    call_file: 8,
                    call_line: 642,
                    origin_id: 207
                },
                Inlinee {
                    depth: 6,
                    addr: 0x8b154,
                    size: 0x18,
                    call_file: 8,
                    call_line: 642,
                    origin_id: 207
                }
            ]
        )
    }

    #[test]
    fn parse_func_lines_and_lines() {
        let data = b"FUNC 1000 30 10 some func
1000 10 42 7
INLINE_ORIGIN 16 inlined_function_name()
1010 10 52 8
INLINE 0 23 9 16 1020 10
1020 10 62 15
";
        let file = SymbolFile::from_bytes(data).expect("failed to parse!");
        let f = file.functions.first().unwrap();
        assert_eq!(f.addr, 0x1000);
        assert_eq!(f.size, 0x30);
        assert_eq!(f.parameter_size, 0x10);
        assert_eq!(f.name, "some func".to_string());
        assert_eq!(
            f.find_line(0x1000).unwrap(),
            &SourceLine {
                addr: 0x1000,
                size: 0x10,
                file: 7,
                line: 42,
            }
        );
        assert_eq!(
            f.lines,
            vec![
                SourceLine {
                    addr: 0x1000,
                    size: 0x10,
                    file: 7,
                    line: 42,
                },
                SourceLine {
                    addr: 0x1010,
                    size: 0x10,
                    file: 8,
                    line: 52,
                },
                SourceLine {
                    addr: 0x1020,
                    size: 0x10,
                    file: 15,
                    line: 62,
                },
            ]
        );
        assert_eq!(
            f.inlinees,
            vec![Inlinee {
                depth: 0,
                addr: 0x1020,
                size: 0x10,
                call_file: 9,
                call_line: 23,
                origin_id: 16
            }]
        );
    }

    #[test]
    fn parse_nested_inlines() {
        // 0x1000: outer_func() @ <file 15>:60 -> mid_func() @ <file 4>:12 ->
        // inner_func1() <file 7>:42
        // 0x1010: outer_func() @ <file 15>:60 -> mid_func() @ <file 4>:17 ->
        // inner_func2() <file 8>:52
        // 0x1020: outer_func() @ <file 15>:62
        let data = b"FUNC 1000 30 10 outer_func()
INLINE_ORIGIN 1 inner_func_2()
INLINE_ORIGIN 2 mid_func()
INLINE_ORIGIN 3 inner_func_1()
INLINE 0 60 15 2 1000 20
INLINE 1 12 4 3 1000 10
INLINE 1 17 4 1 1010 10
1000 10 42 7
1010 10 52 8
1020 10 62 15
";
        let file = SymbolFile::from_bytes(data).expect("failed to parse!");
        let f = file.functions.first().unwrap();
        assert_eq!(f.addr, 0x1000);
        assert_eq!(f.size, 0x30);
        assert_eq!(f.parameter_size, 0x10);
        assert_eq!(f.name, "outer_func()".to_string());

        // Check the first level of inlining. There is only one inlined call
        // at this level, the call from outer_func() to mid_func(), spanning
        // the range 0x1000..0x1020.
        assert_eq!(f.get_inlinee_at_depth(0, 0x0fff), None);
        assert_eq!(f.get_inlinee_at_depth(0, 0x1000), Some((15, 60, 0x1000, 2)));
        assert_eq!(f.get_inlinee_at_depth(0, 0x100f), Some((15, 60, 0x1000, 2)));
        assert_eq!(f.get_inlinee_at_depth(0, 0x1010), Some((15, 60, 0x1000, 2)));
        assert_eq!(f.get_inlinee_at_depth(0, 0x101f), Some((15, 60, 0x1000, 2)));
        assert_eq!(f.get_inlinee_at_depth(0, 0x1020), None);
        assert_eq!(f.get_inlinee_at_depth(0, 0x102f), None);
        assert_eq!(f.get_inlinee_at_depth(0, 0x1030), None);

        // Check the second level of inlining. Two function calls from mid_func()
        // have been inlined at this level, the call to inner_func_1() and the
        // call to inner_func_2().
        // The code for mid_func() is in file 4, so the location of the calls to
        // inner_func_1() and inner_func_2() are in file 4.
        assert_eq!(f.get_inlinee_at_depth(1, 0x0fff), None);
        assert_eq!(f.get_inlinee_at_depth(1, 0x1000), Some((4, 12, 0x1000, 3)));
        assert_eq!(f.get_inlinee_at_depth(1, 0x100f), Some((4, 12, 0x1000, 3)));
        assert_eq!(f.get_inlinee_at_depth(1, 0x1010), Some((4, 17, 0x1010, 1)));
        assert_eq!(f.get_inlinee_at_depth(1, 0x101f), Some((4, 17, 0x1010, 1)));
        assert_eq!(f.get_inlinee_at_depth(1, 0x1020), None);
        assert_eq!(f.get_inlinee_at_depth(1, 0x102f), None);
        assert_eq!(f.get_inlinee_at_depth(1, 0x1030), None);

        // Check that there are no deeper inline calls.
        assert_eq!(f.get_inlinee_at_depth(2, 0x0fff), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x1000), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x100f), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x1010), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x101f), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x1020), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x102f), None);
        assert_eq!(f.get_inlinee_at_depth(2, 0x1030), None);
    }

    #[test]
    fn parse_func_with_m() {
        let data = b"FUNC m 1000 30 10 some func
1000 10 42 7
1010 10 52 8
1020 10 62 15
";
        let file = SymbolFile::from_bytes(data).expect("failed to parse!");
        let _f = file.functions.first().unwrap();
    }

    #[test]
    fn parse_stack_win_line_program_string() {
        let line =
            b"STACK WIN 4 2170 14 a1 b2 c3 d4 e5 f6 1 $eip 4 + ^ = $esp $ebp 8 + = $ebp $ebp ^ =\n";
        let (rest, ()) = stack_win_line(line).unwrap();
        assert_eq!(rest, &[]);
    }

    #[test]
    fn parse_stack_win_line_frame_data() {
        let line = b"STACK WIN 0 1000 30 a1 b2 c3 d4 e5 f6 0 1\n";
        let (rest, ()) = stack_win_line(line).unwrap();
        assert_eq!(rest, &[]);
    }

    #[test]
    fn parse_stack_cfi() {
        let line = b"STACK CFI deadf00d some rules\n";
        let (rest, ()) = stack_cfi(line).unwrap();
        assert_eq!(rest, &[]);
    }

    #[test]
    fn parse_stack_cfi_init() {
        let line = b"STACK CFI INIT badf00d abc init rules\n";
        let (rest, ()) = stack_cfi_init(line).unwrap();
        assert_eq!(rest, &[]);
    }

    #[test]
    fn parse_stack_cfi_lines() {
        let data = b"STACK CFI INIT badf00d abc init rules
STACK CFI deadf00d some rules
STACK CFI deadbeef more rules
";
        let _file = SymbolFile::from_bytes(data).expect("failed to parse!");
    }

    #[test]
    fn parse_symbol_bytes() {
        let bytes = &b"MODULE Linux x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin
INFO blah blah blah
FILE 0 foo.c
FILE 100 bar.c
PUBLIC abcd 10 func 1
PUBLIC ff00 3 func 2
FUNC 900 30 10 some other func
FUNC 1000 30 10 some func
1000 10 42 7
1010 10 52 8
1020 10 62 15
FUNC 1100 30 10 a third func
STACK WIN 4 900 30 a1 b2 c3 d4 e5 f6 1 prog string
STACK WIN 0 1000 30 a1 b2 c3 d4 e5 f6 0 1
STACK CFI INIT badf00d abc init rules
STACK CFI deadf00d some rules
STACK CFI deadbeef more rules
STACK CFI INIT f00f f0 more init rules

"[..];
        let sym = SymbolFile::from_bytes(bytes).unwrap();
        assert_eq!(sym.files.len(), 2);
        assert_eq!(sym.files.get(&0).unwrap(), "foo.c");
        assert_eq!(sym.files.get(&100).unwrap(), "bar.c");
        assert_eq!(sym.functions.len(), 3);
        let funcs = &sym.functions;
        {
            let f = &funcs[0];
            assert_eq!(f.addr, 0x900);
            assert_eq!(f.size, 0x30);
            assert_eq!(f.parameter_size, 0x10);
            assert_eq!(f.name, "some other func".to_string());
            assert_eq!(f.lines.len(), 0);
        }
        {
            let f = &funcs[1];
            assert_eq!(f.addr, 0x1000);
            assert_eq!(f.size, 0x30);
            assert_eq!(f.parameter_size, 0x10);
            assert_eq!(f.name, "some func".to_string());
            assert_eq!(
                f.lines,
                vec![
                    SourceLine {
                        addr: 0x1000,
                        size: 0x10,
                        file: 7,
                        line: 42,
                    },
                    SourceLine {
                        addr: 0x1010,
                        size: 0x10,
                        file: 8,
                        line: 52,
                    },
                    SourceLine {
                        addr: 0x1020,
                        size: 0x10,
                        file: 15,
                        line: 62,
                    },
                ]
            );
        }
        {
            let f = &funcs[2];
            assert_eq!(f.addr, 0x1100);
            assert_eq!(f.size, 0x30);
            assert_eq!(f.parameter_size, 0x10);
            assert_eq!(f.name, "a third func".to_string());
            assert_eq!(f.lines.len(), 0);
        }
    }

    /// Test that parsing a symbol file with overlapping FUNC/line data works.
    #[test]
    fn parse_with_overlap() {
        //TODO: deal with duplicate PUBLIC records?
        let bytes = b"MODULE Linux x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin
FILE 0 foo.c
PUBLIC abcd 10 func 1
PUBLIC ff00 3 func 2
FUNC 1000 30 10 some func
1000 10 42 0
1000 10 43 0
1001 10 44 0
1001 5 45 0
1010 10 52 0
FUNC 1000 30 10 some func overlap exact
FUNC 1001 30 10 some func overlap end
FUNC 1001 10 10 some func overlap contained
";
        let sym = SymbolFile::from_bytes(&bytes[..]).unwrap();
        assert_eq!(sym.functions.len(), 4);
    }

    #[test]
    fn parse_symbol_bytes_malformed() {
        assert!(SymbolFile::from_bytes(&b"this is not a symbol file\n"[..]).is_err(),);

        assert!(SymbolFile::from_bytes(
            &b"MODULE Linux x86 xxxxxx
FILE 0 foo.c
"[..]
        )
        .is_err(),);

        assert!(SymbolFile::from_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FILE x foo.c
"[..]
        )
        .is_err(),);

        assert!(SymbolFile::from_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FUNC xx 1 2 foo
"[..]
        )
        .is_err(),);

        assert!(SymbolFile::from_bytes(
            &b"MODULE Linux x86 abcd1234 foo
this is some junk
"[..]
        )
        .is_err(),);

        assert!(SymbolFile::from_bytes(
            &b"MODULE Linux x86 abcd1234 foo
FILE 0 foo.c
FILE"[..]
        )
        .is_err(),);

        assert!(SymbolFile::from_bytes(&b""[..]).is_err(),);
    }

    #[test]
    fn parse_stack_win_inconsistent() {
        // Various cases where the has_program_string value is inconsistent
        // with the type of the STACK WIN entry.
        //
        // type=0 (FPO) should go with has_program_string==0 (false)
        // type=4 (FrameData) should go with has_program_string==1 (true)
        //
        // Only 4d93e and 8d93e are totally valid.
        //
        // Current policy is to discard all the other ones, but all the cases
        // are here in case we decide on a more sophisticated heuristic.

        let bytes = b"MODULE Windows x86 D3096ED481217FD4C16B29CD9BC208BA0 firefox-bin
FILE 0 foo.c
STACK WIN 0 1d93e 4 4 0 0 10 0 0 1 1
STACK WIN 0 2d93e 4 4 0 0 10 0 0 1 0
STACK WIN 0 3d93e 4 4 0 0 10 0 0 1 prog string
STACK WIN 0 4d93e 4 4 0 0 10 0 0 0 1
STACK WIN 4 5d93e 4 4 0 0 10 0 0 0 1
STACK WIN 4 6d93e 4 4 0 0 10 0 0 0 0
STACK WIN 4 7d93e 4 4 0 0 10 0 0 0 prog string
STACK WIN 4 8d93e 4 4 0 0 10 0 0 1 prog string
";
        let _sym = SymbolFile::from_bytes(&bytes[..]).unwrap();
    }

    /// Check that we handle overlapping functions reasonably.
    #[test]
    fn function_overlap() {
        let bytes = b"FUNC 1 2 3 x
FUNC 1 3 3 y
";
        let sym = SymbolFile::from_bytes(bytes.as_slice()).unwrap();
        for addr in 1..=3 {
            // We leave it unspecified which function is being reported in
            // case of overlap, so we don't check for the expected name
            // here.
            assert!(sym.find_function(addr).is_some());
        }
        assert_eq!(sym.find_function(4), None);
    }

    #[test]
    fn address_size_overflow() {
        let bytes = b"FUNC 1 2 3 x
ffffffffffffffff 2 0 0
";
        let sym = SymbolFile::from_bytes(bytes.as_slice()).unwrap();
        let fun = sym.find_function(1).unwrap();
        assert_eq!(fun.lines.len(), 1);
        assert!(fun.name == "x");
    }
}
