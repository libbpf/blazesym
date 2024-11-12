use std::ffi::c_char;
use std::ffi::CStr;
use std::io;
use std::io::BufRead as _;
use std::io::Cursor;

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

use crate::blaze_err;
#[cfg(doc)]
use crate::blaze_err_last;
use crate::set_last_err;


/// The level at which to emit traces.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum blaze_trace_lvl {
    /// Emit all trace events.
    ///
    /// This is the most verbose level and includes all others.
    BLAZE_LVL_TRACE,
    /// Emit debug traces and above.
    ///
    /// This level excludes traces emitted with "TRACE" verbosity.
    BLAZE_LVL_DEBUG,
    /// Emit info level traces and above.
    ///
    /// This level excludes traces emitted with "TRACE" or "DEBUG"
    /// verbosity.
    BLAZE_LVL_INFO,
    /// Only emit warnings.
    BLAZE_LVL_WARN,
}


impl From<blaze_trace_lvl> for LevelFilter {
    fn from(other: blaze_trace_lvl) -> Self {
        match other {
            blaze_trace_lvl::BLAZE_LVL_WARN => LevelFilter::WARN,
            blaze_trace_lvl::BLAZE_LVL_INFO => LevelFilter::INFO,
            blaze_trace_lvl::BLAZE_LVL_DEBUG => LevelFilter::DEBUG,
            blaze_trace_lvl::BLAZE_LVL_TRACE => LevelFilter::TRACE,
        }
    }
}


/// The signature of a callback function as passed to [`blaze_trace`].
pub type blaze_trace_cb = extern "C" fn(*const c_char);


struct LineWriter<F> {
    /// A buffer used for formatting traces.
    buf: Vec<u8>,
    /// The callback used for emitting formatted traces.
    f: F,
}

impl<F> LineWriter<F> {
    fn new(f: F) -> Self {
        Self { buf: Vec::new(), f }
    }
}

impl<F> io::Write for LineWriter<F>
where
    F: FnMut(&CStr),
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let delim = b'\n';
        let mut read = 0;
        let mut cursor = Cursor::new(buf);

        loop {
            let n = cursor.read_until(delim, &mut self.buf)?;
            if n == 0 {
                break Ok(read)
            }
            read += n;

            if self.buf.last() == Some(&delim) {
                // We reached a complete line. Emit it via the callback.
                let () = self.buf.push(b'\0');
                // SAFETY: We properly NUL terminated the C string.
                let cstr = unsafe { CStr::from_ptr(self.buf.as_ptr().cast()) };
                let () = (self.f)(cstr);
                let () = self.buf.clear();
            } else {
                break Ok(read)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // We flush on a per-line basis.
        Ok(())
    }
}


/// Enable the main library's tracing infrastructure and invoke a
/// callback function for each emitted trace line.
///
/// The provided [`blaze_trace_lvl`] determines what kind of traces are
/// emitted.
///
/// This function should be invoked at most once. Subsequent invocations
/// will not affect tracing behavior.
///
/// On error the function sets the thread's last error to indicate the
/// problem encountered. Use [`blaze_err_last`] to retrieve this error.
///
/// # Notes
/// - the format of emitted lines is unspecified and subject to change; it is
///   meant for human consumption and not programmatic evaluation
#[no_mangle]
pub extern "C" fn blaze_trace(lvl: blaze_trace_lvl, cb: blaze_trace_cb) {
    let format = fmt::format().with_target(false).compact();
    let subscriber = FmtSubscriber::builder()
        .event_format(format)
        .with_max_level(LevelFilter::from(lvl))
        .with_span_events(FmtSpan::FULL)
        .with_timer(SystemTime)
        .with_writer(move || {
            let emit = move |cstr: &CStr| cb(cstr.as_ptr());
            LineWriter::new(emit)
        })
        .finish();

    let err = set_global_subscriber(subscriber)
        .map(|()| blaze_err::BLAZE_ERR_OK)
        .unwrap_or(blaze_err::BLAZE_ERR_ALREADY_EXISTS);
    let () = set_last_err(err);
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::cmp::max;
    use std::hash::BuildHasher as _;
    use std::hash::Hasher as _;
    use std::hash::RandomState;
    use std::io::Write as _;

    use blazesym::__private::ReadRaw;


    /// Test that we can convert `blaze_trace_lvl` values into their
    /// `LevelFilter` counter parts.
    #[test]
    fn lvl_conversions() {
        use super::blaze_trace_lvl::*;

        assert_eq!(LevelFilter::from(BLAZE_LVL_DEBUG), LevelFilter::DEBUG);
        assert_eq!(LevelFilter::from(BLAZE_LVL_INFO), LevelFilter::INFO);
        assert_eq!(LevelFilter::from(BLAZE_LVL_TRACE), LevelFilter::TRACE);
        assert_eq!(LevelFilter::from(BLAZE_LVL_WARN), LevelFilter::WARN);
    }

    /// Check that our `CbWriter` works as expected.
    #[test]
    fn line_writing() {
        let data = br"INFO symbolize: new src=Process(self) addrs=AbsAddr([0x0])
INFO symbolize: enter src=Process(self) addrs=AbsAddr([0x0])
INFO symbolize:handle_unknown_addr: new src=Process(self) addrs=AbsAddr([0x0]) addr=0x0
INFO symbolize:handle_unknown_addr: enter src=Process(self) addrs=AbsAddr([0x0]) addr=0x0
INFO symbolize:handle_unknown_addr: exit src=Process(self) addrs=AbsAddr([0x0]) addr=0x0
INFO symbolize:handle_unknown_addr: close src=Process(self) addrs=AbsAddr([0x0]) addr=0x0
INFO symbolize: exit src=Process(self) addrs=AbsAddr([0x0])
INFO symbolize: close src=Process(self) addrs=AbsAddr([0x0])
";
        let mut to_write = &data[..];

        fn rand() -> u64 {
            RandomState::new().build_hasher().finish()
        }

        let mut bytes = Vec::new();
        let mut writer = LineWriter::new(|line: &CStr| {
            let data = line.to_bytes();
            assert!(data.ends_with(b"\n"), "{line:?}");
            assert!(
                !data[..data.len().saturating_sub(1)].contains(&b'\n'),
                "{line:?}"
            );
            let () = bytes.extend_from_slice(data);
        });

        // Simulate writing of all of `data` into our `LineWriter`
        // instance in arbitrary length chunks and check that it emits
        // back all the lines contained in the original data.
        while !to_write.is_empty() {
            let cnt = max(rand() % (max(to_write.len() as u64 / 2, 1)), 1) as usize;
            let data = to_write.read_slice(cnt).unwrap();
            let n = writer.write(data).unwrap();
            assert_ne!(n, 0);

            if rand() % 2 == 1 {
                let () = writer.flush().unwrap();
            }
        }

        assert_eq!(to_write, &[] as &[u8]);
        assert_eq!(bytes.as_slice(), data);
    }
}
