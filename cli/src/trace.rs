use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::io;
use std::io::Write;
use std::mem::MaybeUninit;

use bufio::Writer as StackWriter;

use tracing::field::Field;
use tracing::field::Visit;
use tracing::level_filters::LevelFilter;
use tracing::span;
use tracing::Event;
use tracing::Level;
use tracing::Metadata;
use tracing::Subscriber;
use tracing_subscriber::fmt::format;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::registry::SpanRef;
use tracing_subscriber::Layer;


const RESET: &str = "\x1b[0m";
const GREEN_S: &str = "\x1b[32m";
const GREEN_E: &str = RESET;
const BLUE_S: &str = "\x1b[34m";
const BLUE_E: &str = RESET;
const RED_S: &str = "\x1b[31m";
const RED_E: &str = RESET;
const YELLOW_S: &str = "\x1b[33m";
const YELLOW_E: &str = RESET;
const MAGENTA_S: &str = "\x1b[35m";
const MAGENTA_E: &str = RESET;
const BOLD_S: &str = "\x1b[1m";
const BOLD_E: &str = RESET;


// A replacement of the standard write!() macro that silently ignores
// short writes and automatically converts errors to `std::fmt::Error`.
macro_rules! write {
    ($($arg:tt)*) => {
        match std::write!($($arg)*) {
            Err(err) if err.kind() == io::ErrorKind::WriteZero => Ok(()),
            result => result,
        }.map_err(|_err| fmt::Error)
    };
}


/// An adapter implementing `fmt::Write` for `io::Write` types.
struct Writer<'w, W>(&'w mut W);

impl<W> fmt::Write for Writer<'_, W>
where
    W: io::Write,
{
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let () = write!(self.0, "{s}")?;
        Ok(())
    }
}


/// An enum representing the different values a single field captured in
/// a tracing span/event can have.
#[derive(Debug)]
enum Value<'v> {
    F64(f64),
    I64(i64),
    U64(u64),
    I128(i128),
    U128(u128),
    Bool(bool),
    Str(&'v str),
    Dbg(&'v dyn Debug),
    Err(&'v dyn Error),
}

impl Display for Value<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        use std::write as writefmt;

        match self {
            Self::F64(val) => writefmt!(f, "{val}"),
            Self::I64(val) => writefmt!(f, "{val}"),
            Self::U64(val) => writefmt!(f, "{val}"),
            Self::I128(val) => writefmt!(f, "{val}"),
            Self::U128(val) => writefmt!(f, "{val}"),
            Self::Bool(val) => writefmt!(f, "{val}"),
            Self::Str(val) => writefmt!(f, "{val}"),
            Self::Dbg(val) => writefmt!(f, "{val:?}"),
            Self::Err(val) => writefmt!(f, "{val}"),
        }
    }
}


/// A visitor for "extracting" captured field values from a tracing
/// span/event.
#[derive(Debug)]
struct Visitor<'w, W>
where
    W: ?Sized,
{
    writer: &'w mut W,
}

impl<'w, W> Visitor<'w, W>
where
    W: ?Sized,
{
    fn new(writer: &'w mut W) -> Self {
        Self { writer }
    }

    fn record_value(&mut self, field: &Field, value: Value)
    where
        W: io::Write,
    {
        let name = field.name();
        // Special case the field "message", only printing the value and
        // not the name.
        if name == "message" {
            let _result = write!(self.writer, " {value}");
        } else {
            let _result = write!(self.writer, " {name}={value}");
        }
    }
}

impl<W> Visit for Visitor<'_, W>
where
    W: ?Sized + io::Write,
{
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.record_value(field, Value::Dbg(value))
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_value(field, Value::F64(value))
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, Value::I64(value))
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, Value::U64(value))
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record_value(field, Value::I128(value))
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_value(field, Value::U128(value))
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, Value::Bool(value))
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, Value::Str(value))
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        self.record_value(field, Value::Err(value))
    }
}


#[derive(Clone, Debug)]
pub(crate) struct Builder<T = SystemTime> {
    verbosity: Option<Level>,
    time: Option<T>,
}

impl<T> Builder<T> {
    /// Adjust the maximum verbosity.
    pub fn with_max_verbosity(mut self, verbosity: Option<Level>) -> Self {
        self.verbosity = verbosity;
        self
    }

    /// Adjust the time formatter being used.
    pub fn with_time<U>(self, time: Option<U>) -> Builder<U> {
        let Self { verbosity, time: _ } = self;

        Builder { verbosity, time }
    }

    /// Build the final "layer".
    pub fn build<W>(self, writer: W) -> Hierarchical<T, W> {
        let Self { verbosity, time } = self;

        Hierarchical {
            verbosity: LevelFilter::from(verbosity.unwrap_or(Level::WARN)),
            time,
            writer,
        }
    }
}


pub(crate) struct Hierarchical<T, W> {
    /// The maximum level we are going to emit traces for.
    verbosity: LevelFilter,
    /// The time we use when emitting traces.
    time: Option<T>,
    /// The writer to which we emit traces.
    writer: W,
}

impl Hierarchical<(), ()> {
    pub(crate) fn builder() -> Builder<()> {
        Builder {
            verbosity: None,
            time: None,
        }
    }
}

impl<T, W> Hierarchical<T, W>
where
    T: FormatTime,
    for<'w> &'w W: io::Write,
{
    fn write_names<V, S>(writer: &mut V, span: &SpanRef<'_, S>) -> fmt::Result
    where
        V: io::Write,
        S: for<'lookup> LookupSpan<'lookup>,
    {
        let prefix = if let Some(parent) = &span.parent() {
            let () = Self::write_names(writer, parent)?;
            ":"
        } else {
            ""
        };

        let name = span.name();
        let () = write!(writer, "{prefix}{name}")?;
        Ok(())
    }

    fn write_impl<V, S, F>(
        writer: &mut V,
        time: &Option<T>,
        level: Option<Level>,
        span: Option<&SpanRef<'_, S>>,
        f: F,
    ) -> fmt::Result
    where
        V: io::Write,
        S: for<'lookup> LookupSpan<'lookup>,
        F: FnOnce(&mut dyn io::Write) -> fmt::Result,
    {
        if let Some(time) = time {
            let () = time.format_time(&mut format::Writer::new(&mut Writer(writer)))?;
        }

        match level.unwrap_or_else(|| {
            span.map(|span| *span.metadata().level())
                .unwrap_or(Level::INFO)
        }) {
            Level::TRACE => write!(writer, " {MAGENTA_S}TRACE{MAGENTA_E}")?,
            Level::DEBUG => write!(writer, "  {BLUE_S}INFO{BLUE_E}")?,
            Level::INFO => write!(writer, "  {GREEN_S}INFO{GREEN_E}")?,
            Level::WARN => write!(writer, "  {YELLOW_S}WARN{YELLOW_E}")?,
            Level::ERROR => write!(writer, " {RED_S}ERROR{RED_E}")?,
        }

        if let Some(span) = span {
            let () = write!(writer, " {BOLD_S}")?;
            let () = Self::write_names(writer, span)?;
            let () = write!(writer, "{BOLD_E}:")?;
        }
        let () = f(writer)?;
        Ok(())
    }

    fn write_args<S, F>(&self, span: Option<SpanRef<'_, S>>, level: Option<Level>, f: F)
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
        F: FnOnce(&mut dyn io::Write) -> fmt::Result,
    {
        // We effectively buffer every trace line here while capping
        // line length at a fixed upper limit. In many ways that just
        // simulates a `BufReader`, but we don't heap allocate.
        // Buffering is useful for two reasons:
        // 1) we can lock the writer once instead of for every write call
        // 2) we don't incur a performance penalty for unbuffered output such as stderr
        let mut buffer = [MaybeUninit::<u8>::uninit(); 256];
        let mut writer = StackWriter::new(&mut buffer);

        if let Ok(()) = Self::write_impl(&mut writer, &self.time, level, span.as_ref(), f) {
            let _result = (&self.writer).write_all(writer.written());
            // Always make sure (well, at least attempt) to terminate
            // the line. This is important because we may have truncated
            // the line.
            let _result = (&self.writer).write_all(b"\n");
        }
    }
}

impl<S, T, W> Layer<S> for Hierarchical<T, W>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    T: FormatTime + 'static,
    W: 'static,
    for<'w> &'w W: io::Write,
{
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        // We enable both spans and events, as long as they are visible
        // as per our level filter.
        self.verbosity >= *metadata.level()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.verbosity)
    }

    /// Callback for the creation of a new span.
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id);
        if span.is_some() {
            let write_fn = |w: &mut dyn io::Write| {
                let () = write!(w, " new")?;
                let () = attrs.values().record(&mut Visitor::new(w));
                Ok(())
            };
            self.write_args(span, None, write_fn);
        } else {
            self.write_args(span, None, |w| write!(w, " new"));
        }
    }

    /// Callback for an event.
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let span = if event.is_root() {
            None
        } else {
            ctx.current_span().id().and_then(|id| ctx.span(id))
        };

        let write_fn = |w: &mut dyn io::Write| {
            let () = event.record(&mut Visitor::new(w));
            Ok(())
        };

        self.write_args(span, Some(*event.metadata().level()), write_fn);
    }

    /// Callback for the entering ("activation"?) of a span.
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        self.write_args(ctx.span(id), None, |w| write!(w, " enter"));
    }

    /// Callback for the exiting ("deactivation"?) of a span.
    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        self.write_args(ctx.span(id), None, |w| write!(w, " exit"));
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Make sure that we don't error out writing data to an
    /// insufficiently sized buffer.
    #[test]
    fn value_writing() {
        let val = Value::Str("foobarbaz");
        let mut buffer = [0u8; 4];
        let mut slice = &mut buffer[0..3];
        let () = write!(slice, "{}", val).unwrap();
        assert_eq!(&buffer, b"foo\0");
    }
}
