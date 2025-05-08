//! **blazesym** is a library that can be used to symbolize addresses. Address
//! symbolization is a common problem in tracing contexts, for example, where
//! users want to reason about functions by name, but low level components
//! report only the "raw" addresses (e.g., in the form of stacktraces).
//!
//! In addition to symbolization, **blazesym** also provides APIs for the
//! reverse operation: looking up addresses from symbol names. That can be
//! useful, for example, for configuring breakpoints or tracepoints.
//!
//! # Overview
//! The crate is organized via public modules that expose functionality
//! pertaining a certain topic. Specifically, these areas are currently covered:
//!
//! - [`symbolize`] covers address symbolization functionality
//! - [`inspect`] contains APIs for inspecting files such as ELF and Gsym to
//!   lookup addresses to symbol names, for example
//! - [`normalize`] exposes address normalization functionality
//!
//! C API bindings are defined in a cross-cutting manner as part of the
//! **blazesym-c** crate (note that Rust code should not have to consume
//! these functions and at the ABI level this module organization has no
//! relevance for C).
//!
//! # Observability
//! **blazesym** optionally integrates with the `tracing` crate and
//! infrastructure and emits spans/events as part of common operations (if the
//! `tracing` feature is enabled). Please refer to the [`tracing`
//! documentation][tracing.rs] for guidance on how to configure event
//! subscription.
//!
//! [tracing.rs]: https://tracing.rs

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(
    not(all(
        feature = "apk",
        feature = "bpf",
        feature = "breakpad",
        feature = "dwarf",
        feature = "gsym"
    )),
    allow(dead_code, unused_imports)
)]
#![cfg_attr(not(linux), allow(dead_code, unused_imports))]


#[cfg(feature = "nightly")]
#[allow(unused_extern_crates)]
extern crate test;

#[macro_use]
mod cfg;
#[cfg(feature = "apk")]
mod apk;
#[cfg(feature = "breakpad")]
mod breakpad;
#[cfg(feature = "dwarf")]
mod dwarf;
mod elf;
mod error;
mod file_cache;
#[cfg(feature = "gsym")]
mod gsym;
mod insert_map;
pub mod inspect;
mod kernel;
mod maps;
mod mmap;
pub mod normalize;
mod once;
mod pathlike;
mod perf_map;
mod pid;
pub mod symbolize;
#[cfg(any(test, feature = "test"))]
mod test_helper;
mod util;
#[cfg(feature = "apk")]
mod zip;

use std::result;


pub use crate::error::Error;
pub use crate::error::ErrorExt;
pub use crate::error::ErrorKind;
pub use crate::error::IntoError;
pub use crate::mmap::Mmap;
pub use crate::normalize::buildid::BuildId;
pub use crate::pid::Pid;

/// A result type using our [`Error`] by default.
pub type Result<T, E = Error> = result::Result<T, E>;


/// A type representing addresses.
pub type Addr = u64;


/// The type of a symbol.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SymType {
    /// The symbol type is unspecified or unknown.
    ///
    /// In input contexts this variant can be used to encompass all
    /// other variants (functions and variables), whereas in output
    /// contexts it means that the type is not known.
    #[default]
    Undefined,
    /// The symbol is a function.
    Function,
    /// The symbol is a variable.
    Variable,
}


/// A type representing an optional value or a default.
#[derive(Clone, Debug, PartialEq)]
pub enum MaybeDefault<T> {
    /// Nothing.
    None,
    /// Use the context-dependent default value.
    Default,
    /// A provided value.
    Some(T),
}

impl<T> From<T> for MaybeDefault<T> {
    #[inline]
    fn from(value: T) -> Self {
        Self::Some(value)
    }
}


/// Utility functionality not specific to any overarching theme.
pub mod helper {
    use super::*;

    pub use crate::normalize::buildid::read_elf_build_id;
    pub use crate::normalize::buildid::read_elf_build_id_from_mmap;
    pub use crate::normalize::ioctl::is_procmap_query_supported;

    cfg_breakpad! {
        pub use crate::breakpad::BreakpadResolver;
    }
    pub use crate::elf::ElfResolver;
    cfg_gsym! {
        use std::path::Path;
        use crate::symbolize::Symbolize;
        use crate::symbolize::ResolvedSym;
        use crate::symbolize::Reason;
        use crate::symbolize::FindSymOpts;
        use crate::gsym;

        /// A symbol resolver for the GSYM format.
        // We provide a wrapper type here to eliminate the need for a lifetime.
        #[derive(Debug)]
        pub struct GsymResolver(gsym::GsymResolver<'static>);

        impl GsymResolver {
            /// Create a `GsymResolver` that loads data from the provided file.
            #[inline]
            pub fn open<P>(path: P) -> Result<Self>
            where
                P: AsRef<Path>,
            {
                Ok(Self(gsym::GsymResolver::open(path)?))
            }
        }

        impl Symbolize for GsymResolver {
            #[inline]
            fn find_sym(&self, addr: Addr, opts: &FindSymOpts) -> Result<Result<ResolvedSym<'_>, Reason>> {
                self.0.find_sym(addr, opts)
            }
        }
    }
}

/// Implementation details shared with other closely related crates.
///
/// NOT PART OF PUBLIC API SURFACE!
#[doc(hidden)]
pub mod __private {
    pub use crate::util::bytes_to_path;
    pub use crate::util::stat;
    pub use crate::util::ReadRaw;

    #[cfg(feature = "apk")]
    pub mod zip {
        pub use crate::zip::Archive;
    }

    #[cfg(feature = "test")]
    pub use crate::test_helper::find_the_answer_fn;
    #[cfg(feature = "test")]
    pub use crate::test_helper::find_the_answer_fn_in_zip;
}


#[cfg(feature = "tracing")]
#[macro_use]
#[allow(unused_imports)]
mod log {
    pub(crate) use tracing::debug;
    pub(crate) use tracing::error;
    pub(crate) use tracing::info;
    pub(crate) use tracing::instrument;
    pub(crate) use tracing::trace;
    pub(crate) use tracing::warn;
}

#[cfg(not(feature = "tracing"))]
#[macro_use]
#[allow(unused_imports)]
mod log {
    macro_rules! debug {
        ($($args:tt)*) => {{
          if false {
            // Make sure to use `args` to prevent any warnings about
            // unused variables.
            let _args = format_args!($($args)*);
          }
        }};
    }
    pub(crate) use debug;
    pub(crate) use debug as error;
    pub(crate) use debug as info;
    pub(crate) use debug as trace;
    pub(crate) use debug as warn;
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use crate::symbolize::FindSymOpts;
    use crate::symbolize::Symbolize as _;


    /// "Test" our public `GsymResolver`.
    #[test]
    fn gsym_resolver() {
        let test_gsym = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addrs.gsym");

        let resolver = helper::GsymResolver::open(test_gsym).unwrap();
        let sym = resolver
            .find_sym(0x2000200, &FindSymOpts::Basic)
            .unwrap()
            .unwrap();
        assert_eq!(sym.name, "factorial");
    }
}
