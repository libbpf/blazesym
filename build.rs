use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::copy;
use std::fs::create_dir_all;
use std::fs::hard_link;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;


/// Retrieve the system's page size.
fn page_size() -> Result<usize> {
    // SAFETY: `sysconf` is always safe to call.
    let rc = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    if rc < 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("failed to retrieve page size: {}", Error::last_os_error()),
        ))
    }
    Ok(usize::try_from(rc).unwrap())
}


/// Format a command with the given list of arguments as a string.
fn format_command<C, A, S>(command: C, args: A) -> String
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().fold(
        command.as_ref().to_string_lossy().into_owned(),
        |mut cmd, arg| {
            cmd += " ";
            cmd += arg.as_ref().to_string_lossy().deref();
            cmd
        },
    )
}

/// Run a command with the provided arguments.
fn run<C, A, S>(command: C, args: A) -> Result<()>
where
    C: AsRef<OsStr>,
    A: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let instance = Command::new(command.as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .args(args.clone())
        .output()
        .map_err(|err| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "failed to run `{}`: {err}",
                    format_command(command.as_ref(), args.clone())
                ),
            )
        })?;

    if !instance.status.success() {
        let code = if let Some(code) = instance.status.code() {
            format!(" ({code})")
        } else {
            " (terminated by signal)".to_string()
        };

        let stderr = String::from_utf8_lossy(&instance.stderr);
        let stderr = stderr.trim_end();
        let stderr = if !stderr.is_empty() {
            format!(": {stderr}")
        } else {
            String::new()
        };

        Err(Error::new(
            ErrorKind::Other,
            format!(
                "`{}` reported non-zero exit-status{code}{stderr}",
                format_command(command, args)
            ),
        ))
    } else {
        Ok(())
    }
}

/// Compile `src` into `dst` using the provided compiler.
fn compile(compiler: &str, src: &Path, dst: &str, options: &[&str]) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    run(
        compiler,
        options
            .iter()
            .map(OsStr::new)
            .chain([src.as_os_str(), "-o".as_ref(), dst.as_os_str()]),
    )
    .unwrap_or_else(|err| panic!("failed to run `{compiler}`: {err}"))
}

/// Compile `src` into `dst` using `cc`.
fn cc(src: &Path, dst: &str, options: &[&str]) {
    compile("cc", src, dst, options)
}

/// Convert debug information contained in `src` into GSYM in `dst` using
/// `llvm-gsymutil`.
fn gsym(src: &Path, dst: impl AsRef<OsStr>) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    let gsymutil = env::var_os("LLVM_GSYMUTIL").unwrap_or_else(|| OsString::from("llvm-gsymutil"));

    run(
        gsymutil,
        ["--convert".as_ref(), src, "--out-file".as_ref(), &dst],
    )
    .expect("failed to run `llvm-gsymutil`")
}

/// Strip all non-debug information from an ELF binary, in an attempt to
/// leave only DWARF remains and necessary ELF bits.
fn dwarf_mostly(src: &Path, dst: &str) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    let _bytes = copy(src, &dst).expect("failed to copy file");

    run("strip", ["--only-keep-debug".as_ref(), dst.as_os_str()]).expect("failed to run `strip`")
}

/// Unpack an xz compressed file.
#[cfg(feature = "xz2")]
fn unpack_xz(src: &Path, dst: &Path) {
    use std::fs::File;
    use std::io::copy;
    use xz2::read::XzDecoder;

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    let src_file = File::options().create(false).read(true).open(src).unwrap();
    let mut decoder = XzDecoder::new_multi_decoder(src_file);

    let mut dst_file = File::options()
        .create(true)
        .truncate(true)
        .read(false)
        .write(true)
        .open(dst)
        .unwrap();

    copy(&mut decoder, &mut dst_file).unwrap();
}

#[cfg(not(feature = "xz2"))]
fn unpack_xz(_src: &Path, _dst: &Path) {
    unimplemented!()
}


/// Put files in a zip archive, uncompressed.
#[cfg(feature = "zip")]
fn zip(files: &[PathBuf], dst: &Path) {
    use std::fs::read as read_file;
    use std::fs::File;
    use std::io::Write as _;
    use zip::write::FileOptions;
    use zip::CompressionMethod;
    use zip::ZipWriter;

    let dst_file = File::options()
        .create(true)
        .truncate(true)
        .read(false)
        .write(true)
        .open(dst)
        .unwrap();
    let dst_dir = dst.parent().unwrap();

    let page_size = page_size().unwrap();
    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(dst_file);
    for file in files {
        let contents = read_file(file).unwrap();
        let path = file.strip_prefix(dst_dir).unwrap();
        // Ensure that members are page aligned so that they can be
        // mmap'ed directly.
        let _align = zip
            .start_file_aligned(
                path.to_str().unwrap(),
                options,
                page_size.try_into().unwrap(),
            )
            .unwrap();
        let _count = zip.write(&contents).unwrap();
    }

    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed={}", dst.display());
}

#[cfg(not(feature = "zip"))]
fn zip(_files: &[PathBuf], _dst: &Path) {
    let _page_size = page_size();
    unimplemented!()
}


/// Prepare the various test files.
fn prepare_test_files(crate_root: &Path) {
    let src = crate_root.join("data").join("test-so.c");
    cc(
        &src,
        "libtest-so.so",
        &["-shared", "-fPIC", "-Wl,--build-id=sha1"],
    );
    cc(
        &src,
        "libtest-so-no-separate-code.so",
        &["-shared", "-fPIC", "-Wl,-z,noseparate-code"],
    );

    let src = crate_root.join("data").join("test-exe.c");
    cc(&src, "test-no-debug.bin", &["-g0", "-Wl,--build-id=none"]);
    cc(&src, "test-dwarf-v4.bin", &["-gdwarf-4"]);
    cc(&src, "test-dwarf-v5.bin", &["-gdwarf-5"]);

    let src = crate_root.join("data").join("test-stable-addresses.c");
    let src_cu2 = crate_root.join("data").join("test-stable-addresses-cu2.c");
    let src_cu2 = src_cu2.to_str().unwrap();
    let ld_script = crate_root.join("data").join("test-stable-addresses.ld");
    let ld_script = ld_script.to_str().unwrap();
    println!("cargo:rerun-if-changed={ld_script}");
    cc(
        &src,
        "test-stable-addresses.bin",
        &[
            "-gdwarf-4",
            "-T",
            ld_script,
            "-Wl,--build-id=none",
            "-O0",
            "-nostdlib",
            // TODO: Eventually we may want to make `cc` multi-input-file aware.
            src_cu2,
        ],
    );
    cc(
        &src,
        "test-stable-addresses-no-dwarf.bin",
        &[
            "-g0",
            "-T",
            ld_script,
            "-Wl,--build-id=none",
            "-O0",
            "-nostdlib",
            // TODO: Eventually we may want to make `cc` multi-input-file aware.
            src_cu2,
        ],
    );

    let src = crate_root.join("data").join("test-stable-addresses.bin");
    gsym(&src, "test.gsym");
    dwarf_mostly(&src, "test-dwarf.bin");

    let src = crate_root.join("data").join("kallsyms.xz");
    let mut dst = src.clone();
    assert!(dst.set_extension(""));
    unpack_xz(&src, &dst);

    let () = create_dir_all(crate_root.join("data").join("zip-dir")).unwrap();
    let () = hard_link(
        crate_root.join("data").join("test-no-debug.bin"),
        crate_root
            .join("data")
            .join("zip-dir")
            .join("test-no-debug.bin"),
    )
    .or_else(|err| {
        if err.kind() == ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(err)
        }
    })
    .unwrap();

    let files = [
        crate_root.join("data").join("test-dwarf.bin"),
        crate_root
            .join("data")
            .join("zip-dir")
            .join("test-no-debug.bin"),
        crate_root.join("data").join("libtest-so.so"),
    ];
    let dst = crate_root.join("data").join("test.zip");
    zip(files.as_slice(), &dst);
}

/// Download a multi-part file split into `part_count` pieces.
#[cfg(feature = "reqwest")]
fn download_multi_part(base_url: &reqwest::Url, part_count: usize, dst: &Path) {
    use std::fs::File;
    use std::io::Write as _;

    let mut dst = File::create(dst).unwrap();
    for part in 1..=part_count {
        let url = reqwest::Url::parse(&format!("{}.part{part}", base_url.as_str())).unwrap();
        let response = reqwest::blocking::get(url).unwrap();
        let _count = dst.write(&response.bytes().unwrap()).unwrap();
    }
}

/// Download large benchmark related files for later use.
#[cfg(feature = "reqwest")]
fn download_bench_files(crate_root: &Path) {
    use reqwest::Url;

    let large_file_url =
        Url::parse("https://github.com/danielocfb/blazesym-data/raw/main/").unwrap();
    let file = "vmlinux-5.17.12-100.fc34.x86_64.xz";

    download_multi_part(
        &large_file_url.join(file).unwrap(),
        2,
        &crate_root.join("data").join(file),
    );
}

#[cfg(not(feature = "reqwest"))]
fn download_bench_files(_crate_root: &Path) {
    unimplemented!()
}

/// Prepare benchmark files.
fn prepare_bench_files(crate_root: &Path) {
    let vmlinux = Path::new(crate_root)
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.xz");

    let mut dst = vmlinux.clone();
    assert!(dst.set_extension(""));
    unpack_xz(&vmlinux, &dst);

    let src = dst.clone();
    let mut dst = vmlinux;
    assert!(dst.set_extension("gsym"));
    let dst = dst.file_name().unwrap();
    gsym(&src, dst);
}

fn main() {
    let crate_dir = env!("CARGO_MANIFEST_DIR");

    if cfg!(feature = "generate-test-files") && !cfg!(feature = "dont-generate-test-files") {
        prepare_test_files(crate_dir.as_ref());
    }

    if cfg!(feature = "generate-bench-files") {
        download_bench_files(crate_dir.as_ref());
        prepare_bench_files(crate_dir.as_ref());
    }

    #[cfg(feature = "generate-c-header")]
    {
        use std::fs::write;

        cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_config(cbindgen::Config::from_root_or_default(crate_dir))
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(Path::new(crate_dir).join("include").join("blazesym.h"));

        // Generate a C program that just included blazesym.h as a basic
        // smoke test that cbindgen didn't screw up completely.
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let out_dir = Path::new(&out_dir);
        let blaze_src_c = out_dir.join("blazesym.c");
        let () = write(
            &blaze_src_c,
            r#"
#include <blazesym.h>

int main() {
  return 0;
}
"#,
        )
        .unwrap();

        let blaze_src_cxx = out_dir.join("blazesym.cpp");
        let _bytes = copy(&blaze_src_c, &blaze_src_cxx).expect("failed to copy file");

        cc(
            &blaze_src_c,
            "blazesym.bin",
            &[
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                Path::new(crate_dir).join("include").to_str().unwrap(),
            ],
        );

        // Best-effort check that C++ can compile the thing as well. Hopefully
        // all flags are supported...
        for cxx in ["clang++", "g++"] {
            if which::which(cxx).is_ok() {
                compile(
                    cxx,
                    &blaze_src_cxx,
                    &format!("blazesym_cxx_{cxx}.bin"),
                    &[
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        Path::new(crate_dir).join("include").to_str().unwrap(),
                    ],
                );
            }
        }
    }
}
