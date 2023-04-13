use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::copy;
use std::fs::create_dir_all;
use std::fs::hard_link;
use std::io::ErrorKind;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::bail;
use anyhow::Context as _;
use anyhow::Result;

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
        .with_context(|| {
            format!(
                "failed to run `{}`",
                format_command(command.as_ref(), args.clone())
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

        bail!(
            "`{}` reported non-zero exit-status{code}{stderr}",
            format_command(command, args),
        );
    }

    Ok(())
}

/// Compile `src` into `dst` using `cc`.
fn cc(src: &Path, dst: &str, options: &[&str]) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    // Ideally we'd use the `cc` crate here, but it seemingly can't be convinced
    // to create binaries.
    run(
        "cc",
        options
            .iter()
            .map(OsStr::new)
            .chain([src.as_os_str(), "-o".as_ref(), dst.as_os_str()]),
    )
    .expect("failed to run `cc`")
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

    let options = FileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(dst_file);
    for file in files {
        let contents = read_file(file).unwrap();
        let path = file.strip_prefix(dst_dir).unwrap();
        let () = zip.start_file(path.to_str().unwrap(), options).unwrap();
        let _count = zip.write(&contents).unwrap();
    }

    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed={}", dst.display());
}

#[cfg(not(feature = "zip"))]
fn zip(_files: &[PathBuf], _dst: &Path) {
    unimplemented!()
}


/// Prepare the various test files.
fn prepare_test_files(crate_root: &Path) {
    let src = crate_root.join("data").join("test.c");
    cc(&src, "test-no-debug.bin", &["-g0"]);
    cc(&src, "test-dwarf-v4.bin", &["-gdwarf-4"]);
    cc(&src, "test-dwarf-v5.bin", &["-gdwarf-5"]);

    let src = crate_root.join("data").join("test-stable-addresses.c");
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
    ];
    let dst = crate_root.join("data").join("test.zip");
    zip(files.as_slice(), &dst);
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
        prepare_bench_files(crate_dir.as_ref());
    }

    #[cfg(feature = "generate-c-header")]
    {
        cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_config(cbindgen::Config::from_root_or_default(crate_dir))
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(Path::new(crate_dir).join("include").join("blazesym.h"));
    }
}
