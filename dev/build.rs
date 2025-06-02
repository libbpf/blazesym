//! Build script for `blazesym-dev`.

use std::env;
use std::env::consts::ARCH;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::create_dir_all;
use std::fs::hard_link;
use std::fs::read_dir;
use std::fs::remove_file;
use std::fs::write;
use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write as _;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn crate_root() -> PathBuf {
    Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf()
}

fn data_dir() -> PathBuf {
    crate_root().join("data")
}

/// Retrieve the system's page size.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn page_size() -> Result<usize> {
    // SAFETY: `sysconf` is always safe to call.
    let rc = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    if rc < 0 {
        return Err(Error::other(format!(
            "failed to retrieve page size: {}",
            Error::last_os_error()
        )))
    }
    Ok(usize::try_from(rc).unwrap())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn page_size() -> Result<usize> {
    unimplemented!()
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
        .env_clear()
        .envs(env::vars().filter(|(k, _)| k == "PATH"))
        .args(args.clone())
        .output()
        .map_err(|err| {
            Error::other(format!(
                "failed to run `{}`: {err}",
                format_command(command.as_ref(), args.clone())
            ))
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

        Err(Error::other(format!(
            "`{}` reported non-zero exit-status{code}{stderr}",
            format_command(command, args)
        )))
    } else {
        Ok(())
    }
}

fn adjust_mtime(path: &Path) -> Result<()> {
    // Note that `OUT_DIR` is only present at runtime.
    let out_dir = env::var("OUT_DIR").unwrap();
    // The $OUT_DIR/output file is (in current versions of Cargo [as of
    // 1.69]) the file containing the reference time stamp that Cargo
    // checks to determine whether something is considered outdated and
    // in need to be rebuild. It's an implementation detail, yes, but we
    // don't rely on it for anything essential.
    let output = Path::new(&out_dir)
        .parent()
        .ok_or_else(|| Error::other("OUT_DIR has no parent"))?
        .join("output");

    if !output.exists() {
        // The file may not exist for legitimate reasons, e.g., when we
        // build for the very first time. If there is not reference there
        // is nothing for us to do, so just bail.
        return Ok(())
    }

    let () = run(
        "touch",
        [
            "-m".as_ref(),
            "--reference".as_ref(),
            output.as_os_str(),
            path.as_os_str(),
        ],
    )?;
    Ok(())
}

enum ArgSpec {
    SrcDst,
    SrcDashODst,
}

/// Invoke `tool` to convert `src` into `dst`.
fn toolize_impl<'p, S, I>(tool: &str, arg_spec: ArgSpec, srcs: S, dst: &Path, options: &[&str])
where
    S: IntoIterator<IntoIter = I>,
    I: Iterator<Item = &'p Path> + Clone,
{
    let srcs = srcs.into_iter();
    for src in srcs.clone() {
        println!("cargo:rerun-if-changed={}", src.display());
    }
    println!("cargo:rerun-if-changed={}", dst.display());

    let args1;
    let args2;
    let args = match arg_spec {
        ArgSpec::SrcDst => {
            args1 = [dst.as_os_str()];
            args1.as_slice()
        }
        ArgSpec::SrcDashODst => {
            args2 = ["-o".as_ref(), dst.as_os_str()];
            args2.as_slice()
        }
    };

    #[allow(clippy::redundant_closure_for_method_calls)]
    let () = run(
        tool,
        options
            .iter()
            .map(OsStr::new)
            .chain(srcs.map(|src| src.as_os_str()))
            .chain(args.iter().map(Deref::deref)),
    )
    .unwrap_or_else(|err| panic!("failed to run `{tool}`: {err}"));

    let () = adjust_mtime(dst).unwrap();
}

fn toolize(tool: &str, src: &Path, dst: impl AsRef<OsStr>, options: &[&str]) {
    let dst = dst.as_ref();
    let dst = src.with_file_name(dst);
    toolize_impl(tool, ArgSpec::SrcDst, [src], &dst, options)
}

fn toolize_o(tool: &str, src: &Path, dst: impl AsRef<OsStr>, options: &[&str]) {
    let dst = dst.as_ref();
    let dst = src.with_file_name(dst);
    toolize_impl(tool, ArgSpec::SrcDashODst, [src], &dst, options)
}

/// Compile `src` into `dst` using `cc`.
fn cc(src: &Path, dst: impl AsRef<OsStr>, options: &[&str]) {
    toolize_o("cc", src, dst, options)
}

/// Compile `src` into `dst` using `rustc`.
fn rustc(src: &Path, dst: impl AsRef<OsStr>, options: &[&str]) {
    toolize_o("rustc", src, dst, options)
}

/// Convert debug information contained in `src` into GSYM in `dst` using
/// `llvm-gsymutil`.
fn gsym(src: &Path, dst: impl AsRef<OsStr>) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());
    println!("cargo:rerun-if-env-changed=LLVM_GSYMUTIL");

    let gsymutil = env::var_os("LLVM_GSYMUTIL").unwrap_or_else(|| OsString::from("llvm-gsymutil"));

    let () = run(
        gsymutil,
        ["--convert".as_ref(), src, "--out-file".as_ref(), &dst],
    )
    .expect("failed to run `llvm-gsymutil`");

    let () = adjust_mtime(&dst).unwrap();
}

/// Invoke `strip` on a copy of `src` placed at `dst`.
fn strip(src: &Path, dst: impl AsRef<OsStr>, options: &[&str]) {
    toolize_o("strip", src, dst, options)
}

/// Strip all DWARF information from an ELF binary, in an attempt to
/// leave only ELF symbols in place.
fn elf(src: &Path, dst: impl AsRef<OsStr>) {
    strip(src, dst, &["--strip-debug"])
}

/// Strip all non-debug information from an ELF binary, in an attempt to
/// leave only DWARF remains.
fn dwarf(src: &Path, dst: impl AsRef<OsStr>) {
    strip(src, dst, &["--only-keep-debug"])
}

/// Invoke `objcopy` on `src` and place the result in `dst`.
fn objcopy(src: &Path, dst: impl AsRef<OsStr>, options: &[&str]) {
    toolize("objcopy", src, dst, options)
}

/// Generate a Breakpad .sym file for the given source.
#[cfg(feature = "dump_syms")]
fn syms(src: &Path, dst: impl AsRef<OsStr>) {
    use dump_syms::dumper;
    use dump_syms::dumper::Config;
    use dump_syms::dumper::FileOutput;
    use dump_syms::dumper::Output;

    let dst = src.with_file_name(dst);

    let mut config = Config::with_output(Output::File(FileOutput::Path(dst)));
    config.check_cfi = false;

    let path = src.to_str().unwrap();
    let () = dumper::single_file(&config, path).unwrap();
}

#[cfg(not(feature = "dump_syms"))]
fn syms(_src: &Path, _dst: impl AsRef<OsStr>) {
    unimplemented!()
}

/// Unpack an xz compressed file.
#[cfg(feature = "xz2")]
fn unpack_xz(src: &Path, dst: &Path) {
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

    let _bytes = copy(&mut decoder, &mut dst_file).unwrap();
    let () = adjust_mtime(dst).unwrap();
}

#[cfg(not(feature = "xz2"))]
fn unpack_xz(_src: &Path, _dst: &Path) {
    unimplemented!()
}


/// Put files in a zip archive, uncompressed.
#[cfg(feature = "zip")]
fn zip(files: &[PathBuf], dst: &Path) {
    use std::fs::read as read_file;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;
    use zip::ZipWriter;

    {
        let dst_file = File::options()
            .create(true)
            .truncate(true)
            .read(false)
            .write(true)
            .open(dst)
            .unwrap();
        let dst_dir = dst.parent().unwrap();

        let page_size = page_size().unwrap();
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            // Ensure that members are page aligned so that they can be
            // mmap'ed directly.
            .with_alignment(page_size.try_into().unwrap());
        let mut zip = ZipWriter::new(dst_file);
        for file in files {
            let contents = read_file(file).unwrap();
            let path = file.strip_prefix(dst_dir).unwrap();
            let () = zip.start_file(path.to_str().unwrap(), options).unwrap();
            let _count = zip.write(&contents).unwrap();
        }
    }

    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed={}", dst.display());
    let () = adjust_mtime(dst).unwrap();
}

#[cfg(not(feature = "zip"))]
fn zip(_files: &[PathBuf], _dst: &Path) {
    let _page_size = page_size();
    unimplemented!()
}


fn cc_stable_addrs(dst: impl AsRef<OsStr>, options: &[&str]) {
    let data_dir = data_dir();
    let src = data_dir.join("test-stable-addrs.c");
    let src_cu2 = data_dir.join("test-stable-addrs-cu2.c");
    let ld_script = data_dir.join("test-stable-addrs.ld");
    println!("cargo:rerun-if-changed={}", ld_script.display());
    println!("cargo:rerun-if-changed={}", src_cu2.display());

    let args = [
        src_cu2.to_str().unwrap(),
        "-T",
        ld_script.to_str().unwrap(),
        "-O0",
        "-nostdlib",
    ]
    .into_iter()
    .chain(options.iter().map(Deref::deref))
    .collect::<Vec<_>>();

    cc(&src, dst, &args)
}

fn cc_test_so(dst: impl AsRef<OsStr>, options: &[&str]) {
    let data_dir = data_dir();
    let src = data_dir.join("test-so.c");
    let map = data_dir.join("test-so.map");
    let wl = format!("-Wl,--version-script,{}", map.to_str().unwrap());
    println!("cargo:rerun-if-changed={}", map.display());

    let args = ["-shared", "-fPIC", &wl]
        .into_iter()
        .chain(options.iter().map(Deref::deref))
        .collect::<Vec<_>>();

    cc(&src, dst, &args);
}


/// Open the file at `path` for writing and append `data` to it.
fn append(path: &Path, data: &[u8]) -> Result<()> {
    {
        let mut file = File::options().append(true).open(path)?;
        let () = file.write_all(data)?;
    }
    let () = adjust_mtime(path).unwrap();
    Ok(())
}

/// Adjust the extension of a file represented via the given `path`.
fn change_ext(path: &Path, ext: &str) -> PathBuf {
    let mut path = path.to_path_buf();
    assert!(path.set_extension(ext));
    path
}

/// Prepare the various test files.
fn prepare_test_files() {
    let data_dir = data_dir();
    let src = data_dir.join("test.rs");
    rustc(
        &src,
        "test-rs.bin",
        &[
            "--crate-type=bin",
            "-C",
            "panic=abort",
            "-C",
            "link-arg=-nostartfiles",
            "-C",
            "opt-level=0",
            "-C",
            "debuginfo=2",
            // Note that despite us specifying the name mangling scheme
            // here, because we want a stable mangled name, the source
            // actually uses a fixed "export name", which really is what
            // is used for the function in question.
            "-C",
            "symbol-mangling-version=v0",
        ],
    );

    cc_test_so("libtest-so.so", &["-Wl,--build-id=sha1"]);
    cc_test_so("libtest-so-32.so", &["-m32", "-Wl,--build-id=sha1"]);
    cc_test_so(
        "libtest-so-no-separate-code.so",
        &["-Wl,--build-id=md5,-z,noseparate-code"],
    );

    let src = data_dir.join("libtest-so.so");
    gsym(&src, "libtest-so.gsym");
    strip(&src, "libtest-so-stripped.so", &[]);
    strip(
        &src,
        "libtest-so-partly-stripped.so",
        &["--keep-symbol=the_ignored_answer"],
    );

    let src = data_dir.join("test-exe.c");
    cc(&src, "test-no-debug.bin", &["-g0", "-Wl,--build-id=none"]);
    cc(&src, "test-dwarf-v2.bin", &["-gstrict-dwarf", "-gdwarf-2"]);
    cc(&src, "test-dwarf-v3.bin", &["-gstrict-dwarf", "-gdwarf-3"]);
    cc(&src, "test-dwarf-v4.bin", &["-gstrict-dwarf", "-gdwarf-4"]);
    cc(&src, "test-dwarf-v5.bin", &["-gstrict-dwarf", "-gdwarf-5"]);
    cc(
        &src,
        "test-dwarf-v5-zlib.bin",
        &["-gstrict-dwarf", "-gdwarf-5", "-gz=zlib"],
    );
    if cfg!(feature = "zstd") {
        cc(
            &src,
            "test-dwarf-v5-zstd.bin",
            &["-gstrict-dwarf", "-gdwarf-5", "-gz=zstd"],
        );
    }

    let src = data_dir.join("test-wait.c");
    cc(&src, "test-wait.bin", &[]);

    let src = data_dir.join("test-mnt-ns.c");
    cc(&src, "test-mnt-ns.bin", &[]);

    let src = data_dir.join("test-block.c");
    let ld_script = data_dir.join("test-block-augmented.ld");
    let args = &[
        "-static",
        "-Wl,--build-id=none",
        "-nostdlib",
        // Just passing the linker script as "regular" input file causes
        // it to "augment" the default linker script.
        ld_script.to_str().unwrap(),
    ];
    cc(&src, "test-block.bin", args);

    cc_stable_addrs(
        "test-stable-addrs.bin",
        &["-gdwarf-4", "-Wl,--build-id=none", "-O0"],
    );
    cc_stable_addrs(
        "test-stable-addrs-compressed-debug-zlib.bin",
        &["-gdwarf-4", "-Wl,--build-id=none", "-O0", "-gz=zlib"],
    );
    if cfg!(feature = "zstd") {
        cc_stable_addrs(
            "test-stable-addrs-compressed-debug-zstd.bin",
            &["-gdwarf-4", "-Wl,--build-id=none", "-gz=zstd"],
        );
    }
    cc_stable_addrs(
        "test-stable-addrs-no-dwarf.bin",
        &["-g0", "-Wl,--build-id=none"],
    );
    cc_stable_addrs(
        "test-stable-addrs-lto.bin",
        &[
            // NB: Keep DWARF 4 for this binary. Cross unit references
            //     as this binary aims to produce only seem to appear in
            //     this version.
            "-gdwarf-4",
            "-flto",
        ],
    );
    cc_stable_addrs("test-stable-addrs-32-no-dwarf.bin", &["-m32", "-g0"]);

    let src = data_dir.join("test-stable-addrs.bin");
    gsym(&src, "test-stable-addrs.gsym");
    // Poor man's stripping of ELF stuff, mostly just to have an alternative to
    // `--only-keep-debug` which actually keeps in tact executable bits.
    strip(
        &src,
        "test-stable-addrs-stripped-elf-with-dwarf.bin",
        &["--keep-section=.debug_*"],
    );
    strip(&src, "test-stable-addrs-stripped.bin", &[]);
    if cfg!(feature = "dump_syms") {
        syms(&src, "test-stable-addrs.sym");
    }

    dwarf(&src, "test-stable-addrs-dwarf-only.dbg");
    let dbg = data_dir.join("test-stable-addrs-dwarf-only.dbg");
    objcopy(
        &src,
        "test-stable-addrs-stripped-with-link.bin",
        &[
            "--strip-all",
            &format!("--add-gnu-debuglink={}", dbg.display()),
        ],
    );

    let elf = data_dir.join("test-stable-addrs-no-dwarf.bin");
    objcopy(
        &src,
        "test-stable-addrs-stripped-with-link-to-elf-only.bin",
        &[
            "--strip-all",
            &format!("--add-gnu-debuglink={}", elf.display()),
        ],
    );

    dwarf(&src, "test-stable-addrs-dwarf-only-wrong-crc.dbg");
    let dbg = data_dir.join("test-stable-addrs-dwarf-only-wrong-crc.dbg");
    objcopy(
        &src,
        "test-stable-addrs-stripped-with-link-to-wrong-crc.bin",
        &[
            "--strip-all",
            &format!("--add-gnu-debuglink={}", dbg.display()),
        ],
    );
    append(&dbg, &[0]).unwrap();


    let dbg = data_dir.join("test-stable-addrs-dwarf-only-non-existent.dbg");
    let () = write(&dbg, [0]).unwrap();
    objcopy(
        &src,
        "test-stable-addrs-stripped-with-link-non-existent.bin",
        &[
            "--strip-all",
            &format!("--add-gnu-debuglink={}", dbg.display()),
        ],
    );
    let () = remove_file(&dbg).unwrap();

    let name = "test-stable-addrs-with-link-to-self.bin";
    let link = data_dir.join(name);
    objcopy(
        &src,
        name,
        &[&format!("--add-gnu-debuglink={}", link.display())],
    );

    let src = data_dir.join("kallsyms.xz");
    unpack_xz(&src, &change_ext(&src, ""));

    let () = create_dir_all(data_dir.join("zip-dir")).unwrap();
    let () = hard_link(
        data_dir.join("test-no-debug.bin"),
        data_dir.join("zip-dir").join("test-no-debug.bin"),
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
        data_dir.join("test-stable-addrs-stripped-elf-with-dwarf.bin"),
        data_dir.join("zip-dir").join("test-no-debug.bin"),
        data_dir.join("libtest-so.so"),
        data_dir.join("libtest-so-no-separate-code.so"),
    ];
    let dst = data_dir.join("test.zip");
    zip(files.as_slice(), &dst);
}


/// Extract vendored libbpf header files into a directory.
#[cfg(feature = "libbpf-sys")]
fn extract_libbpf_headers(target_dir: &Path) {
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::Write;

    let dir = target_dir.join("bpf");
    let () = fs::create_dir_all(&dir).unwrap();
    for (filename, contents) in libbpf_sys::API_HEADERS.iter() {
        let path = dir.as_path().join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }
}


#[cfg(feature = "libbpf-sys")]
fn with_bpf_headers<F>(f: F)
where
    F: FnOnce(&Path),
{
    use tempfile::tempdir;

    let header_parent_dir = tempdir().unwrap();
    let () = extract_libbpf_headers(header_parent_dir.path());
    let () = f(header_parent_dir.path());
}

#[cfg(not(feature = "libbpf-sys"))]
fn with_bpf_headers<F>(_f: F)
where
    F: FnOnce(&Path),
{
    unimplemented!()
}


/// Prepare BPF object files that we need for testing purposes.
fn prepare_bpf_files() {
    let crate_root = crate_root();
    let bpf_dir = crate_root.join("tests").join("bpf");
    let src_dir = bpf_dir.join("src");
    let include = vmlinux::include_path_root().join(ARCH);

    with_bpf_headers(|bpf_hdr_dir| {
        for result in read_dir(&src_dir).unwrap() {
            let entry = result.unwrap();
            let src = entry.file_name();
            let obj = Path::new(&src).with_extension("o");
            let src = src_dir.join(&src);
            let dst = bpf_dir.join(obj);
            let arch = env::var("CARGO_CFG_TARGET_ARCH");
            let arch = arch.as_deref().unwrap_or(ARCH);
            let arch = match arch {
                "x86_64" => "x86",
                "aarch64" => "arm64",
                "powerpc64" => "powerpc",
                "s390x" => "s390",
                "riscv64" => "riscv",
                "loongarch64" => "loongarch",
                "sparc64" => "sparc",
                "mips64" => "mips",
                x => x,
            };

            toolize_o(
                "clang",
                &src,
                &dst,
                &[
                    "-g",
                    "-O2",
                    "-target",
                    "bpf",
                    "-c",
                    "-I",
                    include.to_str().unwrap(),
                    "-I",
                    &format!("{}", bpf_hdr_dir.display()),
                    "-D",
                    &format!("__TARGET_ARCH_{arch}"),
                ],
            );
        }
    })
}


/// Download a multi-part file split into `part_count` pieces.
#[cfg(feature = "reqwest")]
fn download_multi_part(base_url: &reqwest::Url, part_count: usize, dst: &Path) {
    use std::time::Duration;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(360))
        .build()
        .unwrap();
    let mut dst = File::create(dst).unwrap();
    for part in 1..=part_count {
        let url = reqwest::Url::parse(&format!("{}.part{part}", base_url.as_str())).unwrap();
        let response = client.get(url).send().unwrap();
        let _count = dst.write(&response.bytes().unwrap()).unwrap();
    }
}

/// Download large benchmark related files for later use.
#[cfg(feature = "reqwest")]
fn download_bench_files() {
    use reqwest::Url;

    let large_file_url =
        Url::parse("https://github.com/danielocfb/blazesym-data/raw/main/").unwrap();
    let file = "vmlinux-5.17.12-100.fc34.x86_64.xz";
    let dst = data_dir().join(file);
    let () = download_multi_part(&large_file_url.join(file).unwrap(), 2, &dst);
    let () = adjust_mtime(&dst).unwrap();
}

#[cfg(not(feature = "reqwest"))]
fn download_bench_files() {
    unimplemented!()
}

/// Prepare benchmark files.
fn prepare_bench_files() {
    let vmlinux_xz = data_dir().join("vmlinux-5.17.12-100.fc34.x86_64.xz");

    let vmlinux = change_ext(&vmlinux_xz, "");
    unpack_xz(&vmlinux_xz, &vmlinux);

    let dst = change_ext(&vmlinux_xz, "elf");
    let dst = dst.file_name().unwrap();
    elf(&vmlinux, dst);

    let dst = change_ext(&vmlinux_xz, "gsym");
    let dst = dst.file_name().unwrap();
    gsym(&vmlinux, dst);

    let dst = change_ext(&vmlinux_xz, "dwarf");
    let dst = dst.file_name().unwrap();
    dwarf(&vmlinux, dst);

    let dst = change_ext(&vmlinux_xz, "sym");
    let dst = dst.file_name().unwrap();
    syms(&vmlinux, dst);
}

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "linux" || target_os == "android" {
        println!("cargo:rustc-cfg=linux");
    }
    println!("cargo:rustc-check-cfg=cfg(linux)");

    if cfg!(feature = "generate-unit-test-files")
        && !cfg!(feature = "dont-generate-unit-test-files")
    {
        prepare_test_files();
        prepare_bpf_files();
    }

    if cfg!(feature = "generate-large-test-files") {
        download_bench_files();
        prepare_bench_files();
    }
}
