//! Build script for `blazesym-c`.

use std::env;
use std::ffi::OsStr;
use std::fs::write;
use std::io::Error;
use std::io::Result;
use std::ops::Deref as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;


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
    // We use a self-managed marker file in `OUT_DIR` as the reference
    // time stamp for aligning generated artifacts' mtimes. This
    // prevents Cargo from considering build script outputs as outdated
    // on every build. The marker is written at the end of each build
    // script run (see [`write_mtime_marker`]), so on subsequent runs we
    // can align generated files to the previous run's completion time.
    let marker = Path::new(&out_dir).join(".mtime-ref");

    if !marker.exists() {
        // The marker won't exist on the very first build. Without a
        // reference there is nothing for us to do, so just bail.
        return Ok(())
    }

    let () = run(
        "touch",
        [
            "-m".as_ref(),
            "--reference".as_ref(),
            marker.as_os_str(),
            path.as_os_str(),
        ],
    )?;
    Ok(())
}

/// Write the mtime reference marker into `OUT_DIR`. Must be called at
/// the end of the build script so that the next run can align generated
/// artifacts to this run's completion time.
fn write_mtime_marker() -> Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let marker = Path::new(&out_dir).join(".mtime-ref");
    let () = write(&marker, [])?;
    Ok(())
}

/// Compile `src` into `dst` using the provided compiler.
fn compile(compiler: &str, src: &Path, dst: &str, options: &[&str]) {
    let dst = src.with_file_name(dst);
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", dst.display());

    let () = run(
        compiler,
        options
            .iter()
            .map(OsStr::new)
            .chain([src.as_os_str(), "-o".as_ref(), dst.as_os_str()]),
    )
    .unwrap_or_else(|err| panic!("failed to run `{compiler}`: {err}"));

    let () = adjust_mtime(&dst).unwrap();
}

/// Compile `src` into `dst` using `cc`.
fn cc(src: &Path, dst: &str, options: &[&str]) {
    compile("cc", src, dst, options)
}

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "linux" || target_os == "android" {
        println!("cargo:rustc-cfg=linux");
    }
    println!("cargo:rustc-check-cfg=cfg(linux)");

    let crate_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    #[cfg(feature = "generate-c-header")]
    {
        use std::fs::copy;
        use std::fs::write;

        let mut config = cbindgen::Config::from_root_or_default(&crate_dir);
        config.header = Some(format!(
            r#"/*
 * Please refer to the documentation hosted at
 *
 *   https://docs.rs/{name}/{version}
 */
"#,
            name = env::var("CARGO_PKG_NAME").unwrap(),
            version = env::var("CARGO_PKG_VERSION").unwrap(),
        ));

        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(config)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(crate_dir.join("include").join("blazesym.h"));

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
                crate_dir.join("include").to_str().unwrap(),
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
                        crate_dir.join("include").to_str().unwrap(),
                    ],
                );
            }
        }
    }

    if cfg!(feature = "check-doc-snippets") {
        let src = crate_dir.join("examples").join("input-struct-init.c");
        cc(
            &src,
            "input-struct-init.o",
            &["-I", crate_dir.join("include").to_str().unwrap(), "-c"],
        );
    }

    write_mtime_marker().unwrap();
}
