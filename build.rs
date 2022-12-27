#[cfg(feature = "cheader")]
use std::env;
use std::ffi::OsStr;
use std::ops::Deref as _;
use std::path::Path;
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
            format!(" ({})", code)
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

/// Build `data/test.bin`
fn build_dwarf_v4_test_bin(test_bin: &Path) {
    let mut output = test_bin.to_path_buf();
    assert!(output.set_extension("bin"));

    // Ideally we'd use the `cc` crate here, but it seemingly can't be convinced
    // to create binaries.
    run(
        "cc",
        [
            "-gdwarf-4".as_ref(),
            test_bin.as_os_str(),
            "-o".as_ref(),
            output.as_os_str(),
        ],
    )
    .expect("failed to run `cc`")
}

/// Build the various test binaries.
fn build_test_bins(crate_root: &Path) {
    let path = crate_root.join("data").join("test.c");
    println!("cargo:rerun-if-changed={}", path.display());
    build_dwarf_v4_test_bin(&path);
}

fn main() {
    let crate_dir = env!("CARGO_MANIFEST_DIR");

    build_test_bins(crate_dir.as_ref());

    #[cfg(feature = "cheader")]
    {
        let build_type = env::var("PROFILE").unwrap();
        let target_path = Path::new(&crate_dir).join("target").join(build_type);

        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(cbindgen::Config::from_root_or_default(&crate_dir))
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(target_path.join("blazesym.h"));
    }
}
