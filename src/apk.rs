use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use crate::Error;
use crate::Result;


pub(crate) fn create_apk_elf_path(apk: &Path, elf: &Path) -> Result<PathBuf> {
    let mut extension = apk
        .extension()
        .unwrap_or_else(|| OsStr::new("apk"))
        .to_os_string();
    // Append '!' to indicate separation from archive internal contents
    // that follow. This is an Android convention.
    let () = extension.push("!");

    let mut apk = apk.to_path_buf();
    if !apk.set_extension(extension) {
        return Err(Error::with_invalid_data(format!(
            "path {} is not valid",
            apk.display()
        )))
    }

    let path = apk.join(elf);
    Ok(path)
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::ErrorKind;


    /// Check that we can create a path to an ELF inside an APK as expected.
    #[test]
    fn elf_apk_path_creation() {
        let apk = Path::new("/root/test.apk");
        let elf = Path::new("subdir/libc.so");
        let path = create_apk_elf_path(apk, elf).unwrap();
        assert_eq!(path, Path::new("/root/test.apk!/subdir/libc.so"));

        let err = create_apk_elf_path(Path::new(""), elf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }
}
