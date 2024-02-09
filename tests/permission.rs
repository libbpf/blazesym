#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

mod common;

use std::fs::copy;
use std::fs::metadata;
use std::fs::set_permissions;
use std::io::Error;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::ErrorKind;

use libc::getresuid;

use tempfile::NamedTempFile;

use test_log::test;

use common::as_user;
use common::non_root_uid;


fn symbolize_no_permission_impl(path: &Path) {
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}


/// Check that we fail symbolization as expected when we don't have the
/// permission to open the symbolization source.
#[test]
fn symbolize_no_permission() {
    // We run as root. Even if we limit permissions for a root-owned file we can
    // still access it (unlike the behavior for regular users). As such, we have
    // to work as a different user to check handling of permission denied
    // errors. Because such a change is process-wide, though, we can't do that
    // directly but have to fork first.
    let mut ruid = 0;
    let mut euid = 0;
    let mut suid = 0;

    let result = unsafe { getresuid(&mut ruid, &mut euid, &mut suid) };
    if result == -1 {
        panic!("failed to get user IDs: {}", Error::last_os_error());
    }

    let src = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");

    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path();
    let _bytes = copy(src, path).unwrap();

    let mut permissions = metadata(path).unwrap().permissions();
    // Clear all permissions.
    let () = permissions.set_mode(0o0);
    let () = set_permissions(path, permissions).unwrap();
    let uid = non_root_uid();

    as_user(ruid, uid, || symbolize_no_permission_impl(path))
}
