//! Exercise the library's production Linux backend, rather than the
//! unit-test Keychain fake. Every path is inside a throwaway test home.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;

rush_testenv::sandboxed!();

#[test]
fn default_linux_vault_keeps_private_credentials_separate_by_home() {
    let temp = tempfile::tempdir().unwrap();
    rush_state::set_thread_dir(Some(temp.path().join("first")));
    let first = rush_state::vault();
    assert!(first.service().is_none(), "Linux must use the file backend");
    first.put("example", b"test credential").unwrap();
    assert_eq!(first.get("example").unwrap(), b"test credential");
    let file = temp.path().join("first/logins/example.json");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    rush_state::set_thread_dir(Some(temp.path().join("second")));
    assert!(rush_state::vault().get("example").is_err());
    assert_eq!(first.get("example").unwrap(), b"test credential");
    first.forget("example").unwrap();
    assert!(!file.exists());
    rush_state::set_thread_dir(None);
}
