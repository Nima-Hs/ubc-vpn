//! The folder the VPN library is loaded from, when the program is started
//! through a link to it, as `/usr/bin/ubc-vpn` and `/usr/local/bin/ubc-vpn`
//! are.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::program_dir;

/// Set in the child: it prints the folder [`program_dir`] found, and nothing
/// else is tested there.
const CHILD: &str = "UBC_VPN_TEST_PROGRAM_DIR_CHILD";

/// A new empty folder for the link, removed when dropped.
struct Folder(PathBuf);

impl Folder {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ubc-vpn-program-dir-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// This test program, started through a link in another folder, finds the
// folder of its real file, not the link's.
#[test]
fn program_dir_is_the_real_programs_folder_when_started_through_a_link() {
    if std::env::var_os(CHILD).is_some() {
        println!("PROGRAM_DIR={}", program_dir().unwrap().display());
        return;
    }
    let real = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let links = Folder::new();
    let link = links.0.join("ubc-vpn");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let output = Command::new(&link)
        .args([
            "--exact",
            "program_dir_tests::program_dir_is_the_real_programs_folder_when_started_through_a_link",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");

    let found: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("PROGRAM_DIR="))
        .collect();
    let expected = real.parent().unwrap();
    assert_eq!(found, [expected.to_str().unwrap()], "{stdout}");
    assert_ne!(Path::new(found[0]), links.0.as_path());
}
