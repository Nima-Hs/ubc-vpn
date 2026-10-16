//! Saved passwords. The rules are tested on the fake keyring. One test uses
//! the real OS keyring, under a throwaway service name, and only on CI: no
//! test ever touches the keyring of the machine it runs on otherwise.

use super::*;

const PROFILE: &str = "11111111111111111111111111111111";
const OTHER: &str = "22222222222222222222222222222222";

fn saved(username: &str, password: &str) -> Saved {
    Saved {
        username: username.to_string(),
        password: Secret::new(password),
        in_doubt: false,
    }
}

// A password in doubt is saved and read back so; one that is not, is not.
#[test]
fn a_password_in_doubt_reads_back_in_doubt() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    let doubted = Saved {
        in_doubt: true,
        ..saved("user.ece@app", "made-up-pass")
    };
    secrets.save(PROFILE, &doubted).unwrap();
    let back = secrets.load(PROFILE).unwrap().unwrap();
    assert!(back.in_doubt);
    assert_eq!(back.password.expose(), "made-up-pass");
    assert_eq!(back.username, "user.ece@app");
    secrets
        .save(PROFILE, &saved("user.ece@app", "made-up-pass"))
        .unwrap();
    assert!(!secrets.load(PROFILE).unwrap().unwrap().in_doubt);
}

// Security rule: a mark this version does not know reads as in doubt, the
// safe side; a first line that is not this form is no password at all.
#[test]
fn an_unknown_mark_reads_as_in_doubt() {
    let fake = FakeSecrets::new();
    for mark in ["in-doubt", "trusted", "later-version", " "] {
        fake.put(PROFILE, &format!("ubc-vpn 1 {mark}\nuser@app\nmade-up"));
        let back = fake.secrets().load(PROFILE).unwrap();
        assert!(back.is_some_and(|b| b.in_doubt), "{mark:?}");
    }
    for other in [
        "ubc-vpn 10\nuser@app\nmade-up",
        "ubc-vpn 1x\nuser@app\nmade-up",
    ] {
        fake.put(PROFILE, other);
        assert!(fake.secrets().load(PROFILE).unwrap().is_none(), "{other:?}");
    }
}

// Whether a password is saved comes from the index; no password is read.
#[test]
fn the_saved_accounts_come_from_the_index() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    assert_eq!(secrets.saved().unwrap(), Vec::<String>::new());
    secrets.save(PROFILE, &saved("a@app", "made-up-1")).unwrap();
    secrets.save(OTHER, &saved("b@app", "made-up-2")).unwrap();
    assert_eq!(secrets.saved().unwrap(), [PROFILE, OTHER]);
    secrets.forget(PROFILE).unwrap();
    assert_eq!(secrets.saved().unwrap(), [OTHER]);
}

// Two processes that use the same folder share one keyring, and nothing
// is written anywhere else: an account that is not plain is refused.
#[cfg(debug_assertions)]
#[test]
fn a_file_backed_keyring_is_shared_through_its_folder() {
    let dir = std::env::temp_dir().join(format!("ubc-vpn-keyring-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let one = file_backed(&dir, false);
    let two = file_backed(&dir, false);
    one.save(PROFILE, &saved("a@app", "made-up-1")).unwrap();
    assert_eq!(
        two.load(PROFILE).unwrap().unwrap().password.expose(),
        "made-up-1"
    );
    assert_eq!(two.saved().unwrap(), [PROFILE]);
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|f| f.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(files, [PROFILE, INDEX]);
    assert!(one.load("../escape").is_err());
    two.forget_all().unwrap();
    assert!(one.load(PROFILE).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_password_is_saved_with_its_username_and_read_back() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    assert!(secrets.load(PROFILE).unwrap().is_none());
    secrets
        .save(PROFILE, &saved("user.ece@app", "made-up-pass\nword"))
        .unwrap();
    let back = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(back.username, "user.ece@app");
    assert_eq!(back.password.expose(), "made-up-pass\nword");
    // Saved again, it replaces what was there.
    secrets
        .save(PROFILE, &saved("user.ece@app", "another-made-up"))
        .unwrap();
    let back = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(back.password.expose(), "another-made-up");
}

// Security rule: the index names every entry, so forgetting every password
// forgets them all, whatever the settings file says now.
#[test]
fn forgetting_all_forgets_every_entry_the_index_names() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    secrets.save(PROFILE, &saved("a@app", "made-up-1")).unwrap();
    secrets.save(OTHER, &saved("b@app", "made-up-2")).unwrap();
    let index = fake
        .entries()
        .into_iter()
        .find(|(account, _)| account == INDEX)
        .map(|(_, accounts)| accounts);
    assert_eq!(
        index.as_deref(),
        Some(format!("{PROFILE}\n{OTHER}").as_str())
    );
    secrets.forget_all().unwrap();
    assert_eq!(fake.entries(), [], "something was left");
    // With nothing saved, it is nothing to do.
    secrets.forget_all().unwrap();
}

// Security rule: forgetting one password removes it and its line in the
// index, and leaves the others.
#[test]
fn forgetting_one_leaves_the_others() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    secrets.save(PROFILE, &saved("a@app", "made-up-1")).unwrap();
    secrets.save(OTHER, &saved("b@app", "made-up-2")).unwrap();
    secrets.forget(PROFILE).unwrap();
    assert!(secrets.load(PROFILE).unwrap().is_none());
    assert_eq!(
        secrets.load(OTHER).unwrap().unwrap().password.expose(),
        "made-up-2"
    );
    let accounts: Vec<String> = fake.entries().into_iter().map(|(a, _)| a).collect();
    assert_eq!(accounts, [OTHER, INDEX]);
    let index = fake
        .entries()
        .into_iter()
        .find(|(a, _)| a == INDEX)
        .unwrap()
        .1;
    assert_eq!(index, OTHER);
    // Forgetting one that is not there is fine; the last one takes the
    // index with it.
    secrets.forget(PROFILE).unwrap();
    secrets.forget(OTHER).unwrap();
    assert_eq!(fake.entries(), []);
}

// An entry that is not in this product's form, as a leftover or another
// program's would be, is not a saved password.
#[test]
fn an_entry_in_another_form_is_no_password() {
    let fake = FakeSecrets::new();
    for odd in [
        "made-up-pass",
        "",
        "ubc-vpn 1",
        "ubc-vpn 1\nuser@app",
        "ubc-vpn 2\nu\np",
    ] {
        fake.put(PROFILE, odd);
        assert!(fake.secrets().load(PROFILE).unwrap().is_none(), "{odd:?}");
    }
}

// What cannot be stored as this product's entries is refused, and nothing
// is written for it.
#[test]
fn what_cannot_be_an_entry_is_refused() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    let refused = [
        (PROFILE, saved("user\nname@app", "made-up")),
        (INDEX, saved("user@app", "made-up")),
        ("", saved("user@app", "made-up")),
        ("a\nb", saved("user@app", "made-up")),
    ];
    for (account, what) in refused {
        assert!(secrets.save(account, &what).is_err(), "{account:?}");
    }
    assert_eq!(fake.entries(), []);
}

// A keyring that cannot be used says so, and the caller asks each time.
#[test]
fn a_keyring_that_cannot_be_used_says_so() {
    let fake = FakeSecrets::new();
    fake.set_unusable(true);
    let secrets = fake.secrets();
    assert_eq!(secrets.load(PROFILE).err(), Some(Error::Unsupported));
    assert_eq!(
        secrets.save(PROFILE, &saved("a@app", "made-up")).err(),
        Some(Error::Unsupported)
    );
    assert_eq!(secrets.forget(PROFILE).err(), Some(Error::Unsupported));
    assert_eq!(secrets.forget_all().err(), Some(Error::Unsupported));
}

// Security rule: neither the password nor the username shows in what is
// printed of a saved password, nor in the index.
#[test]
fn nothing_secret_shows() {
    let secret = saved("user.ece@app", "made-up-pass-0001");
    let shown = format!("{secret:?}");
    assert!(
        !shown.contains("made-up") && !shown.contains("user.ece"),
        "{shown}"
    );
    let fake = FakeSecrets::new();
    fake.secrets().save(PROFILE, &secret).unwrap();
    let index = fake
        .entries()
        .into_iter()
        .find(|(a, _)| a == INDEX)
        .unwrap()
        .1;
    assert!(
        !index.contains("made-up") && !index.contains("user.ece"),
        "{index}"
    );
}

fn index_of(fake: &FakeSecrets) -> Vec<String> {
    let index = fake.entries().into_iter().find(|(a, _)| a == INDEX);
    index.map_or_else(Vec::new, |(_, accounts)| {
        accounts.lines().map(str::to_string).collect()
    })
}

// Security rule: an account is in the index before its entry is written,
// so an entry is never there without its line: when writing the entry
// fails, the line is there all the same.
#[test]
fn the_index_line_is_written_before_the_entry() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    fake.fail_writes_to(PROFILE, true);
    assert!(secrets.save(PROFILE, &saved("a@app", "made-up")).is_err());
    assert_eq!(index_of(&fake), [PROFILE]);
    assert!(secrets.load(PROFILE).unwrap().is_none());
    // Forgetting all still clears it.
    fake.fail_writes_to(PROFILE, false);
    secrets.forget_all().unwrap();
    assert_eq!(fake.entries(), []);
}

// Security rule: an account's line leaves the index only once its entry is
// gone: when deleting the entry fails, the line stays, so the entry can
// still be found and forgotten.
#[test]
fn the_index_line_goes_only_after_the_entry() {
    let fake = FakeSecrets::new();
    let secrets = fake.secrets();
    secrets.save(PROFILE, &saved("a@app", "made-up")).unwrap();
    fake.fail_writes_to(PROFILE, true);
    assert!(secrets.forget(PROFILE).is_err());
    assert_eq!(index_of(&fake), [PROFILE]);
    assert!(secrets.load(PROFILE).unwrap().is_some());
    fake.fail_writes_to(PROFILE, false);
    secrets.forget(PROFILE).unwrap();
    assert_eq!(fake.entries(), []);
}

// Two saves at once in one process: neither drops the other's line.
#[test]
fn saves_at_once_keep_every_line_of_the_index() {
    let fake = FakeSecrets::new();
    fake.slow_index(true);
    let secrets = fake.secrets();
    let accounts: Vec<String> = (0..8).map(|n| format!("{n:032x}")).collect();
    std::thread::scope(|scope| {
        for account in &accounts {
            let secrets = secrets.clone();
            scope.spawn(move || secrets.save(account, &saved("a@app", "made-up")).unwrap());
        }
    });
    let mut index = index_of(&fake);
    index.sort();
    assert_eq!(index, accounts);
}

// Security rule: whatever the keyring says when it fails, what comes out
// is fixed text, never the OS's own message, which can hold a name.
#[test]
fn keyring_errors_never_carry_the_os_message() {
    let os = "the os said user.ece@app made-up-secret";
    let failures = [
        keyring::Error::PlatformFailure(Box::new(std::io::Error::other(os))),
        keyring::Error::NoStorageAccess(Box::new(std::io::Error::other(os))),
        keyring::Error::Invalid(os.to_string(), os.to_string()),
        keyring::Error::TooLong(os.to_string(), 7),
        keyring::Error::BadEncoding(os.as_bytes().to_vec()),
        keyring::Error::NoEntry,
    ];
    for failure in failures {
        let error = unusable(failure);
        let said = format!("{error} {error:?}");
        assert!(
            !said.contains("made-up") && !said.contains("user.ece"),
            "{said}"
        );
        match error {
            Error::Unsupported => {}
            Error::Failed(text) => assert_eq!(text, "the OS keyring could not be used"),
            other => panic!("{other:?}"),
        }
    }
}

// The real OS keyring, under a throwaway service name: Credential Manager
// on the Windows runner, the Keychain on the macOS runner. Only on CI, when
// the workflow asks for it; never on anyone's own machine.
#[cfg(any(windows, target_os = "macos"))]
#[test]
fn the_real_keyring_saves_reads_and_forgets() {
    // Quietly, without the word the workflows look for: only the one CI
    // step that asks for this test runs it.
    if std::env::var_os("CI").is_none() || std::env::var_os("UBC_VPN_REAL_KEYRING").is_none() {
        return;
    }
    let service = format!("{SERVICE}.test-{}", std::process::id());
    let secrets = under(&service);
    secrets.forget_all().unwrap();
    secrets
        .save(PROFILE, &saved("user.ece@app", "made-up-pass-0001"))
        .unwrap();
    secrets
        .save(OTHER, &saved("other@app", "made-up-pass-0002"))
        .unwrap();
    let back = secrets.load(PROFILE).unwrap().unwrap();
    assert_eq!(back.username, "user.ece@app");
    assert_eq!(back.password.expose(), "made-up-pass-0001");
    secrets.forget(PROFILE).unwrap();
    assert!(secrets.load(PROFILE).unwrap().is_none());
    secrets.forget_all().unwrap();
    assert!(secrets.load(OTHER).unwrap().is_none());
    println!("RAN: real keyring");
}
