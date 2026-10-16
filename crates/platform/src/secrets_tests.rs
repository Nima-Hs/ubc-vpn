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
    }
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

// The real OS keyring, under a throwaway service name: Credential Manager
// on the Windows runner, the Keychain on the macOS runner. Only on CI, when
// the workflow asks for it; never on anyone's own machine.
#[cfg(any(windows, target_os = "macos"))]
#[test]
fn the_real_keyring_saves_reads_and_forgets() {
    if std::env::var_os("CI").is_none() || std::env::var_os("UBC_VPN_REAL_KEYRING").is_none() {
        println!("SKIPPED: the real keyring is used on CI only");
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
