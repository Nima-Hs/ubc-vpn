//! The Duo method. Usernames and codes are made up.

use super::*;

#[test]
fn methods_have_stable_names() {
    let names = [
        (DuoMethod::Push, "push"),
        (DuoMethod::Call, "call"),
        (DuoMethod::Sms, "sms"),
        (DuoMethod::Passcode, "passcode"),
    ];
    for (method, name) in names {
        assert_eq!(
            serde_json::to_string(&method).unwrap(),
            format!("\"{name}\"")
        );
    }
    assert_eq!(DuoMethod::default(), DuoMethod::Push);
}

#[test]
fn migration_splits_each_known_suffix() {
    let cases = [
        ("user.dept@app", "user.dept", DuoMethod::Push),
        ("user.dept@call", "user.dept", DuoMethod::Call),
        ("user.dept@phone", "user.dept", DuoMethod::Call),
        ("user.dept@sms", "user.dept", DuoMethod::Sms),
        ("user@APP", "user", DuoMethod::Push),
        ("user.dept@Phone", "user.dept", DuoMethod::Call),
    ];
    for (typed, kept, method) in cases {
        let migrated = migrate(Some(typed));
        assert_eq!(migrated, (Some(kept.to_string()), Some(method)), "{typed}");
    }
}

// Security rule: a passcode in a stored username becomes the method, and
// the code itself is not kept.
#[test]
fn migration_drops_a_stored_passcode() {
    let (username, method) = migrate(Some("user.dept@123456"));
    assert_eq!(username.as_deref(), Some("user.dept"));
    assert_eq!(method, Some(DuoMethod::Passcode));
    assert!(holds_code("user.dept@123456"));
    assert!(!holds_code("user.dept@app"));
}

#[test]
fn migration_leaves_an_unknown_suffix_as_typed() {
    for typed in [
        "user.dept@push",
        "user@12345",
        "user@1234567",
        "user@abcdef",
        "user@",
        "user@example.test",
        "user@one@app",
    ] {
        assert_eq!(
            migrate(Some(typed)),
            (Some(typed.to_string()), None),
            "{typed}"
        );
    }
}

#[test]
fn migration_gives_the_default_to_a_plain_username_or_none() {
    assert_eq!(
        migrate(Some("user.dept")),
        (Some("user.dept".to_string()), Some(DuoMethod::Push))
    );
    assert_eq!(migrate(None), (None, Some(DuoMethod::Push)));
}

#[test]
fn the_account_is_the_username_without_a_known_suffix() {
    assert_eq!(account("user.dept@app"), "user.dept");
    assert_eq!(account("user.dept@123456"), "user.dept");
    assert_eq!(account("user.dept"), "user.dept");
    assert_eq!(account("user.dept@other"), "user.dept@other");
}

fn composed(username: &str, method: Option<DuoMethod>, code: Option<&str>) -> String {
    let code = code.map(Secret::new);
    let made = gateway_username(username, method, code.as_ref()).unwrap();
    made.expose().to_string()
}

#[test]
fn the_gateway_username_carries_the_method() {
    assert_eq!(
        composed("user.dept", Some(DuoMethod::Push), None),
        "user.dept@app"
    );
    assert_eq!(
        composed("user.dept", Some(DuoMethod::Call), None),
        "user.dept@call"
    );
    assert_eq!(
        composed("user.dept", Some(DuoMethod::Sms), None),
        "user.dept@sms"
    );
    let passcode = composed("user.dept", Some(DuoMethod::Passcode), Some("012345"));
    assert_eq!(passcode, "user.dept@012345");
    // The second login with texted codes sends one of them.
    let texted = composed("user.dept", Some(DuoMethod::Sms), Some("1234567"));
    assert_eq!(texted, "user.dept@1234567");
    // No method: as typed. A code is used only by the methods that take one.
    assert_eq!(composed("user@other", None, Some("012345")), "user@other");
    assert_eq!(
        composed("user", Some(DuoMethod::Push), Some("012345")),
        "user@app"
    );
}

#[test]
fn a_passcode_is_six_digits() {
    for good in ["000000", "123456", "999999"] {
        assert!(is_passcode(good), "{good}");
    }
    for bad in [
        "",
        "12345",
        "1234567",
        "12345a",
        " 12345",
        "١٢٣٤٥٦",
        "12 456",
        "+12345",
    ] {
        assert!(!is_passcode(bad), "{bad:?}");
    }
    let made = |code: Option<&str>| {
        let code = code.map(Secret::new);
        gateway_username("user", Some(DuoMethod::Passcode), code.as_ref()).map(|_| ())
    };
    assert_eq!(made(None), Err(NoUsername::NoCode));
    assert_eq!(made(Some("12345")), Err(NoUsername::BadCode));
    assert_eq!(made(Some("1234567")), Err(NoUsername::BadCode));
    assert_eq!(made(Some("12345x")), Err(NoUsername::BadCode));
    assert_eq!(made(Some("123456")), Ok(()));
}

#[test]
fn a_texted_code_is_six_to_eight_digits() {
    for good in ["123456", "1234567", "12345678"] {
        assert!(is_texted_code(good), "{good}");
    }
    for bad in ["12345", "123456789", "12345a", ""] {
        assert!(!is_texted_code(bad), "{bad:?}");
    }
    let code = Secret::new("12345");
    let made = gateway_username("user", Some(DuoMethod::Sms), Some(&code));
    assert_eq!(made.map(|_| ()), Err(NoUsername::BadCode));
}

#[test]
fn an_unknown_method_reads_as_none() {
    #[derive(serde::Deserialize)]
    struct Holder {
        #[serde(deserialize_with = "lenient_method")]
        method: Option<DuoMethod>,
    }
    let read = |json: &str| serde_json::from_str::<Holder>(json).unwrap().method;
    assert_eq!(read(r#"{"method":"call"}"#), Some(DuoMethod::Call));
    assert_eq!(read(r#"{"method":null}"#), None);
    assert_eq!(read(r#"{"method":"totp"}"#), None);
    assert_eq!(read(r#"{"method":7}"#), None);
}
