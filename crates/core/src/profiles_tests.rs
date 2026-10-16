//! Settings version 2 and its rules. Names, usernames and routes are made
//! up.

use super::*;

fn net(text: &str) -> Ipv4Net {
    text.parse().unwrap()
}

fn id(n: u8) -> ProfileId {
    ProfileId::from_random([n; 16])
}

fn routes(subnets: &[&str], domains: &[&str]) -> RouteSet {
    RouteSet {
        subnets: subnets.iter().map(|s| net(s)).collect(),
        dns_domains: domains.iter().map(|d| d.to_string()).collect(),
    }
}

/// Two profiles: the first, active, and "Lab" with the id `id(2)`.
fn two() -> Profiles {
    let mut all = Profiles::fresh();
    let lab = routes(&["10.255.0.0/16"], &["lab.example.test"]);
    all.create(id(2), "Lab", Some("user.lab@app"), lab, true)
        .unwrap();
    all
}

#[test]
fn ids_are_32_lowercase_hex_digits() {
    assert_eq!(
        ProfileId::first().as_str(),
        "00000000000000000000000000000001"
    );
    assert_eq!(id(0xab).as_str(), "abababababababababababababababab");
    for bad in [
        "",
        "0000000000000000000000000000001",
        "000000000000000000000000000000001",
        "ABABABABABABABABABABABABABABABAB",
        "gggggggggggggggggggggggggggggggg",
        "../../../../../../../../../../..",
    ] {
        assert!(bad.parse::<ProfileId>().is_err(), "{bad:?}");
        let json = format!("\"{bad}\"");
        assert!(serde_json::from_str::<ProfileId>(&json).is_err(), "{bad:?}");
    }
}

#[test]
fn a_user_with_no_file_has_one_empty_profile() {
    let fresh = Profiles::read(None).unwrap();
    assert_eq!(fresh, Profiles::fresh());
    assert_eq!(fresh.profiles.len(), 1);
    let first = fresh.active();
    assert_eq!(
        (first.id.clone(), first.name.as_str()),
        (ProfileId::first(), FIRST_PROFILE_NAME)
    );
    assert_eq!(first.routes, RouteSet::default());
    assert_eq!(fresh.global.start, StartMode::Off);
    assert!(!fresh.global.auto_connect);
    assert_eq!(fresh.check(), Ok(()));
}

// Security rule: settings from before profiles lose nothing. They become
// one active profile with the same username, routes and choice about the
// password, and the file's other fields stay. A route the rules would now
// refuse is kept as it was: dropping a route the user chose would be worse.
#[test]
fn version_1_settings_become_one_profile_and_lose_nothing() {
    let v1 = r#"{"username":"user.ece@app","save_password":true,"theme":"dark",
        "routes":{"subnets":["10.255.0.0/16","10.0.0.0/7"],"dns_domains":["ece.example.test"]}}"#;
    let read = Profiles::read(Some(v1)).unwrap();
    assert_eq!(read.profiles.len(), 1);
    let profile = read.active();
    assert_eq!(profile.id, ProfileId::first());
    assert_eq!(profile.name, FIRST_PROFILE_NAME);
    assert_eq!(profile.username.as_deref(), Some("user.ece@app"));
    assert!(profile.save_password);
    assert_eq!(
        profile.routes,
        routes(&["10.255.0.0/16", "10.0.0.0/7"], &["ece.example.test"])
    );
    assert_eq!(read.other.get("theme"), Some(&Value::from("dark")));
    // The same id every time it is read, until it is saved.
    assert_eq!(Profiles::read(Some(v1)).unwrap(), read);

    // Saved, it is version 2, without the old fields, and reads back the
    // same.
    let text = read.to_text();
    let saved: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(saved["version"], 2);
    for moved in ["username", "routes", "save_password"] {
        assert!(saved.get(moved).is_none(), "{moved} is still at the top");
    }
    assert_eq!(saved["theme"], "dark");
    assert_eq!(Profiles::read(Some(&text)).unwrap(), read);
    // And an explicit version 1 is read the same way.
    let explicit = v1.replacen('{', r#"{"version":1,"#, 1);
    assert_eq!(Profiles::read(Some(&explicit)).unwrap(), read);
}

#[test]
fn version_2_has_a_stable_shape() {
    let text = Profiles::fresh().to_text();
    let compact: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        compact.to_string(),
        r#"{"global":{"active_profile":"00000000000000000000000000000001","auto_connect":false,"start":"off"},"profiles":[{"id":"00000000000000000000000000000001","name":"UBC VPN","routes":{"dns_domains":[],"subnets":[]},"save_password":false,"username":null}],"version":2}"#
    );
}

// What a newer version stored is kept, wherever it is.
#[test]
fn fields_this_version_does_not_know_are_kept() {
    let mut text = two().to_text();
    let mut file: Value = serde_json::from_str(&text).unwrap();
    file["future"] = Value::from(1);
    file["global"]["theme"] = Value::from("dark");
    file["profiles"][1]["colour"] = Value::from("teal");
    text = file.to_string();
    let mut read = Profiles::read(Some(&text)).unwrap();
    read.rename(&id(2), "Lab 2").unwrap();
    let saved: Value = serde_json::from_str(&read.to_text()).unwrap();
    assert_eq!(saved["future"], 1);
    assert_eq!(saved["global"]["theme"], "dark");
    assert_eq!(saved["profiles"][1]["colour"], "teal");
    assert_eq!(saved["profiles"][1]["name"], "Lab 2");
}

// A newer version, or a version 2 file that breaks a rule, is unreadable:
// the way out is `settings reset`, never a guess.
#[test]
fn files_that_break_the_rules_are_unreadable() {
    let good: Value = serde_json::from_str(&two().to_text()).unwrap();
    let spoiled = |spoil: &dyn Fn(&mut Value)| {
        let mut file = good.clone();
        spoil(&mut file);
        file.to_string()
    };
    let cases: Vec<(&str, String)> = vec![
        ("newer", spoiled(&|f| f["version"] = Value::from(3))),
        (
            "version as text",
            spoiled(&|f| f["version"] = Value::from("2")),
        ),
        (
            "no profiles",
            spoiled(&|f| f["profiles"] = Value::Array(vec![])),
        ),
        (
            "active is no profile",
            spoiled(&|f| f["global"]["active_profile"] = Value::from(id(9).as_str())),
        ),
        (
            "no active",
            spoiled(&|f| {
                f["global"]
                    .as_object_mut()
                    .unwrap()
                    .remove("active_profile");
            }),
        ),
        (
            "bad id",
            spoiled(&|f| f["profiles"][1]["id"] = Value::from("LAB")),
        ),
        (
            "same id twice",
            spoiled(&|f| f["profiles"][1]["id"] = f["profiles"][0]["id"].clone()),
        ),
        (
            "same name in another case",
            spoiled(&|f| f["profiles"][1]["name"] = Value::from("ubc vpn")),
        ),
        (
            "empty name",
            spoiled(&|f| f["profiles"][1]["name"] = Value::from("")),
        ),
        (
            "misleading name",
            spoiled(&|f| f["profiles"][1]["name"] = Value::from("Lab\u{202e}")),
        ),
        (
            "misleading username",
            spoiled(&|f| f["profiles"][1]["username"] = Value::from("user\u{1b}[2J")),
        ),
        ("not an object", "[]".to_string()),
        ("not JSON", "{".to_string()),
    ];
    for (case, text) in cases {
        assert_eq!(
            Profiles::read(Some(&text)),
            Err(SettingsFailureCode::Unreadable),
            "{case}"
        );
    }
    let many = spoiled(&|f| {
        let profile = f["profiles"][1].clone();
        let list = f["profiles"].as_array_mut().unwrap();
        for n in 0..MAX_PROFILES {
            let mut more = profile.clone();
            more["id"] = Value::from(id(100 + n as u8).as_str());
            more["name"] = Value::from(format!("Lab {n}"));
            list.push(more);
        }
    });
    assert_eq!(
        Profiles::read(Some(&many)),
        Err(SettingsFailureCode::Unreadable)
    );
}

#[test]
fn names_are_trimmed_short_and_plain() {
    assert_eq!(check_name("  Lab  "), Ok("Lab".to_string()));
    assert_eq!(
        check_name("Département ECE"),
        Ok("Département ECE".to_string())
    );
    assert_eq!(
        check_name(&"x".repeat(MAX_NAME_CHARS)).map(|n| n.len()),
        Ok(64)
    );
    for bad in [
        "".to_string(),
        "   ".to_string(),
        "x".repeat(MAX_NAME_CHARS + 1),
        "Lab\n2".to_string(),
        "Lab\u{1b}[31m".to_string(),
        "\u{202e}baL".to_string(),
        "Lab\u{200b}".to_string(),
    ] {
        assert_eq!(
            check_name(&bad),
            Err(ProfileFailureCode::BadName),
            "{bad:?}"
        );
    }
}

// Security rule: a refused change changes nothing.
#[test]
fn profiles_are_made_with_the_rules_and_a_refusal_changes_nothing() {
    let mut all = two();
    assert_eq!(all.profiles[1].name, "Lab");
    assert_eq!(
        all.global.active_profile,
        ProfileId::first(),
        "made, not made active"
    );
    let before = all.clone();
    let none = RouteSet::default;
    let refused = [
        (
            all.clone().create(id(3), " ", None, none(), false),
            ProfileFailureCode::BadName,
        ),
        (
            all.clone().create(id(3), "LAB", None, none(), false),
            ProfileFailureCode::NameTaken,
        ),
        (
            all.clone().create(id(3), "Home", Some("  "), none(), false),
            ProfileFailureCode::BadUsername,
        ),
        (
            all.clone()
                .create(id(3), "Home", Some("a\u{7}b"), none(), false),
            ProfileFailureCode::BadUsername,
        ),
    ];
    for (result, expected) in refused {
        assert_eq!(result, Err(expected));
    }
    for n in 0..MAX_PROFILES - 2 {
        all.create(id(10 + n as u8), &format!("P{n}"), None, none(), false)
            .unwrap();
    }
    let full = all.clone();
    assert_eq!(
        all.create(id(99), "One more", None, none(), false),
        Err(ProfileFailureCode::TooManyProfiles)
    );
    assert_eq!(all, full);
    assert_ne!(all, before);
}

#[test]
fn a_rename_keeps_the_id() {
    let mut all = two();
    all.rename(&id(2), "  Robotics lab ").unwrap();
    let lab = all.profile(&id(2)).unwrap();
    assert_eq!(lab.name, "Robotics lab");
    assert_eq!(lab.username.as_deref(), Some("user.lab@app"));
    // Its own name in another case is no clash.
    all.rename(&id(2), "ROBOTICS LAB").unwrap();
    let before = all.clone();
    assert_eq!(
        all.rename(&id(2), "ubc vpn"),
        Err(ProfileFailureCode::NameTaken)
    );
    assert_eq!(
        all.rename(&id(9), "Other"),
        Err(ProfileFailureCode::UnknownProfile)
    );
    assert_eq!(all, before);
}

// Security rule: the saved password is forgotten when the username changes
// or saving is turned off, and kept otherwise.
#[test]
fn an_update_says_when_the_saved_password_must_go() {
    let mut all = two();
    let lab = &id(2);
    assert_eq!(all.update(lab, None, None), Ok(Password::Keep));
    assert_eq!(
        all.update(lab, Some(Some("user.lab@app")), None),
        Ok(Password::Keep)
    );
    assert_eq!(all.update(lab, None, Some(true)), Ok(Password::Keep));
    assert_eq!(
        all.update(lab, Some(Some("other.lab@app")), None),
        Ok(Password::Forget)
    );
    assert_eq!(
        all.profile(lab).unwrap().username.as_deref(),
        Some("other.lab@app")
    );
    assert_eq!(all.update(lab, Some(None), None), Ok(Password::Forget));
    assert_eq!(all.profile(lab).unwrap().username, None);
    assert_eq!(all.update(lab, None, Some(false)), Ok(Password::Forget));
    assert!(!all.profile(lab).unwrap().save_password);
    // Turning it off again, or on, leaves nothing to forget.
    assert_eq!(all.update(lab, None, Some(false)), Ok(Password::Keep));
    assert_eq!(all.update(lab, None, Some(true)), Ok(Password::Keep));
    let before = all.clone();
    assert_eq!(
        all.update(lab, Some(Some("\u{202e}x")), None),
        Err(ProfileFailureCode::BadUsername)
    );
    assert_eq!(
        all.update(&id(9), None, Some(false)),
        Err(ProfileFailureCode::UnknownProfile)
    );
    assert_eq!(all, before);
}

// Security rule: a deleted profile's saved password is forgotten. The last
// profile stays; deleting the active one makes the first left active.
#[test]
fn deleting_a_profile_forgets_its_password() {
    let mut all = two();
    all.switch(&id(2)).unwrap();
    assert_eq!(all.active().name, "Lab");
    assert_eq!(all.delete(&id(2)), Ok(Password::Forget));
    assert_eq!(all.profiles.len(), 1);
    assert_eq!(all.global.active_profile, ProfileId::first());
    assert_eq!(
        all.delete(&ProfileId::first()),
        Err(ProfileFailureCode::LastProfile)
    );
    assert_eq!(all.delete(&id(2)), Err(ProfileFailureCode::UnknownProfile));
}

#[test]
fn switching_and_routes_need_a_profile_that_exists() {
    let mut all = two();
    assert_eq!(all.switch(&id(9)), Err(ProfileFailureCode::UnknownProfile));
    all.switch(&id(2)).unwrap();
    assert_eq!(all.active().id, id(2));
    let new = routes(&["192.0.2.0/24"], &[]);
    all.set_routes(&id(2), new.clone()).unwrap();
    assert_eq!(all.profile(&id(2)).unwrap().routes, new);
    assert_eq!(
        all.set_routes(&id(9), new),
        Err(ProfileFailureCode::UnknownProfile)
    );
    all.set_startup(StartMode::Tray, true);
    assert_eq!(
        (all.global.start, all.global.auto_connect),
        (StartMode::Tray, true)
    );
}

// The commands and the app that do not know profiles yet see the active
// profile as the settings were.
#[test]
fn the_view_from_before_profiles_is_the_active_profile() {
    let mut all = two();
    assert_eq!(all.v1_view(), Settings::default());
    all.switch(&id(2)).unwrap();
    let view = all.v1_view();
    assert_eq!(view.username.as_deref(), Some("user.lab@app"));
    assert_eq!(
        view.routes,
        routes(&["10.255.0.0/16"], &["lab.example.test"])
    );
    assert!(view.save_password);
}

#[test]
fn the_app_lines_have_a_stable_shape() {
    // A field left out is not changed; `null` removes the username.
    let left_out: UpdateProfile =
        serde_json::from_str(&format!(r#"{{"id":"{}"}}"#, id(2).as_str())).unwrap();
    assert_eq!((left_out.username, left_out.save_password), (None, None));
    let removed: UpdateProfile =
        serde_json::from_str(&format!(r#"{{"id":"{}","username":null}}"#, id(2).as_str())).unwrap();
    assert_eq!(removed.username, Some(None));
    // Nothing may be smuggled in, such as a password.
    let smuggled = [
        r#"{"name":"Lab","password":"made-up"}"#.to_string(),
        format!(r#"{{"id":"{}","password":"made-up"}}"#, id(2).as_str()),
    ];
    assert!(serde_json::from_str::<NewProfile>(&smuggled[0]).is_err());
    assert!(serde_json::from_str::<UpdateProfile>(&smuggled[1]).is_err());
    assert!(serde_json::from_str::<ProfileRef>(&smuggled[1]).is_err());
    let startup: Startup = serde_json::from_str(r#"{"start":"tray","auto_connect":true}"#).unwrap();
    assert_eq!(startup.start, StartMode::Tray);
    assert!(serde_json::from_str::<Startup>(r#"{"start":"later","auto_connect":true}"#).is_err());
    let failure = ProfileFailure {
        error: ProfileFailureCode::NameTaken,
    };
    assert_eq!(
        serde_json::to_string(&failure).unwrap(),
        r#"{"error":"name_taken"}"#
    );
    let view = ProfileView {
        profile: Profiles::fresh().profiles[0].clone(),
        password_saved: true,
    };
    let json: Value = serde_json::to_value(&view).unwrap();
    assert_eq!(json["name"], FIRST_PROFILE_NAME);
    assert_eq!(json["password_saved"], true);
}
