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

/// The settings of a user who has saved none.
fn untouched() -> Profiles {
    Profiles::read(None).unwrap().profiles
}

/// Two profiles: the first, active, and "Lab" with the id `id(2)`.
fn two() -> Profiles {
    let mut all = untouched();
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
    assert!(fresh.cleaned.is_empty());
    let fresh = fresh.profiles;
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

// Security rule: fresh settings, as a reset leaves them, have the random id
// they are given, never the fixed one: a password saved under that id
// before the reset must not become theirs.
#[test]
fn fresh_settings_have_the_id_they_are_given() {
    let fresh = Profiles::fresh(id(7));
    assert_eq!(fresh.profiles.len(), 1);
    assert_eq!(fresh.active().id, id(7));
    assert_eq!(fresh.global.active_profile, id(7));
    assert_ne!(fresh.active().id, ProfileId::first());
    assert_eq!(fresh.active().name, FIRST_PROFILE_NAME);
    assert_eq!(fresh.check(), Ok(()));
}

// Security rule: settings from before profiles lose nothing. They become
// one active profile with the same username, routes and choice about the
// password, and the file's other fields stay. A route the rules would now
// refuse is kept as it was: dropping a route the user chose would be worse.
#[test]
fn version_1_settings_become_one_profile_and_lose_nothing() {
    let v1 = r#"{"username":"user.dept@app","save_password":true,"theme":"dark",
        "routes":{"subnets":["10.255.0.0/16","10.0.0.0/7"],"dns_domains":["dept.example.test"]}}"#;
    let read = Profiles::read(Some(v1)).unwrap().profiles;
    assert_eq!(read.profiles.len(), 1);
    let profile = read.active();
    assert_eq!(profile.id, ProfileId::first());
    assert_eq!(profile.name, FIRST_PROFILE_NAME);
    assert_eq!(profile.username.as_deref(), Some("user.dept@app"));
    assert!(profile.save_password);
    assert_eq!(
        profile.routes,
        routes(&["10.255.0.0/16", "10.0.0.0/7"], &["dept.example.test"])
    );
    assert_eq!(read.other.get("theme"), Some(&Value::from("dark")));
    // The same id every time it is read, until it is saved.
    assert_eq!(Profiles::read(Some(v1)).unwrap().profiles, read);

    // Saved, it is version 2, without the old fields, and reads back the
    // same.
    let text = read.to_text();
    let saved: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(saved["version"], 2);
    for moved in ["username", "routes", "save_password"] {
        assert!(saved.get(moved).is_none(), "{moved} is still at the top");
    }
    assert_eq!(saved["theme"], "dark");
    assert_eq!(Profiles::read(Some(&text)).unwrap().profiles, read);
    // And an explicit version 1 is read the same way.
    let explicit = v1.replacen('{', r#"{"version":1,"#, 1);
    assert_eq!(Profiles::read(Some(&explicit)).unwrap().profiles, read);
}

#[test]
fn version_2_has_a_stable_shape() {
    let text = untouched().to_text();
    let compact: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        compact.to_string(),
        r#"{"global":{"active_profile":"00000000000000000000000000000001","auto_connect":false,"start":"off","tunnel":"split"},"profiles":[{"id":"00000000000000000000000000000001","name":"UBC VPN","routes":{"dns_domains":[],"subnets":[]},"save_password":false,"username":null}],"version":2}"#
    );
}

// One tunnel mode for every profile, split unless set. A file from before
// there was a choice, or with a word this version does not know, reads as
// split, the narrower: never as full.
#[test]
fn the_tunnel_mode_is_global_and_split_unless_set() {
    let mut profiles = two();
    assert_eq!(profiles.global.tunnel, TunnelMode::Split);
    profiles.set_tunnel(TunnelMode::Full);
    let saved: Value = serde_json::from_str(&profiles.to_text()).unwrap();
    assert_eq!(saved["global"]["tunnel"], "full");
    let read = Profiles::read(Some(&profiles.to_text())).unwrap().profiles;
    assert_eq!(read.global.tunnel, TunnelMode::Full);

    for odd in [
        Value::Null,
        Value::from("everything"),
        Value::from(true),
        Value::from("Full"),
    ] {
        let mut file = saved.clone();
        file["global"]["tunnel"] = odd.clone();
        let read = Profiles::read(Some(&file.to_string())).unwrap().profiles;
        assert_eq!(read.global.tunnel, TunnelMode::Split, "{odd}");
    }
    let mut file = saved.clone();
    file["global"].as_object_mut().unwrap().remove("tunnel");
    let read = Profiles::read(Some(&file.to_string())).unwrap().profiles;
    assert_eq!(read.global.tunnel, TunnelMode::Split);
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
    let mut read = Profiles::read(Some(&text)).unwrap().profiles;
    read.rename(&id(2), "Lab 2").unwrap();
    let saved: Value = serde_json::from_str(&read.to_text()).unwrap();
    assert_eq!(saved["future"], 1);
    assert_eq!(saved["global"]["theme"], "dark");
    assert_eq!(saved["profiles"][1]["colour"], "teal");
    assert_eq!(saved["profiles"][1]["name"], "Lab 2");
}

// Security rule: a rule made stricter later never loses a whole file. A
// name or a username that today's rules refuse is cleaned, and the file
// stays readable and can be changed; what was cleaned is said, and a
// cleared username's saved password is to be forgotten.
#[test]
fn names_and_usernames_today_refuses_are_cleaned_not_fatal() {
    let good: Value = serde_json::from_str(&two().to_text()).unwrap();
    // A v2 name holding a line separator, which reads as two lines.
    let mut file = good.clone();
    file["profiles"][1]["name"] = Value::from("Lab\u{2028}North");
    let read = Profiles::read(Some(&file.to_string())).unwrap();
    assert_eq!(read.profiles.profile(&id(2)).unwrap().name, "LabNorth");
    assert_eq!(
        read.cleaned,
        [Cleaned {
            id: id(2),
            renamed: true,
            username_cleared: false
        }]
    );
    assert_eq!(read.passwords_to_forget().count(), 0);
    let mut editable = read.profiles;
    editable.rename(&id(2), "Lab North").unwrap();
    assert_eq!(editable.check(), Ok(()));

    // A v1 username with a newline: cleared, and its password forgotten.
    let v1 = r#"{"username":"user.dept@app\nsudo","save_password":true,
        "routes":{"subnets":["10.255.0.0/16"],"dns_domains":[]}}"#;
    let read = Profiles::read(Some(v1)).unwrap();
    let first = read.profiles.active();
    assert_eq!(first.username, None);
    assert_eq!(
        first.routes,
        routes(&["10.255.0.0/16"], &[]),
        "the routes stay"
    );
    assert!(first.save_password);
    let forget: Vec<_> = read.passwords_to_forget().collect();
    assert_eq!(forget, [&ProfileId::first()]);
    let mut editable = read.profiles;
    let username = Some(Some("user.dept@app"));
    assert_eq!(
        editable.update(&ProfileId::first(), username, None),
        Ok(Password::Forget)
    );

    // Names that clean to nothing, or to another's name, get a free one.
    let cases = [
        ("", "Profile 2"),
        ("\u{202e}\u{200b}", "Profile 2"),
        ("ubc vpn", "Profile 2"),
        ("  UBC VPN\u{2029}", "Profile 2"),
        (
            &*"x".repeat(MAX_NAME_CHARS + 10),
            &*"x".repeat(MAX_NAME_CHARS),
        ),
    ];
    for (stored, expected) in cases {
        let mut file = good.clone();
        file["profiles"][1]["name"] = Value::from(stored);
        let read =
            Profiles::read(Some(&file.to_string())).unwrap_or_else(|e| panic!("{stored:?}: {e:?}"));
        assert_eq!(
            read.profiles.profile(&id(2)).unwrap().name,
            expected,
            "{stored:?}"
        );
        assert!(read.cleaned[0].renamed, "{stored:?}");
        assert_eq!(read.profiles.check(), Ok(()), "{stored:?}");
    }
    // A name given to one with none usable never takes a name the user
    // chose, even one later in the file: that one is kept as it was.
    // Compared as it will be kept: "Profile 1 " is the user's "Profile 1".
    for chosen in ["Profile 1", "Profile 1 ", " profile 1\u{200b}"] {
        let mut file = good.clone();
        file["profiles"][0]["name"] = Value::from("");
        file["profiles"][1]["name"] = Value::from(chosen);
        let read = Profiles::read(Some(&file.to_string())).unwrap();
        let names: Vec<_> = read
            .profiles
            .profiles
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        let kept = chosen.replace('\u{200b}', "");
        assert_eq!(names, ["Profile 2", kept.trim()], "{chosen:?}");
        assert_eq!(read.profiles.check(), Ok(()), "{chosen:?}");
    }
}

// A newer version, or a version 2 file whose structure is broken, is
// unreadable: the way out is `settings reset`, never a guess.
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
            "an id that is not one",
            spoiled(&|f| f["profiles"][0]["id"] = Value::from(7)),
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
}

// More profiles than this version makes, as a newer one might allow, are no
// reason to lose any: all are kept and can be changed, and no more can be
// made until there are fewer.
#[test]
fn more_profiles_than_the_limit_are_kept() {
    let mut file: Value = serde_json::from_str(&two().to_text()).unwrap();
    let profile = file["profiles"][1].clone();
    let list = file["profiles"].as_array_mut().unwrap();
    for n in 0..MAX_PROFILES {
        let mut more = profile.clone();
        more["id"] = Value::from(id(100 + n as u8).as_str());
        more["name"] = Value::from(format!("Lab {n}"));
        list.push(more);
    }
    let read = Profiles::read(Some(&file.to_string())).unwrap();
    let mut all = read.profiles;
    assert_eq!(all.profiles.len(), MAX_PROFILES + 2);
    assert!(read.cleaned.is_empty());
    all.rename(&id(100), "Lab zero").unwrap();
    all.switch(&id(101)).unwrap();
    assert_eq!(
        all.create(id(250), "One more", None, RouteSet::default(), false),
        Err(ProfileFailureCode::TooManyProfiles)
    );
    assert_eq!(all.delete(&id(102)), Ok(Password::Forget));
    assert_eq!(all.profiles.len(), MAX_PROFILES + 1);
    assert_eq!(Profiles::read(Some(&all.to_text())).unwrap().profiles, all);
}

#[test]
fn names_are_trimmed_short_and_plain() {
    assert_eq!(check_name("  Lab  "), Ok("Lab".to_string()));
    assert_eq!(
        check_name("Département Physique"),
        Ok("Département Physique".to_string())
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
        // An id that is taken: the caller tries another.
        (
            all.clone().create(id(2), "Home", None, none(), false),
            ProfileFailureCode::IdTaken,
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
        profile: untouched().profiles[0].clone(),
        password_saved: true,
    };
    let json: Value = serde_json::to_value(&view).unwrap();
    assert_eq!(json["name"], FIRST_PROFILE_NAME);
    assert_eq!(json["password_saved"], true);
}
