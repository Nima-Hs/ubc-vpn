//! The stand-in gateway itself: each scenario comes up, answers a plain
//! client the way its description says, and logs what it received.
//!
//! These say nothing yet about how `libopenconnect` reads the replies. That
//! is settled when the login engine drives the gateway, and the replies may
//! change then.
//!
//! All names, passwords and cookies here are made up.

#[path = "gateway/mod.rs"]
mod gateway;

use gateway::{Gateway, post};
use serde_json::Value;

const ANSWERS: &str = "username=someone&password=not-a-real-password";

/// Starts `scenario`, asks for the form and answers it, and returns the two
/// replies and the gateway. `None` when the test is skipped.
fn login(scenario: &str) -> Option<(Value, Value, Gateway)> {
    let gateway = Gateway::start(scenario)?;
    let reply = |path, body| -> Value {
        let line = post(gateway.port, path, body);
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{scenario} {path}: {e}: {line}"))
    };
    let (first, second) = (reply("/", ""), reply("/auth", ANSWERS));
    println!("RAN: gateway {scenario}");
    Some((first, second, gateway))
}

fn text<'a>(reply: &'a Value, field: &str) -> &'a str {
    reply[field].as_str().unwrap_or_default()
}

/// The form asks for a username and a password, by those names.
fn is_login_form(reply: &Value) -> bool {
    let body = text(reply, "body");
    reply["status"] == 200
        && body.contains(r#"<input type="text" name="username""#)
        && body.contains(r#"<input type="password" name="password""#)
}

fn gives_cookie(reply: &Value) -> bool {
    text(reply, "cookie").starts_with("webvpn=FAKE-GATEWAY-COOKIE-")
        && text(reply, "body").contains(r#"type="complete""#)
}

#[test]
fn accept_shows_the_form_and_gives_a_cookie_and_logs_both_requests() {
    let Some((first, second, gateway)) = login("accept") else {
        return;
    };
    assert!(
        is_login_form(&first) && gives_cookie(&second),
        "{first} {second}"
    );
    let requests = gateway.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].contains(r#""listener": "main", "method": "POST", "path": "/", "#));
    let answered =
        format!(r#""listener": "main", "method": "POST", "path": "/auth", "body": "{ANSWERS}""#);
    assert!(requests[1].contains(&answered), "{requests:?}");
}

#[test]
fn reject_shows_the_form_again_with_an_error() {
    let Some((first, second, _gateway)) = login("reject") else {
        return;
    };
    assert!(is_login_form(&first) && is_login_form(&second), "{second}");
    assert!(text(&second, "body").contains("<error>Login failed.</error>"));
    assert!(second["cookie"].is_null(), "{second}");
}

#[test]
fn code_asks_for_a_one_time_code_before_it_gives_a_cookie() {
    let Some((_, second, gateway)) = login("code") else {
        return;
    };
    let body = text(&second, "body");
    assert!(
        body.contains(r#"<input type="password" name="secondary_password""#),
        "{body}"
    );
    assert!(second["cookie"].is_null() && !body.contains(r#"name="username""#));
    let third: Value =
        serde_json::from_str(&post(gateway.port, "/code", "secondary_password=000000")).unwrap();
    assert!(gives_cookie(&third), "{third}");
}

#[test]
fn group_shows_a_choice_and_hang_never_answers_the_login() {
    let Some((first, _, _gateway)) = login("group") else {
        return;
    };
    assert!(text(&first, "body").contains(r#"<select name="group_list""#));
    let (first, second, _gateway) = login("hang").expect("the first scenario ran");
    assert!(is_login_form(&first), "{first}");
    assert_eq!(second["error"], "TimeoutError", "{second}");
}

// The three scenarios that try to send the client elsewhere all point at the
// second listener, and that listener logs whoever follows.
#[test]
fn redirect_action_and_csd_point_at_the_other_listener() {
    let Some((first, _, gateway)) = login("redirect") else {
        return;
    };
    let elsewhere = format!("https://127.0.0.1:{}", gateway.other_port);
    assert_eq!(
        (&first["status"], text(&first, "location")),
        (&302.into(), format!("{elsewhere}/").as_str())
    );
    assert!(
        gateway
            .requests()
            .iter()
            .all(|line| line.contains(r#""listener": "main""#))
    );
    let followed: Value = serde_json::from_str(&post(gateway.other_port, "/", "")).unwrap();
    assert!(gives_cookie(&followed), "{followed}");
    let last = gateway.requests().pop().unwrap_or_default();
    assert!(last.contains(r#""listener": "other""#), "{last}");

    let (first, _, gateway) = login("action").expect("the first scenario ran");
    let action = format!(r#"action="https://127.0.0.1:{}/auth""#, gateway.other_port);
    assert!(
        is_login_form(&first) && text(&first, "body").contains(&action),
        "{first}"
    );

    let (first, _, gateway) = login("csd").expect("the first scenario ran");
    let base = format!(
        "<host-scan-base-uri>https://127.0.0.1:{}/",
        gateway.other_port
    );
    assert!(
        is_login_form(&first) && text(&first, "body").contains(&base),
        "{first}"
    );
}
