use super::*;
use crate::routes::Ipv4Net;

// When the gateway's certificate is replaced, every connect fails until
// the user updates. The sentence says so, and reaches the log whole.
#[test]
fn a_changed_certificate_tells_the_user_to_update() {
    assert!(CERTIFICATE_CHANGED.contains("certificate has changed"));
    assert!(CERTIFICATE_CHANGED.contains("Update UBC VPN"));
    // The other usual cause: a network that intercepts connections.
    assert!(CERTIFICATE_CHANGED.contains("already up to date"));
    assert!(CERTIFICATE_CHANGED.contains("try another network"));
    // Security rule: it never offers a way past the pin.
    let lower = CERTIFICATE_CHANGED.to_lowercase();
    for offer in ["accept", "trust", "anyway", "continue", "ignore", "proceed"] {
        assert!(!lower.contains(offer), "{offer}");
    }
    assert_eq!(
        crate::redact::redact_line(CERTIFICATE_CHANGED),
        CERTIFICATE_CHANGED
    );
}

fn connect() -> Request {
    Request {
        id: 7,
        body: RequestBody::Connect(ConnectParams {
            cookie: Secret::new("s3cr3t-cookie"),
            gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
            routes: RouteSet {
                subnets: vec!["198.19.0.0/16".parse::<Ipv4Net>().unwrap()],
                dns_domains: vec!["dept.ubc.ca".to_string()],
            },
            tunnel: TunnelMode::Split,
        }),
    }
}

#[test]
fn request_wire_format_is_stable() {
    // If the snapshot below has to change, so does this number: an older
    // peer could no longer read the message.
    assert_eq!(PROTOCOL_VERSION, 6);
    let line = encode(&connect()).unwrap();
    assert_eq!(
        line,
        concat!(
            r#"{"id":7,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","gateway_addr":"192.0.2.1","#,
            r#""routes":{"subnets":["198.19.0.0/16"],"dns_domains":["dept.ubc.ca"]},"tunnel":"split"}}}"#,
            "\n"
        )
    );
    assert_eq!(decode::<Request>(&line).unwrap(), connect());
}

// Version 5: a connect says split or full, and left out it is split, as
// before there was a choice. Only those two words are taken.
#[test]
fn a_connect_says_its_tunnel_mode() {
    let without = concat!(
        r#"{"id":7,"body":{"method":"connect","params":{"cookie":"s3cr3t-cookie","gateway_addr":"192.0.2.1","#,
        r#""routes":{"subnets":["198.19.0.0/16"],"dns_domains":["dept.ubc.ca"]}}}}"#
    );
    assert_eq!(decode::<Request>(without).unwrap(), connect());
    let full = without.replace(r#"]}}}}"#, r#"]},"tunnel":"full"}}}"#);
    let Request {
        body: RequestBody::Connect(params),
        ..
    } = decode::<Request>(&full).unwrap()
    else {
        panic!("{full}")
    };
    assert_eq!(params.tunnel, TunnelMode::Full);
    let other = without.replace(r#"]}}}}"#, r#"]},"tunnel":"everything"}}}"#);
    assert!(decode::<Request>(&other).is_err());
}

// Version 5: the live tunnel can be switched between split and full,
// with nothing else in the request.
#[test]
fn set_tunnel_has_a_stable_wire_format() {
    let switch = Request {
        id: 11,
        body: RequestBody::SetTunnel(SetTunnelParams {
            mode: TunnelMode::Full,
        }),
    };
    let line = encode(&switch).unwrap();
    assert_eq!(
        line,
        "{\"id\":11,\"body\":{\"method\":\"set_tunnel\",\"params\":{\"mode\":\"full\"}}}\n"
    );
    assert_eq!(decode::<Request>(&line).unwrap(), switch);
    let smuggled = [
        r#"{"id":11,"body":{"method":"set_tunnel","params":{"mode":"full","subnets":["0.0.0.0/1"]}}}"#,
        r#"{"id":11,"body":{"method":"set_tunnel","params":{}}}"#,
        r#"{"id":11,"body":{"method":"set_tunnel"}}"#,
    ];
    for line in smuggled {
        assert!(decode::<Request>(line).is_err(), "{line}");
    }
}

// The mode of a live tunnel is in every `connected` state, for the app to
// show, and is always there.
#[test]
fn a_connected_state_says_its_mode() {
    let state = ConnState::Connected {
        tunnel: crate::state::TunnelInfo {
            interface: "tun0".to_string(),
            address: "10.255.0.2".to_string(),
            subnets: vec![],
            dns_domains: vec![],
            mode: TunnelMode::Full,
        },
    };
    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(
        json,
        r#"{"state":"connected","tunnel":{"interface":"tun0","address":"10.255.0.2","subnets":[],"dns_domains":[],"mode":"full"}}"#
    );
    assert_eq!(serde_json::from_str::<ConnState>(&json).unwrap(), state);
    let without = json.replace(r#","mode":"full""#, "");
    assert!(serde_json::from_str::<ConnState>(&without).is_err());
}

// A peer that speaks version 4 knows nothing of `set_tunnel` or of a
// tunnel's mode. It is told to update in the handshake.
#[test]
fn a_version_4_peer_is_told_to_update() {
    let older = r#"{"protocol_version":4,"client":"cli","client_version":"0.1.0"}"#;
    assert_eq!(peek_protocol_version(older), Ok(4));
    let reply = HelloReply {
        protocol_version: 4,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    assert!(!reply.is_compatible());
}

#[test]
fn unit_requests_have_no_params() {
    let line = encode(&Request {
        id: 1,
        body: RequestBody::Status,
    })
    .unwrap();
    assert_eq!(line, "{\"id\":1,\"body\":{\"method\":\"status\"}}\n");
}

#[test]
fn server_messages_round_trip() {
    let messages = [
        ServerMessage::Response(Response {
            id: 1,
            outcome: Outcome::Ok(ResponseBody::Status(ConnState::Disconnected)),
        }),
        ServerMessage::Response(Response {
            id: 2,
            outcome: Outcome::Error(ErrorInfo {
                code: ErrorCode::NotOwner,
                message: "only the owner may do this".to_string(),
            }),
        }),
        ServerMessage::Event(Event::StateChanged(ConnState::Connecting)),
    ];
    for message in messages {
        let line = encode(&message).unwrap();
        assert_eq!(decode::<ServerMessage>(&line).unwrap(), message);
    }
    let undone = ServerMessage::Event(Event::SwitchUndone(ErrorInfo {
        code: ErrorCode::VerificationFailed,
        message: "Kept split tunnel.".to_string(),
    }));
    let line = encode(&undone).unwrap();
    let expected = r#"{"type":"event","data":{"kind":"switch_undone","value":{"code":"verification_failed","message":"Kept split tunnel."}}}"#;
    assert_eq!(line.trim_end(), expected);
    assert_eq!(decode::<ServerMessage>(&line).unwrap(), undone);
}

// Security rule: the service accepts exactly the expected fields. A request
// must not be able to smuggle in a gateway name or a pin.
#[test]
fn requests_with_unknown_fields_are_refused() {
    let smuggled = [
        r#"{"id":1,"body":{"method":"status"},"gateway":"evil.example"}"#,
        r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[]},"gateway":"evil.example"}}}"#,
        r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[],"pins":[]}}}}"#,
        r#"{"protocol_version":1,"client":"app","client_version":"0.1.0","owner":"me"}"#,
    ];
    assert!(decode::<Request>(smuggled[0]).is_err());
    assert!(decode::<Request>(smuggled[1]).is_err());
    assert!(decode::<Request>(smuggled[2]).is_err());
    assert!(decode::<Hello>(smuggled[3]).is_err());

    // Beside the method, where a `deny_unknown_fields` on the outer struct
    // alone would not reach.
    let beside_method = [
        r#"{"id":1,"body":{"method":"status","gateway":"evil.example"}}"#,
        r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","gateway_addr":"192.0.2.1","routes":{"subnets":[]}},"pins":["x"]}}"#,
    ];
    for line in beside_method {
        assert!(decode::<Request>(line).is_err(), "{line} must be refused");
    }
}

// Version 4: the routes of a live tunnel can be changed, and a request
// that needs a tunnel is refused with its own code when there is none.
#[test]
fn update_routes_has_a_stable_wire_format() {
    let update = Request {
        id: 9,
        body: RequestBody::UpdateRoutes(RouteSet {
            subnets: vec!["10.255.0.0/16".parse().unwrap()],
            dns_domains: vec!["dept.example.test".to_string()],
        }),
    };
    let line = encode(&update).unwrap();
    assert_eq!(
        line,
        concat!(
            r#"{"id":9,"body":{"method":"update_routes","params":"#,
            r#"{"subnets":["10.255.0.0/16"],"dns_domains":["dept.example.test"]}}}"#,
            "\n"
        )
    );
    assert_eq!(decode::<Request>(&line).unwrap(), update);
    // As strict as a connect's routes: nothing may be smuggled in.
    let smuggled = r#"{"id":9,"body":{"method":"update_routes","params":{"subnets":[],"gateway":"evil.example"}}}"#;
    assert!(decode::<Request>(smuggled).is_err());

    let refused = Outcome::Error(ErrorInfo {
        code: ErrorCode::NotConnected,
        message: "made up".to_string(),
    });
    let json = serde_json::to_string(&refused).unwrap();
    assert!(json.contains(r#""code":"not_connected""#), "{json}");
}

// A peer that speaks version 3 knows nothing of `update_routes`. It is
// told to update in the handshake.
#[test]
fn a_version_3_peer_is_told_to_update() {
    let older = r#"{"protocol_version":3,"client":"app","client_version":"0.1.0"}"#;
    assert_eq!(peek_protocol_version(older), Ok(3));
    let reply = HelloReply {
        protocol_version: 3,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    assert!(!reply.is_compatible());
}

#[test]
fn unknown_methods_are_refused() {
    assert!(decode::<Request>(r#"{"id":1,"body":{"method":"set_gateway"}}"#).is_err());
}

// Security rule: an oversized line is refused before it is parsed.
#[test]
fn oversized_lines_are_refused() {
    let huge = format!(r#"{{"id":1,"pad":"{}"}}"#, "x".repeat(MAX_LINE_BYTES));
    assert!(matches!(decode::<Request>(&huge), Err(FrameError::TooLong)));

    let big_cookie = Request {
        id: 1,
        body: RequestBody::Connect(ConnectParams {
            cookie: Secret::new("x".repeat(MAX_LINE_BYTES)),
            gateway_addr: Ipv4Addr::new(192, 0, 2, 1),
            routes: RouteSet::default(),
            tunnel: TunnelMode::Split,
        }),
    };
    assert!(matches!(encode(&big_cookie), Err(FrameError::TooLong)));
}

// Security rule: a cookie holds only what RFC 6265 allows in a cookie
// value. Each byte that could split the `Cookie:` header, end it, or add
// a cookie is refused; what gateways issue, base64 padding included, is
// not.
#[test]
fn a_cookie_holds_only_cookie_octets() {
    let plausible = |text: &str| is_plausible_cookie(&Secret::new(text));
    for good in [
        "Zq7-made-up-0123456789",
        "bWFkZS11cC1jb29raWU==",
        "webvpn=bWFkZS11cC1jb29raWU=",
        "1A2B3C@1234@ABCD@0123456789ABCDEF",
        "!#$%&'()*+-./:<>?[]^_`{|}~",
    ] {
        assert!(plausible(good), "{good:?}");
    }
    let base = "made-up-cookie";
    for bad in [
        ";", "\r", "\n", " ", "\"", ",", "\\", "é", "\0", "\t", "\u{7f}",
    ] {
        for cookie in [
            format!("{bad}{base}"),
            format!("{base}{bad}x"),
            format!("{base}{bad}"),
        ] {
            assert!(!plausible(&cookie), "{cookie:?}");
        }
    }
    assert!(!plausible(""));
    // Every byte outside the set, one at a time.
    let allowed = (0u8..=127).filter(|byte| plausible(&char::from(*byte).to_string()));
    let expected = (0x21u8..=0x7e).filter(|byte| !b"\",;\\".contains(byte));
    assert!(allowed.eq(expected));
}

// Security rule: neither a request's debug output nor a decode error may
// reveal the cookie.
#[test]
fn the_cookie_never_reaches_debug_output_or_errors() {
    assert!(!format!("{:?}", connect()).contains("s3cr3t-cookie"));

    // In each of these the secret sits where another type is expected,
    // which is exactly when serde_json quotes the offending value in its
    // own error message.
    let broken = [
        r#"{"id":"s3cr3t-cookie","body":{"method":"status"}}"#,
        r#"{"id":1,"body":{"method":"connect","params":{"cookie":"x","gateway_addr":"192.0.2.1","routes":"s3cr3t-cookie"}}}"#,
        r#"{"id":1,"body":{"method":"s3cr3t-cookie"}}"#,
        r#"{"id":1,"body":{"method":"status"},"s3cr3t-cookie":1}"#,
    ];
    for line in broken {
        let error = decode::<Request>(line).unwrap_err();
        assert!(
            matches!(
                error,
                FrameError::Invalid {
                    kind: InvalidKind::Shape,
                    ..
                }
            ),
            "{line} should be a shape error, got {error:?}"
        );
        for shown in [format!("{error}"), format!("{error:?}")] {
            assert!(!shown.contains("s3cr3t"), "{shown} reveals the input");
        }
    }
}

#[test]
fn syntax_and_shape_errors_are_told_apart() {
    assert!(matches!(
        decode::<Request>("{not json"),
        Err(FrameError::Invalid {
            kind: InvalidKind::Syntax,
            ..
        })
    ));
    assert!(matches!(
        decode::<Request>(r#"{"id":1}"#),
        Err(FrameError::Invalid {
            kind: InvalidKind::Shape,
            ..
        })
    ));
}

// A client from another version must still get a "please update" answer,
// so its version is readable even when the rest of its hello is not.
#[test]
fn the_version_is_readable_from_a_hello_this_version_cannot_parse() {
    let future = r#"{"protocol_version":2,"client":"tray","client_version":"9.0.0","new":true}"#;
    assert!(decode::<Hello>(future).is_err());
    assert_eq!(peek_protocol_version(future).unwrap(), 2);
    assert!(peek_protocol_version(r#"{"client":"app"}"#).is_err());
}

// Security rule: the service must not be aimed at itself, at a network
// segment, or at a non-address. Weakening the check, or removing any
// range from the reserved list in routes.rs, makes
// this test fail.
#[test]
fn implausible_gateway_addresses_are_refused() {
    for bad in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
    ] {
        let addr: Ipv4Addr = bad.parse().unwrap();
        assert!(!is_plausible_gateway_addr(addr), "{bad} must be refused");
    }
    for good in [
        "198.19.1.1",
        "10.0.0.1",
        "192.168.1.1",
        "1.1.1.1",
        "223.255.255.254",
    ] {
        let addr: Ipv4Addr = good.parse().unwrap();
        assert!(is_plausible_gateway_addr(addr), "{good} must be accepted");
    }
}

#[test]
fn a_connect_request_needs_a_well_formed_gateway_address() {
    let without =
        r#"{"id":1,"body":{"method":"connect","params":{"cookie":"c","routes":{"subnets":[]}}}}"#;
    assert!(decode::<Request>(without).is_err());
    for bad in ["myvpn.ubc.ca", "::1", "1.2.3", "1.2.3.4:443", ""] {
        let line = format!(
            r#"{{"id":1,"body":{{"method":"connect","params":{{"cookie":"c","gateway_addr":"{bad}","routes":{{"subnets":[]}}}}}}}}"#
        );
        assert!(decode::<Request>(&line).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn hello_reply_reports_compatibility() {
    let reply = |v| HelloReply {
        protocol_version: v,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    assert!(reply(PROTOCOL_VERSION).is_compatible());
    assert!(!reply(PROTOCOL_VERSION + 1).is_compatible());
}

fn line(seq: u64, text: &str) -> LogLine {
    LogLine {
        seq,
        at_unix_ms: 1_800_000_000_000 + seq,
        level: LogLevel::Info,
        source: LogSource::Engine,
        text: LogText::new(text).unwrap(),
    }
}

// The app is written against these lines. Changing one is changing the
// protocol.
#[test]
fn the_log_messages_have_a_stable_wire_format() {
    let request = |body| encode(&Request { id: 1, body }).unwrap();
    let after = Some(LogCursor { run: 7, seq: 41 });
    let add = AddLogParams {
        level: LogLevel::Error,
        text: "Login failed.".to_string(),
    };
    let requests = [
        (
            RequestBody::Logs(LogsParams { after }),
            r#"{"id":1,"body":{"method":"logs","params":{"after":{"run":7,"seq":41}}}}"#,
        ),
        (
            RequestBody::Logs(LogsParams { after: None }),
            r#"{"id":1,"body":{"method":"logs","params":{"after":null}}}"#,
        ),
        (
            RequestBody::WatchLogs(WatchLogsParams { on: true }),
            r#"{"id":1,"body":{"method":"watch_logs","params":{"on":true}}}"#,
        ),
        (
            RequestBody::Diagnostics,
            r#"{"id":1,"body":{"method":"diagnostics"}}"#,
        ),
        (
            RequestBody::AddLog(add),
            r#"{"id":1,"body":{"method":"add_log","params":{"level":"error","text":"Login failed."}}}"#,
        ),
    ];
    for (body, wire) in requests {
        assert_eq!(request(body.clone()), format!("{wire}\n"));
        assert_eq!(decode::<Request>(wire).unwrap().body, body);
    }
    // `after` may be left out, which reads from the oldest line.
    let bare: Request = decode(r#"{"id":1,"body":{"method":"logs","params":{}}}"#).unwrap();
    assert_eq!(bare.body, RequestBody::Logs(LogsParams { after: None }));

    let logged = r#"{"seq":42,"at_unix_ms":1800000000042,"level":"info","source":"engine","text":"CSTP connected"}"#;
    let event = ServerMessage::Event(Event::Log(line(42, "CSTP connected")));
    let wire = format!(r#"{{"type":"event","data":{{"kind":"log","value":{logged}}}}}"#);
    assert_eq!(encode(&event).unwrap(), format!("{wire}\n"));
    assert_eq!(decode::<ServerMessage>(&wire).unwrap(), event);

    let page = LogPage::after(7, 41, true, [line(42, "CSTP connected")]);
    let wire = format!(
        r#"{{"kind":"logs","value":{{"run":7,"lines":[{logged}],"next":42,"dropped":true}}}}"#
    );
    assert_eq!(
        encode(&ResponseBody::Logs(page.clone())).unwrap(),
        format!("{wire}\n")
    );
    assert_eq!(
        decode::<ResponseBody>(&wire).unwrap(),
        ResponseBody::Logs(page)
    );
    for (level, source) in [("error", "service"), ("warn", "login")] {
        let other = logged.replace("info", level).replace("engine", source);
        assert!(decode::<LogLine>(&other).is_ok(), "{other}");
    }
}

#[test]
fn diagnostics_have_a_stable_wire_format() {
    let diagnostics = Diagnostics {
        service_version: "0.1.0".to_string(),
        protocol_version: 3,
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        os_version: None,
        uptime_s: 90,
        state: StateKind::Connected,
        subnets: 2,
        dns_domains: 1,
        last_error: Some(LastError {
            code: ErrorCode::GatewayUnreachable,
            message: LogText::new("The gateway could not be reached.").unwrap(),
        }),
        policy_readable: true,
        pins: 2,
        gateway: Some("vpn.example.test".to_string()),
        owner_claimed: true,
    };
    let wire = concat!(
        r#"{"kind":"diagnostics","value":{"service_version":"0.1.0","protocol_version":3,"#,
        r#""os":"linux","arch":"x86_64","os_version":null,"uptime_s":90,"#,
        r#""state":"connected","subnets":2,"dns_domains":1,"#,
        r#""last_error":{"code":"gateway_unreachable","message":"The gateway could not be reached."},"#,
        r#""policy_readable":true,"pins":2,"gateway":"vpn.example.test","owner_claimed":true}}"#,
    );
    let body = ResponseBody::Diagnostics(Box::new(diagnostics.clone()));
    assert_eq!(encode(&body).unwrap(), format!("{wire}\n"));
    assert_eq!(decode::<ResponseBody>(wire).unwrap(), body);

    // Security rule: the message of the last failure is checked like a
    // log line when it is read, as is the system's version.
    for odd in ["two\\nlines", "escape\\u001b[2J", ""] {
        let message = wire.replace("The gateway could not be reached.", odd);
        assert!(decode::<ResponseBody>(&message).is_err(), "{odd}");
        let version = wire.replace(r#""os_version":null"#, &format!(r#""os_version":"{odd}""#));
        assert!(decode::<ResponseBody>(&version).is_err(), "{odd}");
    }

    // The largest there can be: the worst text wherever there is text
    // with a limit, the largest numbers, and the longest name a gateway
    // can have. The largest state a connect can carry (256 subnets and
    // as many domains as fit in a request) adds nothing to it, because
    // those are counted, not listed.
    let worst = LogText::new(&"\"".repeat(MAX_LOG_TEXT_BYTES)).unwrap();
    let largest = Diagnostics {
        os_version: Some(worst.clone()),
        uptime_s: u64::MAX,
        state: StateKind::Disconnecting,
        subnets: u32::MAX,
        dns_domains: u32::MAX,
        last_error: Some(LastError {
            code: ErrorCode::VerificationFailed,
            message: worst,
        }),
        pins: u32::MAX,
        gateway: Some("x".repeat(253)),
        ..diagnostics
    };
    let line = encode(&ResponseBody::Diagnostics(Box::new(largest))).unwrap();
    assert!(line.len() < 4096, "{}", line.len());
}

// What `diagnostics` says of each state.
#[test]
fn every_state_has_its_kind() {
    let tunnel = crate::state::TunnelInfo {
        interface: "fake0".to_string(),
        address: "10.255.0.2".to_string(),
        subnets: Vec::new(),
        dns_domains: Vec::new(),
        mode: TunnelMode::Split,
    };
    let (code, message) = (ErrorCode::Internal, String::new());
    let kinds = [
        (ConnState::Disconnected, "disconnected"),
        (ConnState::Connecting, "connecting"),
        (ConnState::Connected { tunnel }, "connected"),
        (ConnState::Disconnecting, "disconnecting"),
        (ConnState::LoginNeeded, "login_needed"),
        (ConnState::Failed { code, message }, "failed"),
    ];
    for (state, kind) in kinds {
        let said = serde_json::to_string(&StateKind::from(&state)).unwrap();
        assert_eq!(said, format!("{kind:?}"));
        // The same word as the state itself uses.
        let whole = serde_json::to_string(&state).unwrap();
        assert!(whole.contains(&format!(r#""state":{said}"#)), "{whole}");
    }
}

// Security rule: a log line is one plain line of bounded length, however
// it comes to be: made here, or read off the wire from a peer.
#[test]
fn a_log_text_is_one_plain_line_or_it_is_nothing() {
    // The number is part of the contract: the app sizes its rows by it.
    assert_eq!(MAX_LOG_TEXT_BYTES, 512);
    let longest = "x".repeat(MAX_LOG_TEXT_BYTES);
    assert_eq!(LogText::new(&longest).unwrap().as_str(), longest);
    // Counted in bytes, not characters.
    let wide = "é".repeat(MAX_LOG_TEXT_BYTES / 2);
    assert!(LogText::new(&wide).is_ok());
    let not_lines = [
        String::new(),
        format!("{longest}x"),
        format!("{wide}é"),
        "two\nlines".to_string(),
        "carriage\rreturn".to_string(),
        "escape\u{1b}[2J".to_string(),
        "tab\there".to_string(),
        "reordered\u{202e}txet".to_string(),
        "hid\u{200b}den".to_string(),
        // Not control characters, but each breaks a line.
        "two\u{2028}lines".to_string(),
        "two\u{2029}paragraphs".to_string(),
        "tagged\u{e0041}".to_string(),
    ];
    for text in &not_lines {
        assert_eq!(LogText::new(text), Err(NotLogText), "{text:?}");
        // The same text off the wire is refused in a line. A request to
        // add it can be read, so that the service can answer it.
        let quoted = serde_json::to_string(text).unwrap();
        let shape = Err(InvalidKind::Shape);
        let kind = |found: Result<(), FrameError>| match found {
            Err(FrameError::Invalid { kind, .. }) => Err(kind),
            other => Ok(other),
        };
        assert_eq!(
            kind(decode::<LogText>(&quoted).map(drop)),
            shape,
            "{text:?}"
        );
        let logged = format!(
            r#"{{"seq":1,"at_unix_ms":1,"level":"info","source":"engine","text":{quoted}}}"#
        );
        assert_eq!(
            kind(decode::<LogLine>(&logged).map(drop)),
            shape,
            "{text:?}"
        );
        let add = format!(
            r#"{{"id":1,"body":{{"method":"add_log","params":{{"level":"info","text":{quoted}}}}}}}"#
        );
        let Ok(Request { body, .. }) = decode::<Request>(&add) else {
            panic!("{text:?} must be readable, to be answered");
        };
        let RequestBody::AddLog(params) = body else {
            panic!("not an add_log: {body:?}");
        };
        assert_eq!(LogText::new(&params.text), Err(NotLogText));
    }
    // The error does not repeat the text.
    assert!(!NotLogText.to_string().contains("escape"));

    // Cleaning removes what misleads and keeps the rest, and still does
    // not cut: a line too long to keep is not kept in part.
    let cleaned = LogText::cleaned("es\u{1b}[2Jcape\u{202e} and a\ttab").unwrap();
    assert_eq!(cleaned.as_str(), "es[2Jcape and atab");
    assert_eq!(
        LogText::cleaned(&format!("{longest}\u{1b}"))
            .unwrap()
            .as_str(),
        longest
    );
    assert_eq!(LogText::cleaned(&format!("{longest}x")), Err(NotLogText));
    assert_eq!(LogText::cleaned("\u{1b}\n"), Err(NotLogText));
    // The marker for a line that was left out is itself a line.
    assert_eq!(LogText::new(LogText::LEFT_OUT), Ok(LogText::left_out()));
}

// A page of the log is one response and so one line. However long the
// lines are, and however many there are, the page stops in time.
#[test]
fn a_page_of_the_log_always_fits_in_a_line() {
    // The worst a line can be on the wire: every byte doubles.
    let worst = "\"".repeat(MAX_LOG_TEXT_BYTES);
    let all: Vec<LogLine> = (1..=600).map(|seq| line(seq, &worst)).collect();
    let (mut after, mut read, mut pages) = (0, Vec::new(), 0);
    loop {
        let rest = all.iter().filter(|line| line.seq > after).cloned();
        let page = LogPage::after(7, after, false, rest);
        let response = ServerMessage::Response(Response {
            id: u32::MAX,
            outcome: Outcome::Ok(ResponseBody::Logs(page.clone())),
        });
        let wire = encode(&response).expect("a page fits in a line");
        assert!(wire.len() <= LOG_PAGE_BYTES + 256, "{}", wire.len());
        if page.lines.is_empty() {
            // An empty page leaves the cursor where it was.
            assert_eq!(page.next, after);
            break;
        }
        // Nothing is skipped and nothing comes twice.
        assert_eq!(page.lines[0].seq, after + 1);
        assert_eq!(page.next, page.lines.last().unwrap().seq);
        after = page.next;
        read.extend(page.lines);
        pages += 1;
    }
    assert_eq!(read, all);
    // Full pages: about 48 KiB of lines that take about 1.1 KiB each.
    assert!((13..=16).contains(&pages), "{pages} pages");
    // Short lines go many to a page, by the same rule.
    let short = (1..=600).map(|seq| line(seq, "ok"));
    let page = LogPage::after(7, 0, false, short);
    assert!(page.lines.len() > 400, "{}", page.lines.len());
    assert!(encode(&ResponseBody::Logs(page)).unwrap().len() <= LOG_PAGE_BYTES + 256);
}

// The app reads these as JavaScript numbers. The contract says they stay
// below 2^53; a `bigint` here would break the app's arithmetic on them.
#[test]
fn the_log_numbers_are_plain_numbers_for_the_app() {
    use ts_rs::TS;
    let how = ts_rs::Config::default();
    let fields = [
        (LogLine::decl(&how), "seq"),
        (LogLine::decl(&how), "at_unix_ms"),
        (LogCursor::decl(&how), "run"),
        (LogCursor::decl(&how), "seq"),
        (LogPage::decl(&how), "run"),
        (LogPage::decl(&how), "next"),
        (Diagnostics::decl(&how), "uptime_s"),
    ];
    for (declared, field) in fields {
        let wanted = format!("{field}: number,");
        let found = declared.lines().any(|line| line.starts_with(&wanted));
        assert!(found, "{field} in {declared}");
    }
    // The largest value promised is carried without loss.
    let most = (1u64 << 53) - 1;
    let text = encode(&LogCursor {
        run: most,
        seq: most,
    })
    .unwrap();
    assert_eq!(
        text.trim_end(),
        r#"{"run":9007199254740991,"seq":9007199254740991}"#
    );
}

// The new requests refuse what they do not know, like the old ones.
#[test]
fn the_log_requests_refuse_unknown_fields() {
    for odd in [
        r#"{"id":1,"body":{"method":"logs","params":{"after":null,"all":true}}}"#,
        r#"{"id":1,"body":{"method":"logs","params":{"after":{"run":1,"seq":2,"x":3}}}}"#,
        r#"{"id":1,"body":{"method":"logs","params":{"after":{"seq":2}}}}"#,
        r#"{"id":1,"body":{"method":"watch_logs","params":{"on":true,"level":"debug"}}}"#,
        r#"{"id":1,"body":{"method":"watch_logs","params":{}}}"#,
        r#"{"id":1,"body":{"method":"add_log","params":{"level":"debug","text":"x"}}}"#,
        r#"{"id":1,"body":{"method":"add_log","params":{"level":"info","text":"x","source":"service"}}}"#,
        r#"{"id":1,"body":{"method":"add_log","params":{"level":"info"}}}"#,
        r#"{"id":1,"body":{"method":"diagnostics","params":{}}}"#,
    ] {
        assert!(decode::<Request>(odd).is_err(), "{odd}");
    }
    // A level for protocol detail does not exist, so no line can have it.
    assert!(decode::<LogLevel>(r#""debug""#).is_err());
}

// A peer that speaks version 2 knows none of this. It is told to update
// in the handshake, before either side sends what the other cannot read.
#[test]
fn a_version_2_peer_is_told_to_update() {
    let older = r#"{"protocol_version":2,"client":"app","client_version":"0.1.0"}"#;
    assert_eq!(peek_protocol_version(older), Ok(2));
    assert_ne!(peek_protocol_version(older), Ok(PROTOCOL_VERSION));
    let reply = HelloReply {
        protocol_version: 2,
        service_version: "0.1.0".to_string(),
        owner_claimed: true,
    };
    assert!(!reply.is_compatible());
}
