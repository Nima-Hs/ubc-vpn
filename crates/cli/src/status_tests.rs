//! The `status` command and how the command line reports a service it cannot
//! use, against the real service running on the platform fake and the engine
//! fake, and against a pretend service.

use ubc_vpn_core::protocol::{
    ErrorCode, HelloReply, Outcome, PROTOCOL_VERSION, Request, Response, ServerMessage, decode,
};
use ubc_vpn_platform::fake::{Op, paths};
use ubc_vpn_platform::{Error, Transport};

use super::*;
use crate::test_support::{Rig, greet, scripted, tell};

#[test]
fn status_claims_on_first_use_and_prints_the_state() {
    let rig = Rig::new();
    let _service = rig.service();
    assert_eq!(
        rig.run(&["status"]),
        (0, "Disconnected\n".into(), "".into())
    );
    let json = "{\"state\":\"disconnected\"}\n";
    assert_eq!(rig.run(&["status", "--json"]), (0, json.into(), "".into()));
    // The first run made this user the owner.
    let name = paths(&rig.root).channel_name;
    let stranger = "someone-else".parse().unwrap();
    let refused = rig.fake.connect_as(&name, &stranger).err();
    assert_eq!(refused, Some(Error::PermissionDenied));
}

/// Writes a policy where the installer would, as an installed UBC VPN has.
fn install_policy(rig: &Rig) {
    let dir = paths(&rig.root).policy_dir;
    std::fs::create_dir_all(&dir).unwrap();
    let pin = format!("pin-sha256:{}=", "A".repeat(43));
    let policy = format!(r#"{{"gateway":"vpn.example.test","pins":["{pin}"]}}"#);
    std::fs::write(dir.join("policy.json"), policy).unwrap();
}

// When `status` cannot reach the service it says which of the three it is,
// and what to do next: install UBC VPN, start its service, or ask the
// owner or an administrator.
#[test]
fn status_says_why_it_cannot_reach_the_service_and_what_to_do() {
    // Nothing installed: no service and no policy.
    let rig = Rig::new();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("UBC VPN is not installed"), "{err}");
    assert!(err.contains("Install UBC VPN"), "{err}");

    // Installed, so its policy is there, but the service is stopped.
    install_policy(&rig);
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("installed but not running"), "{err}");
    assert!(err.contains("restart the computer"), "{err}");
    #[cfg(windows)]
    assert!(err.contains("sc start ubc-vpn"), "{err}");

    // Running, but the channel is kept to another user.
    let rig = Rig::new();
    install_policy(&rig);
    let _service = rig.service();
    rig.claim_as_someone_else();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_OWNER, ""));
    assert!(err.contains("belongs to another user"), "{err}");
    assert!(
        err.contains("administrator can make you the owner"),
        "{err}"
    );
}

#[test]
fn each_failure_has_its_own_exit_code_and_message() {
    let rig = Rig::new();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_RUNNING, ""));
    assert!(err.contains("not installed"), "{err}");

    // Not the owner: refused by the OS, and, where the OS could not narrow
    // the channel, refused by the service.
    for narrowed in [true, false] {
        let rig = Rig::new();
        if !narrowed {
            let broken = Some(Error::Unsupported);
            rig.fake.set_failure(Op::RestrictTo, broken);
        }
        let _service = rig.service();
        rig.claim_as_someone_else();
        let (code, out, err) = rig.run(&["status", "--json"]);
        assert_eq!((code, out.as_str()), (NOT_OWNER, ""), "{narrowed}");
        assert!(err.contains("not the owner"), "{err}");
    }

    // Something else holds the channel. This is not "not running": the
    // user has to be told, and nothing may be sent.
    let rig = Rig::new();
    let _service = rig.service();
    let impostor = Some(Error::NotTheService);
    rig.fake.set_failure(Op::Connect, impostor);
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (NOT_THE_SERVICE, ""));
    assert!(err.contains("Another program is answering"), "{err}");
    rig.fake.set_failure(Op::Connect, None);
    assert!(
        !rig.fake
            .platform(&rig.root)
            .paths
            .state_dir
            .join("state.json")
            .exists(),
        "no claim was sent"
    );

    for usage in [
        &[][..],
        &["bogus"],
        &["status", "--bogus"],
        &["status", "--json", "x"],
    ] {
        let (code, _, err) = rig.run(usage);
        assert_eq!(code, USAGE, "{usage:?}");
        assert!(err.contains("Usage:"), "{err}");
    }
    let unsupported = || Err(Error::Unsupported);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run(&["status"], &unsupported, &mut out, &mut err), FAILED);

    // A request the service refuses is a failure too, with its reason: here
    // the first claim, which the service cannot store.
    let rig = Rig::new();
    let _service = rig.service();
    let state = rig.fake.platform(&rig.root).paths.state_dir;
    std::fs::create_dir_all(state.join(".state.json.new")).unwrap();
    let (code, out, err) = rig.run(&["status"]);
    assert_eq!((code, out.as_str()), (FAILED, ""));
    assert!(err.contains("The owner could not be saved"), "{err}");

    // The help says what the statuses mean and that the first use claims.
    let (code, help, _) = rig.run(&["help"]);
    assert_eq!(code, 0);
    for line in [
        "3  UBC VPN is not installed, or its service is not running",
        "6  another program",
        "9  cancelled",
        "connect, disconnect or status becomes the owner",
        "The bridge claims nothing itself",
        "never taken from an argument, a variable or a file",
        "is told to disconnect before the program ends.",
        "connect [--profile <id>] [--json]  Log in and connect",
        "which is sent only for the username it\nwas saved for",
        "A\ncancel line, or standard input closing, stops the login.",
        "bridge            Carry messages",
        "logs [--json] [--follow]  Show what the service has logged",
        "they do not make
anyone the owner",
        "settings reset [--force] --json  Start afresh",
    ] {
        assert!(help.contains(line), "{help}");
    }
    assert_eq!(rig.run(&["help"]).0, 0);
}

// A service from another version answers the hello and hangs up. The user
// is told to update, not shown a broken connection.
#[test]
fn a_service_of_another_version_means_please_update() {
    let rig = Rig::new();
    let listener = rig.fake.listen(&paths(&rig.root).channel_name).unwrap();
    let service = std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        conn.read_line().unwrap();
        let reply = HelloReply {
            protocol_version: PROTOCOL_VERSION + 1,
            service_version: "9.9.9".to_string(),
            owner_claimed: true,
        };
        conn.write_line(encode(&reply).unwrap().trim_end()).unwrap();
    });
    let (code, out, err) = rig.run(&["status"]);
    service.join().unwrap();
    assert_eq!((code, out.as_str()), (MISMATCH, ""));
    assert!(
        err.contains("9.9.9") && err.contains("Please update"),
        "{err}"
    );
}

/// Runs `status` against a pretend service that answers it with `answer`.
fn status_answered_with(answer: ResponseBody, args: &[&str]) -> (u8, String, String) {
    let rig = Rig::new();
    let service = scripted(&rig, move |conn| {
        greet(conn);
        let asked: Request = decode(&conn.read_line().unwrap().unwrap()).unwrap();
        let outcome = Outcome::Ok(answer);
        let response = Response {
            id: asked.id,
            outcome,
        };
        tell(conn, &ServerMessage::Response(response));
    });
    let result = rig.run(args);
    service.join().unwrap();
    result
}

// `status` is how a person or a script learns whether traffic goes through
// the tunnel, so every state has its exact words and its exact JSON.
#[test]
fn every_state_is_printed_exactly() {
    let tunnel = ubc_vpn_core::state::TunnelInfo {
        interface: "utun4".to_string(),
        address: "10.255.0.2".to_string(),
        subnets: vec![
            "10.19.0.0/16".parse().unwrap(),
            "198.19.0.0/16".parse().unwrap(),
        ],
        dns_domains: vec![
            "dept.example.test".to_string(),
            "cs.example.test".to_string(),
        ],
        mode: ubc_vpn_core::state::TunnelMode::Split,
    };
    let full = ubc_vpn_core::state::TunnelInfo {
        mode: ubc_vpn_core::state::TunnelMode::Full,
        ..tunnel.clone()
    };
    let failed = ConnState::Failed {
        code: ErrorCode::VerificationFailed,
        // Whatever an OS error may hold, the terminal gets no control codes
        // and nothing that reorders the line. Ordinary Unicode is kept.
        message:
            "10.19.0.0/16 is \u{1b}[2Jnot routed \u{202e}(réseau 網, می\u{200c}خواهم)\u{200b}\r\n"
                .to_string(),
    };
    let states = [
        (
            ConnState::Disconnected,
            "Disconnected\n",
            r#"{"state":"disconnected"}"#,
        ),
        (
            ConnState::Connecting,
            "Connecting\n",
            r#"{"state":"connecting"}"#,
        ),
        (
            ConnState::Disconnecting,
            "Disconnecting\n",
            r#"{"state":"disconnecting"}"#,
        ),
        (
            ConnState::LoginNeeded,
            "Login needed: the session has ended.\n",
            r#"{"state":"login_needed"}"#,
        ),
        (
            failed,
            "Failed: 10.19.0.0/16 is [2Jnot routed (réseau 網, می\u{200c}خواهم)\n",
            "{\"state\":\"failed\",\"code\":\"verification_failed\",\"message\":\"10.19.0.0/16 is \\u001b[2Jnot routed (réseau 網, می\u{200c}خواهم)\\r\\n\"}",
        ),
        (
            ConnState::Connected { tunnel },
            "Connected (utun4 as 10.255.0.2)\n  \
             Tunnel: split (only the chosen UBC subnets and domains)\n  \
             Subnets: 10.19.0.0/16, 198.19.0.0/16\n  \
             DNS domains: dept.example.test, cs.example.test\n",
            r#"{"state":"connected","tunnel":{"interface":"utun4","address":"10.255.0.2","subnets":["10.19.0.0/16","198.19.0.0/16"],"dns_domains":["dept.example.test","cs.example.test"],"mode":"split"}}"#,
        ),
        // In full mode the chosen subnets and domains are not all the tunnel
        // carries, and the words say so.
        (
            ConnState::Connected {
                tunnel: full.clone(),
            },
            "Connected (utun4 as 10.255.0.2)\n  \
             Tunnel: full (all IPv4 traffic and every name lookup; IPv6 is blocked)\n  \
             Subnets: 10.19.0.0/16, 198.19.0.0/16, and all other IPv4 traffic\n  \
             DNS domains: dept.example.test, cs.example.test, and every other name\n",
            r#"{"state":"connected","tunnel":{"interface":"utun4","address":"10.255.0.2","subnets":["10.19.0.0/16","198.19.0.0/16"],"dns_domains":["dept.example.test","cs.example.test"],"mode":"full"}}"#,
        ),
        // No domains is said as none, not as an empty line.
        (
            ConnState::Connected {
                tunnel: ubc_vpn_core::state::TunnelInfo {
                    dns_domains: Vec::new(),
                    ..full
                },
            },
            "Connected (utun4 as 10.255.0.2)\n  \
             Tunnel: full (all IPv4 traffic and every name lookup; IPv6 is blocked)\n  \
             Subnets: 10.19.0.0/16, 198.19.0.0/16, and all other IPv4 traffic\n  \
             DNS domains: none, and every other name\n",
            r#"{"state":"connected","tunnel":{"interface":"utun4","address":"10.255.0.2","subnets":["10.19.0.0/16","198.19.0.0/16"],"dns_domains":[],"mode":"full"}}"#,
        ),
    ];
    for (state, words, json) in states {
        let answer = ResponseBody::Status(state);
        let said = status_answered_with(answer.clone(), &["status"]);
        assert_eq!(said, (0, words.to_string(), String::new()));
        let said = status_answered_with(answer, &["status", "--json"]);
        assert_eq!(said, (0, format!("{json}\n"), String::new()));
    }
}

// An answer to `status` that is not a status is an error. Nothing is printed
// as if it were the state.
#[test]
fn an_answer_that_is_not_a_status_is_an_error() {
    for args in [&["status"][..], &["status", "--json"]] {
        let (code, out, err) = status_answered_with(ResponseBody::Claimed, args);
        assert_eq!((code, out.as_str()), (FAILED, ""));
        assert!(err.contains("unexpected answer"), "{err}");
    }
}

// A service of a later version may answer the hello in a shape this version
// cannot read. That is still "please update", not a broken connection.
#[test]
fn a_reply_this_version_cannot_read_still_means_please_update() {
    let rig = Rig::new();
    let service = scripted(&rig, |conn| {
        // The command-line client says which program it is.
        let hello: ubc_vpn_core::protocol::Hello =
            decode(&conn.read_line().unwrap().unwrap()).unwrap();
        assert_eq!(hello.client, ClientKind::Cli);
        let later = r#"{"protocol_version":99,"service":{"version":"9.9.9"}}"#;
        conn.write_line(later).unwrap();
    });
    let (code, out, err) = rig.run(&["status"]);
    service.join().unwrap();
    assert_eq!((code, out.as_str()), (MISMATCH, ""));
    assert!(
        err.contains("another version") && err.contains("Please update"),
        "{err}"
    );
}
