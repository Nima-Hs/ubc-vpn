//! `settings set-routes` while connected, against the real service on the
//! fakes. The ranges are made up.

use ubc_vpn_core::protocol::{ClientKind, ErrorCode, decode};
use ubc_vpn_core::settings_cli::{LiveRoutes, RoutesReply};
use ubc_vpn_core::state::ConnState;
use ubc_vpn_platform::fake::Op;

use crate::client::{Client, Limits};
use crate::connect_tests::{CODE, PASSWORD, Scene, Typist};
use crate::settings::{Command, run};

/// The saved routes are 10.255.0.0/24 and dept.example.test (see
/// `connect_tests.rs`). These add 198.51.100.0/24.
const WIDER: &str =
    r#"{"subnets":["10.255.0.0/24","198.51.100.0/24"],"dns_domains":["dept.example.test"]}"#;

fn connected() -> Scene {
    let scene = Scene::usual();
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    let (status, _, err) = scene.connect(&mut typist);
    assert_eq!(status, 0, "{err}");
    scene
}

/// Saves `typed` as the routes, and returns what the reply said of the
/// live connection.
fn save(scene: &Scene, typed: &str) -> Option<LiveRoutes> {
    let platform = || Ok(scene.rig.fake.platform(&scene.rig.root));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run(
        Command::SetRoutes,
        &platform,
        &mut typed.as_bytes(),
        &mut out,
        &mut err,
    );
    let out = String::from_utf8(out).unwrap();
    assert_eq!(status, 0, "{out}");
    match decode::<RoutesReply>(out.trim_end()).unwrap() {
        RoutesReply::Ok { live, .. } => live,
        other => panic!("{other:?}"),
    }
}

/// The subnets the service says the connection carries now.
fn carried(scene: &Scene) -> Option<Vec<String>> {
    let (status, out, _) = scene.rig.run(&["status", "--json"]);
    assert_eq!(status, 0);
    match decode::<ConnState>(out.trim_end()).unwrap() {
        ConnState::Connected { tunnel } => {
            Some(tunnel.subnets.iter().map(ToString::to_string).collect())
        }
        _ => None,
    }
}

// The issue's case: routes saved while connected are applied to the live
// connection, and the reply says so.
#[test]
fn routes_saved_while_connected_are_applied_to_it() {
    let scene = connected();
    assert_eq!(save(&scene, WIDER), Some(LiveRoutes::Applied));
    let now = carried(&scene).expect("still connected");
    assert_eq!(now, ["10.255.0.0/24", "198.51.100.0/24"]);
    let routed: Vec<_> = scene.rig.fake.applied().tunnel_routes;
    assert!(
        routed
            .iter()
            .any(|(_, net)| net.to_string() == "198.51.100.0/24")
    );
}

// Saving the routes the connection carries already changes nothing, and
// the reply says they are applied.
#[test]
fn routes_the_connection_carries_already_are_applied() {
    let scene = connected();
    let calls = scene.rig.fake.calls();
    let same = r#"{"subnets":["10.255.0.0/24"],"dns_domains":["dept.example.test"]}"#;
    assert_eq!(save(&scene, same), Some(LiveRoutes::Applied));
    assert_eq!(scene.rig.fake.calls(), calls, "something was done");
}

// Not connected, the reply says the routes are for the next connect: before
// anyone has used the service, and once disconnected.
#[test]
fn routes_saved_while_not_connected_are_for_the_next_connect() {
    let scene = Scene::usual();
    assert_eq!(save(&scene, WIDER), Some(LiveRoutes::NextConnect));
    // Security rule: saving routes makes nobody the owner.
    let platform = scene.rig.fake.platform(&scene.rig.root);
    let client = Client::reach(&platform, ClientKind::Cli, Limits::default()).unwrap();
    assert!(!client.owner_claimed(), "saving routes claimed the service");
    let scene = connected();
    assert_eq!(scene.rig.run(&["disconnect"]).0, 0);
    assert_eq!(save(&scene, WIDER), Some(LiveRoutes::NextConnect));
}

// Routes the settings accept but the service does not, here one into the
// network the machine is on, are saved, and the connection keeps the routes
// it had. The reply says so.
#[test]
fn routes_the_service_refuses_leave_the_connection_as_it_was() {
    let scene = Scene::usual();
    let own = [[192, 168, 0, 10].into()];
    scene
        .rig
        .fake
        .set_local(&own, &["192.168.0.0/24".parse().unwrap()]);
    let mut typist = Typist::typing(&[Some(PASSWORD), Some(CODE)]);
    assert_eq!(scene.connect(&mut typist).0, 0);
    let home = r#"{"subnets":["192.168.0.0/24"],"dns_domains":[]}"#;
    let Some(LiveRoutes::Refused { code, message }) = save(&scene, home) else {
        panic!("not refused");
    };
    assert_eq!(code, ErrorCode::RouteRefused);
    assert!(message.contains("keeps the routes it has"), "{message}");
    assert_eq!(carried(&scene), Some(vec!["10.255.0.0/24".to_string()]));
}

// Applying them fails closed: the connection is closed, and the reply says
// why.
#[test]
fn routes_that_cannot_be_applied_close_the_connection() {
    let scene = connected();
    let unknown = Some(ubc_vpn_platform::Error::Unsupported);
    scene.rig.fake.set_failure(Op::AddTunnelRoutes, unknown);
    let live = save(&scene, WIDER);
    scene.rig.fake.set_failure(Op::AddTunnelRoutes, None);
    assert!(
        matches!(
            live,
            Some(LiveRoutes::Failed {
                code: ErrorCode::Internal,
                ..
            })
        ),
        "{live:?}"
    );
    assert_eq!(carried(&scene), None);
    assert!(scene.rig.fake.applied() == Default::default());
}
