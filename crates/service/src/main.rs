//! The privileged service. It opens the tunnel, applies routes and DNS,
//! verifies them, and cleans up.

fn main() {
    println!("ubc-vpn-service {}", ubc_vpn_core::VERSION);
}
