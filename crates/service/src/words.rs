//! Small pieces of the service's log lines, said the same way everywhere.

/// A value of one of the protocol's closed lists as the word the protocol
/// sends for it, such as `route_refused`.
macro_rules! word {
    ($value:expr) => {
        serde_json::to_string(&$value)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string()
    };
}

pub(crate) use word;

/// A number of things: `1 subnet`, `2 subnets`.
pub(crate) fn counted(many: usize, one: &str) -> String {
    match many {
        1 => format!("1 {one}"),
        _ => format!("{many} {one}s"),
    }
}

#[cfg(test)]
mod tests {
    use ubc_vpn_core::protocol::ErrorCode;

    use super::*;

    #[test]
    fn words_and_counts_read_as_meant() {
        assert_eq!(word!(ErrorCode::RouteRefused), "route_refused");
        assert_eq!(counted(0, "pin"), "0 pins");
        assert_eq!(counted(1, "pin"), "1 pin");
        assert_eq!(counted(2, "DNS domain"), "2 DNS domains");
    }
}
