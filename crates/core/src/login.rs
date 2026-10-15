//! The messages between the app and `ubc-vpn connect --json`.
//!
//! The app never talks to the gateway and never holds the session cookie. It
//! starts the command-line client, relays its questions to the user, and sends
//! the answers back. Each message is one JSON line: [`CliMessage`]s on the
//! client's standard output, [`AppMessage`]s on its standard input.

use serde::{Deserialize, Serialize};

use crate::redact::Secret;

/// What kind of answer a prompt wants, so the app can show the right field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum PromptKind {
    /// The CWL username.
    Username,
    /// The password. Hide what is typed.
    Password,
    /// A one-time MFA code. Hide what is typed.
    Code,
    /// Anything else the gateway asks for.
    Text,
}

/// A line the command-line client writes for the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum CliMessage {
    /// A question for the user. The app replies with an answer carrying the
    /// same `id`, or cancels.
    Prompt {
        /// Echoed in the answer.
        id: u32,
        /// What kind of field to show.
        kind: PromptKind,
        /// The gateway's wording for the question.
        label: String,
        /// Anything the gateway says alongside the question, such as why the
        /// last attempt was refused. Left out when there is nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(test, ts(optional))]
        message: Option<String>,
    },
    /// Login succeeded and the service accepted the connect request. Always
    /// the last line. Connection progress follows on the channel.
    Done,
    /// Something failed. Always the last line.
    Error {
        /// For the app to act on.
        code: LoginErrorCode,
        /// For the user to read. Never contains a secret.
        message: String,
    },
}

/// A line the app writes for the command-line client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum AppMessage {
    /// The user's answer to the prompt with the same `id`.
    Answer {
        /// The `id` of the prompt being answered.
        id: u32,
        /// What the user entered.
        value: Secret,
    },
    /// The user gave up. The client stops without contacting the gateway
    /// again.
    Cancel,
}

/// The kinds of login failure the app can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub enum LoginErrorCode {
    /// The gateway rejected the username, the password or the one-time code.
    /// It does not say which: it simply shows the form again. The client stops
    /// at once and never retries, so no further MFA request is sent.
    WrongPassword,
    /// The gateway did not take the login in a way that points at the
    /// username's format: it sent an empty reply to the answers, or asked for
    /// the username again before any password. Check the username.
    CheckUsername,
    /// The gateway's certificate matched none of the policy's pins.
    PinMismatch,
    /// The user cancelled.
    Cancelled,
    /// The gateway could not be reached.
    GatewayUnreachable,
    /// The service refused one of the chosen routes or DNS domains.
    RouteRefused,
    /// The service is not running or refused the connection.
    ServiceUnavailable,
    /// The service is already connecting, connected or disconnecting.
    /// Disconnect first.
    Busy,
    /// The service belongs to another user of this computer.
    NotOwner,
    /// Something unexpected went wrong.
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode, encode};

    #[test]
    fn prompt_wire_format_matches_the_architecture_document() {
        let prompt = CliMessage::Prompt {
            id: 1,
            kind: PromptKind::Password,
            label: "Password".to_string(),
            message: None,
        };
        assert_eq!(
            encode(&prompt).unwrap(),
            "{\"type\":\"prompt\",\"id\":1,\"kind\":\"password\",\"label\":\"Password\"}\n"
        );
        assert_eq!(encode(&CliMessage::Done).unwrap(), "{\"type\":\"done\"}\n");

        let with_message = CliMessage::Prompt {
            id: 2,
            kind: PromptKind::Code,
            label: "Code".to_string(),
            message: Some("Enter the code from your authenticator.".to_string()),
        };
        let line = encode(&with_message).unwrap();
        assert!(line.contains(r#""message":"Enter the code from your authenticator.""#));
        assert_eq!(decode::<CliMessage>(&line).unwrap(), with_message);
    }

    #[test]
    fn answers_and_cancel_round_trip() {
        let answer: AppMessage = decode(r#"{"type":"answer","id":1,"value":"hunter2"}"#).unwrap();
        match &answer {
            AppMessage::Answer { id, value } => {
                assert_eq!(*id, 1);
                assert_eq!(value.expose(), "hunter2");
            }
            AppMessage::Cancel => panic!("expected an answer"),
        }
        assert!(!format!("{answer:?}").contains("hunter2"));
        assert_eq!(
            decode::<AppMessage>(r#"{"type":"cancel"}"#).unwrap(),
            AppMessage::Cancel
        );
    }

    #[test]
    fn errors_carry_a_code_the_app_can_match() {
        let error = CliMessage::Error {
            code: LoginErrorCode::WrongPassword,
            message: "The gateway rejected the password.".to_string(),
        };
        let line = encode(&error).unwrap();
        assert!(line.contains(r#""code":"wrong_password""#));
        assert_eq!(decode::<CliMessage>(&line).unwrap(), error);
    }

    // The app matches on these names, so each is pinned here.
    #[test]
    fn every_error_code_has_a_stable_name() {
        use LoginErrorCode::*;
        let names = [
            (WrongPassword, "wrong_password"),
            (CheckUsername, "check_username"),
            (PinMismatch, "pin_mismatch"),
            (Cancelled, "cancelled"),
            (GatewayUnreachable, "gateway_unreachable"),
            (RouteRefused, "route_refused"),
            (ServiceUnavailable, "service_unavailable"),
            (Busy, "busy"),
            (NotOwner, "not_owner"),
            (Internal, "internal"),
        ];
        for (code, name) in names {
            assert_eq!(encode(&code).unwrap(), format!("\"{name}\"\n"));
        }
        assert!(decode::<LoginErrorCode>("\"anything_else\"").is_err());
    }
}
