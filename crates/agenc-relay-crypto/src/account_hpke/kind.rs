//! The closed sets of messages accepted by each account-service HPKE profile.

use agenc_relay_types::{AccountServiceMessageKind, AccountServiceResponseKind};

mod private {
    pub trait Sealed {}
}

/// Selects one of the reviewed HPKE profiles and its corresponding result type.
/// External callers cannot define additional wire tags or label combinations.
pub trait AccountHpkeExchange: private::Sealed + Copy + Eq {
    /// The allowed response type for this profile.
    type Response: Copy + Eq;
    /// The version in the authenticated plaintext, header and request info.
    const VERSION: u16;
    /// The authenticated request tag.
    fn request_tag(self) -> u16;
    /// The authenticated response tag.
    fn response_tag(response: Self::Response) -> u16;
    /// The recognized request with this tag in this profile.
    fn request_from_tag(tag: u16) -> Option<Self>;
    /// The recognized response with this tag in this profile.
    fn response_from_tag(tag: u16) -> Option<Self::Response>;
    /// The only response allowed for this specific request.
    fn expected_response(self) -> Self::Response;
}

impl private::Sealed for AccountServiceMessageKind {}

impl AccountHpkeExchange for AccountServiceMessageKind {
    type Response = AccountServiceResponseKind;
    const VERSION: u16 = 1;

    fn request_tag(self) -> u16 {
        self.wire_value()
    }

    fn response_tag(response: Self::Response) -> u16 {
        response.wire_value()
    }

    fn request_from_tag(tag: u16) -> Option<Self> {
        Self::from_wire(tag).ok()
    }

    fn response_from_tag(tag: u16) -> Option<Self::Response> {
        AccountServiceResponseKind::from_wire(tag).ok()
    }

    fn expected_response(self) -> Self::Response {
        match self {
            Self::AccountCreateStart => AccountServiceResponseKind::AccountCreateChallenge,
            Self::AccountCreateFinish => AccountServiceResponseKind::AccountCreateComplete,
            Self::OpaqueAuthStart => AccountServiceResponseKind::OpaqueAuthChallenge,
            Self::OpaqueAuthFinish => AccountServiceResponseKind::OpaqueAuthComplete,
            Self::CredentialChangeStart => AccountServiceResponseKind::CredentialChangeChallenge,
            Self::CredentialChangeFinish => AccountServiceResponseKind::CredentialChangeComplete,
        }
    }
}

/// Two correlated request/response pairs in the optional initial-root profile.
/// Each pair uses its own tag in both authenticated directions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialRootExchange {
    /// The creation START carrying a private commitment and its OPAQUE challenge.
    ClaimedCreateStart,
    /// The registered private read or choose action and its sealed disposition.
    Claim,
}

impl InitialRootExchange {
    /// Recognizes an exact request or response header in the negotiated profile.
    #[must_use]
    pub const fn from_header(version: u16, tag: u16) -> Option<Self> {
        match (version, tag) {
            (2, 7) => Some(Self::ClaimedCreateStart),
            (2, 8) => Some(Self::Claim),
            _ => None,
        }
    }
}

impl private::Sealed for InitialRootExchange {}

impl AccountHpkeExchange for InitialRootExchange {
    type Response = Self;
    const VERSION: u16 = 2;

    fn request_tag(self) -> u16 {
        match self {
            Self::ClaimedCreateStart => 7,
            Self::Claim => 8,
        }
    }

    fn response_tag(response: Self::Response) -> u16 {
        response.request_tag()
    }

    fn request_from_tag(tag: u16) -> Option<Self> {
        Self::from_header(Self::VERSION, tag)
    }

    fn response_from_tag(tag: u16) -> Option<Self::Response> {
        Self::request_from_tag(tag)
    }

    fn expected_response(self) -> Self::Response {
        self
    }
}
