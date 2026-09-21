//! What one E2EE client line is charged before it is parsed (companion 16).
//!
//! A command line, and fragment zero of an object, costs one E2EE command
//! token for the session, and one signature-verification token for the
//! account when it carries object bytes: one object is one verification.
//! After the cheap fragment-zero checks and the atomic quota reservation,
//! the continuation fragments of that object are not line-count penalized
//! again; they are charged by decoded bytes through the dedicated bucket of
//! the authenticated account and device, which provides at least
//! `MIN_ADMITTED_E2EE_INGRESS_RATE`. A continuation is one only behind a
//! fragment zero this connection had accepted: it opened the connection's
//! one in-progress assembly, or it was answered from the retry cache so its
//! duplicate fragments cost no work. Every other fragment is a command line
//! again, pays like one, and is refused by the router.

#![forbid(unsafe_code)]

use agenc_relay_client_wire::ParsedMessage;
use agenc_relay_e2ee::wire::fragment::{FragmentTag, fragment_tag_of};
use agenc_relay_types::{AccountId, UserId};

use super::E2eeEdge;
use crate::RuntimeError;
use crate::admission::{BucketDemand, BucketKey, BucketKind};
use crate::connection::ConnectionGeneration;

/// The client-only fragment tag key as the client sends it.
const CLIENT_FRAGMENT_KEY: &str = "+agenc.ag/e2ee";

/// The admission class of one E2EE client line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressCharge {
    /// A command line or a fragment zero; `carries_object` when the line
    /// carries object bytes whose verification the account pays for.
    Command {
        /// Whether the line carries a client fragment tag.
        carries_object: bool,
    },
    /// A continuation fragment behind an accepted fragment zero.
    Continuation {
        /// The attached device, all zero while none is attached.
        device: [u8; 16],
        /// The decoded bytes this fragment carries.
        decoded_bytes: u64,
    },
}

impl IngressCharge {
    /// The bucket demands of this line, all charged or none.
    pub fn demands(
        self,
        user_id: UserId,
        account: Option<AccountId>,
    ) -> Result<Vec<BucketDemand>, RuntimeError> {
        let command = || BucketDemand::new(BucketKind::E2eeCommand, BucketKey::Session(user_id), 1);
        match (self, account) {
            (
                Self::Continuation {
                    device,
                    decoded_bytes,
                },
                Some(account),
            ) => Ok(vec![BucketDemand::new(
                BucketKind::E2eeIngress,
                BucketKey::AccountDevice(account, device),
                decoded_bytes,
            )?]),
            (
                Self::Command {
                    carries_object: true,
                },
                Some(account),
            ) => Ok(vec![
                command()?,
                BucketDemand::new(BucketKind::E2eeSignature, BucketKey::Account(account), 1)?,
            ]),
            // No object, or no account: the router refuses an object line
            // without an account before anything is assembled.
            _ => Ok(vec![command()?]),
        }
    }
}

impl E2eeEdge {
    /// Classifies one E2EE client line for admission, before any parsing
    /// beyond its one bounded fragment tag.
    #[must_use]
    pub fn ingress_charge(
        &self,
        generation: ConnectionGeneration,
        message: &ParsedMessage,
    ) -> IngressCharge {
        let tags: Vec<(&str, &str)> = message
            .tags()
            .iter()
            .filter_map(|tag| tag.value().map(|value| (tag.key(), value)))
            .collect();
        let carries_object = message
            .tags()
            .iter()
            .any(|tag| tag.key() == CLIENT_FRAGMENT_KEY);
        let continuation = fragment_tag_of(&tags)
            .ok()
            .flatten()
            .filter(|(key, _)| *key == CLIENT_FRAGMENT_KEY)
            .and_then(|(_, raw)| FragmentTag::parse(raw).ok())
            .filter(|tag| tag.part != 0 && self.continues_accepted_zero(generation, tag));
        match continuation {
            Some(tag) => IngressCharge::Continuation {
                device: self
                    .origins
                    .get(&generation)
                    .and_then(|origin| origin.device)
                    .map_or([0; 16], |(device, _)| device),
                decoded_bytes: u64::try_from(tag.segment.len()).unwrap_or(u64::MAX),
            },
            None => IngressCharge::Command { carries_object },
        }
    }

    /// Whether `tag` continues the object whose fragment zero this
    /// connection last had accepted.
    fn continues_accepted_zero(&self, generation: ConnectionGeneration, tag: &FragmentTag) -> bool {
        self.ingress
            .get(&generation)
            .is_some_and(|open| open.key.object_id == tag.object_id)
            || self.retried.get(&generation) == Some(tag.object_id.as_bytes())
    }
}
