//! The `ECAP IRCMLS` link profile negotiation (companion Section 12.5):
//! four flags, one nonextendable five-second deadline, exact tuple
//! equality, and the durable sequencer key-set record rule.
//!
//! Time is supplied by the caller in milliseconds of a monotonic clock.

use std::fmt;

use crate::error::E2eeError;
use crate::federation::frames::CompanionFrame;
use crate::profile::EcapTuple;

/// The negotiation deadline in milliseconds.
pub const NEGOTIATION_DEADLINE_MILLIS: u64 = 5_000;

/// Why the link must send `ERROR :IRC-MLS profile mismatch` and close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcapViolation {
    /// A tuple field differed from the local profile.
    TupleMismatch,
    /// A second OFFER or ACK arrived.
    Duplicate,
    /// An ACK arrived before the peer OFFER.
    AckBeforeOffer,
    /// The deadline passed before activation.
    Timeout,
    /// An E2EE frame arrived before the profile was active.
    NotActive,
    /// The line's prefix was not the authenticated peer.
    Prefix,
}

impl fmt::Display for EcapViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TupleMismatch => "the ECAP tuple differs from the local profile",
            Self::Duplicate => "a duplicate ECAP frame arrived",
            Self::AckBeforeOffer => "an ECAP ACK arrived before the peer OFFER",
            Self::Timeout => "the ECAP deadline passed",
            Self::NotActive => "an E2EE frame arrived before the profile was active",
            Self::Prefix => "the ECAP prefix is not the authenticated peer",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for EcapViolation {}

/// The per-link negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcapNegotiation {
    local: EcapTuple,
    deadline: u64,
    peer_offer_received: bool,
    peer_ack_sent: bool,
    peer_ack_received: bool,
    profile_active: bool,
}

impl EcapNegotiation {
    /// Starts negotiating at `now`: returns the state and the one OFFER
    /// to send immediately.
    #[must_use]
    pub fn start(local: EcapTuple, now: u64) -> (Self, CompanionFrame) {
        let offer = CompanionFrame::EcapOffer(local.clone());
        (
            Self {
                local,
                deadline: now.saturating_add(NEGOTIATION_DEADLINE_MILLIS),
                peer_offer_received: false,
                peer_ack_sent: false,
                peer_ack_received: false,
                profile_active: false,
            },
            offer,
        )
    }

    /// The local tuple.
    #[must_use]
    pub const fn local(&self) -> &EcapTuple {
        &self.local
    }

    /// Whether every E2EE frame may now flow.
    #[must_use]
    pub const fn profile_active(&self) -> bool {
        self.profile_active
    }

    /// The four flags in specification order.
    #[must_use]
    pub const fn flags(&self) -> [bool; 4] {
        [
            self.peer_offer_received,
            self.peer_ack_sent,
            self.peer_ack_received,
            self.profile_active,
        ]
    }

    fn activate_if_complete(&mut self) {
        self.profile_active =
            self.peer_offer_received && self.peer_ack_sent && self.peer_ack_received;
    }

    /// Handles the peer OFFER: on the first exact match, returns the ACK to
    /// send.
    pub fn on_offer(
        &mut self,
        prefix_ok: bool,
        tuple: &EcapTuple,
    ) -> Result<CompanionFrame, EcapViolation> {
        if !prefix_ok {
            return Err(EcapViolation::Prefix);
        }
        if self.peer_offer_received {
            return Err(EcapViolation::Duplicate);
        }
        if *tuple != self.local {
            return Err(EcapViolation::TupleMismatch);
        }
        self.peer_offer_received = true;
        self.peer_ack_sent = true;
        self.activate_if_complete();
        Ok(CompanionFrame::EcapAck(tuple.clone()))
    }

    /// Handles the peer ACK, legal only after the peer OFFER.
    pub fn on_ack(&mut self, prefix_ok: bool, tuple: &EcapTuple) -> Result<(), EcapViolation> {
        if !prefix_ok {
            return Err(EcapViolation::Prefix);
        }
        if !self.peer_offer_received {
            return Err(EcapViolation::AckBeforeOffer);
        }
        if self.peer_ack_received {
            return Err(EcapViolation::Duplicate);
        }
        if *tuple != self.local {
            return Err(EcapViolation::TupleMismatch);
        }
        self.peer_ack_received = true;
        self.activate_if_complete();
        Ok(())
    }

    /// Checks the deadline at `now`.
    pub fn on_tick(&self, now: u64) -> Result<(), EcapViolation> {
        if !self.profile_active && now >= self.deadline {
            return Err(EcapViolation::Timeout);
        }
        Ok(())
    }

    /// The deadline instant.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Admits a non-ECAP companion frame only once the profile is active.
    pub fn admit(&self, frame: &CompanionFrame) -> Result<(), EcapViolation> {
        match frame {
            CompanionFrame::EcapOffer(_) | CompanionFrame::EcapAck(_) => {
                Err(EcapViolation::Duplicate)
            }
            _ if self.profile_active => Ok(()),
            _ => Err(EcapViolation::NotActive),
        }
    }
}

/// The durable highest accepted sequencer key set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeySetRecord {
    /// Set generation.
    pub generation: u64,
    /// Set digest.
    pub hash: [u8; 32],
}

/// How an offered key set relates to the durable record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySetAcceptance {
    /// No record existed; the first configured set initializes it.
    Initialized,
    /// The offered set equals the record.
    Same,
    /// The offered set is the direct successor; continuity must be proven
    /// by the caller before the record advances.
    Successor,
}

/// Why an offered key set is fatal before activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeySetError {
    /// A lower generation than the record.
    Rollback,
    /// A generation more than one above the record.
    Gap,
    /// The same generation with a different hash.
    Equivocation,
    /// The generation counter is exhausted.
    Exhausted,
    /// The offered set differs from the locally configured one.
    LocalMismatch,
}

impl fmt::Display for KeySetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Rollback => "the key set generation is lower than the record",
            Self::Gap => "the key set generation skips the record",
            Self::Equivocation => "the key set hash differs at the recorded generation",
            Self::Exhausted => "the key set generation counter is exhausted",
            Self::LocalMismatch => "the key set differs from the local configuration",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for KeySetError {}

/// Classifies the locally configured set `local` against the durable
/// `record` before OFFER is sent.
pub fn accept_key_set(
    record: Option<KeySetRecord>,
    local: KeySetRecord,
) -> Result<KeySetAcceptance, KeySetError> {
    let Some(record) = record else {
        return Ok(KeySetAcceptance::Initialized);
    };
    if local.generation < record.generation {
        return Err(KeySetError::Rollback);
    }
    if local.generation == record.generation {
        return if local.hash == record.hash {
            Ok(KeySetAcceptance::Same)
        } else {
            Err(KeySetError::Equivocation)
        };
    }
    let next = record
        .generation
        .checked_add(1)
        .ok_or(KeySetError::Exhausted)?;
    if local.generation != next {
        return Err(KeySetError::Gap);
    }
    Ok(KeySetAcceptance::Successor)
}

/// Checks that a peer tuple's key set equals the local one; a differing
/// set is a tuple mismatch on the link and a local configuration fault.
pub fn check_peer_key_set(local: &EcapTuple, peer: &EcapTuple) -> Result<(), KeySetError> {
    if local.key_set_generation != peer.key_set_generation
        || local.key_set_hash != peer.key_set_hash
    {
        return Err(KeySetError::LocalMismatch);
    }
    Ok(())
}

/// Maps a violation to the one line the link sends before closing.
#[must_use]
pub fn violation_line(prefix: &str) -> String {
    format!(
        ":{prefix} {}\r\n",
        crate::federation::frames::PROFILE_MISMATCH_LINE
    )
}

impl From<EcapViolation> for E2eeError {
    fn from(_: EcapViolation) -> Self {
        Self::ProfileMismatch
    }
}

#[cfg(test)]
#[path = "../tests/ecap.rs"]
mod tests;

#[cfg(test)]
mod display_tests {
    use super::KeySetError;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            KeySetError::Rollback,
            KeySetError::Gap,
            KeySetError::Equivocation,
            KeySetError::Exhausted,
            KeySetError::LocalMismatch,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }
}
