//! V2 uses the exact Appendix B field widths. Validate those fields using their original
//! schemas on an isolated copy with the v1 discriminators. Only the original immutable
//! request/response is handed to the account service or included in a federation digest.
#![forbid(unsafe_code)]

use agenc_relay_types::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountServiceMessageKind,
    AccountServiceResponseKind, BASE_OBJECT_BYTES, FederationOpcode, FederationResultKind,
    SessionId,
};
use zeroize::Zeroizing;

use crate::{
    CanonicalEncode, CodecError, DecodeBudget, FederationProfile, ReplayKey, RequestHeader,
    ResultHeader, SchemaObject, WireValue, access,
};

// profile, network, origin replay tuple and federation request ID precede the opcode.
const REQUEST_KIND: usize = 2 + 32 + ReplayKey::BYTES + 16;
const REQUEST_ARM: usize = REQUEST_KIND + 2 + 3;
// The request hash and the required empty completion ID precede the result kind.
const COMPLETION_LENGTH: usize = REQUEST_KIND + 32;
const RESULT_KIND: usize = COMPLETION_LENGTH + 1;
const RESULT_ARM: usize = RESULT_KIND + 2 + 3;
// Profile, network, HPKE key and private request ID precede the signed HPKE kind.
const HPKE_KIND: usize = 2 + 32 + 32 + 16;
const V1: u16 = 1;
const V2: u16 = 2;

/// A federation operation exclusively available on an authenticated initial-root profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialRootOperation {
    /// Guarded preregistration START, completed by the unchanged creation FINISH.
    ClaimedCreateStart,
    /// Registered private read or choose.
    Claim,
}

impl InitialRootOperation {
    /// The frozen v1 header layout reused by this operation. This identifies structural fields only.
    #[must_use]
    pub const fn base_layout(self) -> FederationOpcode {
        match self {
            Self::ClaimedCreateStart => FederationOpcode::AccountCreateStart,
            Self::Claim => FederationOpcode::CredentialChangeFinish,
        }
    }
    const fn wire(self) -> u16 {
        match self {
            Self::ClaimedCreateStart => 27,
            Self::Claim => 28,
        }
    }
    const fn hpke(self) -> u16 {
        match self {
            Self::ClaimedCreateStart => 7,
            Self::Claim => 8,
        }
    }
    const fn base_hpke(self) -> u16 {
        match self {
            Self::ClaimedCreateStart => AccountServiceMessageKind::AccountCreateStart.wire_value(),
            Self::Claim => AccountServiceMessageKind::CredentialChangeFinish.wire_value(),
        }
    }
    const fn result(self) -> u16 {
        match self {
            Self::ClaimedCreateStart => FederationResultKind::AuthChallenge.wire_value(),
            Self::Claim => 11,
        }
    }
    const fn session_width(self) -> usize {
        match self {
            Self::ClaimedCreateStart => 0,
            Self::Claim => 16,
        }
    }
}

fn read_tag(bytes: &[u8], offset: usize) -> Result<u16, CodecError> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..)
            .and_then(|tail| tail.first_chunk::<2>())
            .copied()
            .ok_or(CodecError::UnexpectedEof)?,
    ))
}
fn replace_tag(
    bytes: &mut [u8],
    offset: usize,
    expected: u16,
    next: u16,
) -> Result<(), CodecError> {
    let slot = bytes
        .get_mut(offset..)
        .and_then(|tail| tail.first_chunk_mut::<2>())
        .ok_or(CodecError::UnexpectedEof)?;
    if u16::from_be_bytes(*slot) != expected {
        return Err(CodecError::UnknownDiscriminant);
    }
    slot.copy_from_slice(&next.to_be_bytes());
    Ok(())
}
fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let mut copy = Zeroizing::new(Vec::new());
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
fn check_profile(profile: FederationProfile, bytes: &[u8]) -> Result<(), CodecError> {
    if !profile.supports_initial_root() || read_tag(bytes, 0)? != V2 {
        return Err(CodecError::CrossReference);
    }
    Ok(())
}
fn outer_copy(bytes: &[u8], budget: &mut DecodeBudget) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    if bytes.len() > BASE_OBJECT_BYTES as usize {
        return Err(CodecError::LengthAboveMaximum);
    }
    budget.claim_bytes(bytes.len())?;
    copy_bytes(bytes)
}
fn hpke_for_layout(
    bytes: &[u8],
    size: u64,
    kind: InitialRootOperation,
    shape: u16,
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    if bytes.len() != size as usize {
        return Err(CodecError::TypeMismatch);
    }
    let mut copy = copy_bytes(bytes)?;
    replace_tag(&mut copy, 0, V2, V1)?;
    replace_tag(&mut copy, HPKE_KIND, kind.hpke(), shape)?;
    Ok(copy)
}
fn restore_hpke(output: &mut [u8], start: usize, hpke: &[u8]) -> Result<(), CodecError> {
    output
        .get_mut(start..)
        .and_then(|tail| tail.get_mut(..hpke.len()))
        .ok_or(CodecError::UnexpectedEof)?
        .copy_from_slice(hpke);
    Ok(())
}

/// Canonically checked FREQUEST fields, retaining the original borrowed sealed envelope.
pub struct InitialRootRequest<'a> {
    /// The exact selected optional operation.
    pub operation: InitialRootOperation,
    /// Common header fields, with `opcode` set only to the Appendix B field layout.
    pub layout: RequestHeader,
    /// The registered session is present for a claim and absent for creation.
    pub session: Option<SessionId>,
    /// Original HPKE bytes, including their profile and operation tag.
    pub envelope: &'a [u8],
}

impl<'a> InitialRootRequest<'a> {
    /// Encodes the agreed v2 operation without changing any HPKE byte.
    pub fn encode(&self, profile: FederationProfile) -> Result<Vec<u8>, CodecError> {
        if !profile.supports_initial_root()
            || self.layout.opcode != self.operation.base_layout()
            || self.session.is_some() != (self.operation == InitialRootOperation::Claim)
        {
            return Err(CodecError::CrossReference);
        }
        let hpke = hpke_for_layout(
            self.envelope,
            ACCOUNT_SERVICE_ENVELOPE_BYTES,
            self.operation,
            self.operation.base_hpke(),
        )?;
        let mut budget = DecodeBudget::new(32_768, 128);
        let envelope = SchemaObject::decode_exact("AccountServiceEnvelope", &hpke, &mut budget)?;
        let mut fields = Vec::with_capacity(1 + usize::from(self.session.is_some()));
        if let Some(session) = self.session {
            fields.push(access::opaque(session.as_bytes())?);
        }
        fields.push(WireValue::Structure(envelope));
        let arm = SchemaObject::new(crate::operation_schema_name(self.layout.opcode), fields)?;
        let mut bytes = self
            .layout
            .build(&arm)?
            .encode_canonical()?
            .as_slice()
            .to_vec();
        replace_tag(&mut bytes, 0, V1, V2)?;
        replace_tag(
            &mut bytes,
            REQUEST_KIND,
            self.layout.opcode.wire_value(),
            self.operation.wire(),
        )?;
        restore_hpke(
            &mut bytes,
            REQUEST_ARM + self.operation.session_width(),
            self.envelope,
        )?;
        Ok(bytes)
    }

    /// Checks the profile and fixed widths before allocating, then applies all shared field rules.
    pub fn decode(
        profile: FederationProfile,
        bytes: &'a [u8],
        budget: &mut DecodeBudget,
    ) -> Result<Self, CodecError> {
        check_profile(profile, bytes)?;
        let operation = match read_tag(bytes, REQUEST_KIND)? {
            27 => InitialRootOperation::ClaimedCreateStart,
            28 => InitialRootOperation::Claim,
            _ => return Err(CodecError::UnknownDiscriminant),
        };
        let offset = REQUEST_ARM + operation.session_width();
        let envelope = bytes.get(offset..).ok_or(CodecError::UnexpectedEof)?;
        if envelope.len() != ACCOUNT_SERVICE_ENVELOPE_BYTES as usize {
            return Err(CodecError::TypeMismatch);
        }
        let mut normalized = outer_copy(bytes, budget)?;
        replace_tag(&mut normalized, 0, V2, V1)?;
        replace_tag(
            &mut normalized,
            REQUEST_KIND,
            operation.wire(),
            operation.base_layout().wire_value(),
        )?;
        replace_tag(&mut normalized, offset, V2, V1)?;
        replace_tag(
            &mut normalized,
            offset + HPKE_KIND,
            operation.hpke(),
            operation.base_hpke(),
        )?;
        let object = SchemaObject::decode_exact("FederationRequest", &normalized, budget)?;
        let layout = RequestHeader::from_object(&object)?;
        let session = if operation == InitialRootOperation::Claim {
            Some(SessionId::from_bytes(
                *bytes
                    .get(REQUEST_ARM..)
                    .and_then(|tail| tail.first_chunk::<16>())
                    .ok_or(CodecError::UnexpectedEof)?,
            ))
        } else {
            None
        };
        Ok(Self {
            operation,
            layout,
            session,
            envelope,
        })
    }
}

/// A v2 result. Every protected disposition is carried as a sealed fixed-width response.
/// Pre-open failures keep the Appendix B failed arm and any ordinary indexed error replies.
pub struct InitialRootResult<'a> {
    /// Header naming the exact request and hash; both positive cases share the challenge field layout.
    pub layout: ResultHeader,
    /// Original sealed payload plus its actual operation, absent only for a pre-open failure.
    pub sealed: Option<(InitialRootOperation, &'a [u8])>,
    object: SchemaObject,
}

impl<'a> InitialRootResult<'a> {
    /// Returns only the ordinary indexed replies carried by this checked result.
    pub fn indexed_replies(&self) -> Result<&[SchemaObject], CodecError> {
        access::vector(&self.object, "replies")
    }

    /// Returns the canonical failure fields only for a pre-open failure.
    pub fn failed_arm(&self, budget: &mut DecodeBudget) -> Result<SchemaObject, CodecError> {
        if self.sealed.is_some() {
            return Err(CodecError::CrossReference);
        }
        crate::decode_result_arm(&self.object, budget)
    }

    /// Encodes one committed sealed reply. A state reply has no indexed replies and no completion event.
    pub fn encode_sealed(
        profile: FederationProfile,
        header: &ResultHeader,
        operation: InitialRootOperation,
        response: &[u8],
    ) -> Result<Vec<u8>, CodecError> {
        if !profile.supports_initial_root()
            || header.result_kind != FederationResultKind::AuthChallenge
            || header.completion_event_id.is_some()
        {
            return Err(CodecError::CrossReference);
        }
        let hpke = hpke_for_layout(
            response,
            ACCOUNT_SERVICE_RESPONSE_BYTES,
            operation,
            AccountServiceResponseKind::AccountCreateChallenge.wire_value(),
        )?;
        let mut budget = DecodeBudget::new(32_768, 128);
        let response_shape =
            SchemaObject::decode_exact("AccountServiceResponse", &hpke, &mut budget)?;
        let arm = SchemaObject::new(
            "result.auth_challenge",
            vec![WireValue::Structure(response_shape)],
        )?;
        let mut bytes = header
            .build(&arm, Vec::new())?
            .encode_canonical()?
            .as_slice()
            .to_vec();
        replace_tag(&mut bytes, 0, V1, V2)?;
        replace_tag(
            &mut bytes,
            RESULT_KIND,
            FederationResultKind::AuthChallenge.wire_value(),
            operation.result(),
        )?;
        restore_hpke(&mut bytes, RESULT_ARM, response)?;
        Ok(bytes)
    }

    /// Encodes the original validated pre-open error arm and permitted indexed replies under v2.
    pub fn encode_failed(
        profile: FederationProfile,
        header: &ResultHeader,
        arm: &SchemaObject,
        replies: Vec<SchemaObject>,
    ) -> Result<Vec<u8>, CodecError> {
        if !profile.supports_initial_root()
            || header.result_kind != FederationResultKind::Failed
            || header.completion_event_id.is_some()
        {
            return Err(CodecError::CrossReference);
        }
        let mut bytes = header
            .build(arm, replies)?
            .encode_canonical()?
            .as_slice()
            .to_vec();
        replace_tag(&mut bytes, 0, V1, V2)?;
        Ok(bytes)
    }

    /// Parses only a valid v2 outcome with exact optional kind, nested HPKE header and shared result grammar.
    pub fn decode(
        profile: FederationProfile,
        bytes: &'a [u8],
        budget: &mut DecodeBudget,
    ) -> Result<Self, CodecError> {
        check_profile(profile, bytes)?;
        if bytes.get(COMPLETION_LENGTH) != Some(&0) {
            return Err(CodecError::CrossReference);
        }
        let selected = match read_tag(bytes, RESULT_KIND)? {
            1 => None,
            4 => Some(InitialRootOperation::ClaimedCreateStart),
            11 => Some(InitialRootOperation::Claim),
            _ => return Err(CodecError::UnknownDiscriminant),
        };
        if selected == Some(InitialRootOperation::Claim)
            && bytes.len() != RESULT_ARM + ACCOUNT_SERVICE_RESPONSE_BYTES as usize + 2
        {
            return Err(CodecError::TypeMismatch);
        }
        let mut normalized = outer_copy(bytes, budget)?;
        replace_tag(&mut normalized, 0, V2, V1)?;
        let sealed = if let Some(operation) = selected {
            let response = bytes
                .get(RESULT_ARM..)
                .and_then(|tail| tail.get(..ACCOUNT_SERVICE_RESPONSE_BYTES as usize))
                .ok_or(CodecError::UnexpectedEof)?;
            replace_tag(
                &mut normalized,
                RESULT_KIND,
                operation.result(),
                FederationResultKind::AuthChallenge.wire_value(),
            )?;
            replace_tag(&mut normalized, RESULT_ARM, V2, V1)?;
            replace_tag(
                &mut normalized,
                RESULT_ARM + HPKE_KIND,
                operation.hpke(),
                AccountServiceResponseKind::AccountCreateChallenge.wire_value(),
            )?;
            Some((operation, response))
        } else {
            None
        };
        let object = SchemaObject::decode_exact("FederationResult", &normalized, budget)?;
        if selected == Some(InitialRootOperation::Claim)
            && !access::vector(&object, "replies")?.is_empty()
        {
            return Err(CodecError::CrossReference);
        }
        Ok(Self {
            layout: ResultHeader::from_object(&object)?,
            sealed,
            object,
        })
    }
}

#[cfg(test)]
mod tests;
