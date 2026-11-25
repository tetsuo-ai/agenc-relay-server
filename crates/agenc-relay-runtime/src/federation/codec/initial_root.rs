//! Explicit version dispatch for the two enhanced account carriers and their durable replay.
#![forbid(unsafe_code)]

use super::results::ResultArm;
use agenc_relay_federation_wire::{
    CanonicalEncode, CodecError, DecodeBudget, FederationProfile, InitialRootOperation,
    InitialRootRequest, InitialRootResult, RequestHeader, ResultHeader, SchemaObject,
    decode_result_arm, result_kind_permitted,
};
use agenc_relay_types::FederationResultKind;

pub(crate) enum Request<'a> {
    Base(RequestHeader, SchemaObject),
    Enhanced(InitialRootRequest<'a>),
}
impl<'a> Request<'a> {
    pub(crate) fn read(
        profile: FederationProfile,
        bytes: &'a [u8],
        budget: &mut DecodeBudget,
    ) -> Result<Self, CodecError> {
        if bytes.starts_with(&2u16.to_be_bytes()) {
            Ok(Self::Enhanced(InitialRootRequest::decode(
                profile, bytes, budget,
            )?))
        } else {
            let object = SchemaObject::decode_exact("FederationRequest", bytes, budget)?;
            Ok(Self::Base(RequestHeader::from_object(&object)?, object))
        }
    }
    pub(crate) fn header(&self) -> RequestHeader {
        match self {
            Self::Base(header, _) => *header,
            Self::Enhanced(request) => request.layout,
        }
    }
    pub(crate) fn extension(&self) -> Option<InitialRootOperation> {
        match self {
            Self::Base(..) => None,
            Self::Enhanced(request) => Some(request.operation),
        }
    }
}

enum Index<'a> {
    Base(SchemaObject),
    Enhanced(InitialRootResult<'a>),
}

pub(crate) struct ResultObject<'a> {
    pub(crate) header: ResultHeader,
    index: Index<'a>,
    pub(crate) arm: ResultArm,
}
impl<'a> ResultObject<'a> {
    pub(crate) fn indexed_replies(&self) -> Result<&[SchemaObject], CodecError> {
        match &self.index {
            Index::Base(object) => agenc_relay_federation_wire::access::vector(object, "replies"),
            Index::Enhanced(result) => result.indexed_replies(),
        }
    }

    pub(crate) fn read(
        profile: FederationProfile,
        expected: Option<InitialRootOperation>,
        bytes: &'a [u8],
        budget: &mut DecodeBudget,
    ) -> Result<Self, CodecError> {
        if expected.is_none() {
            let object = SchemaObject::decode_exact("FederationResult", bytes, budget)?;
            let header = ResultHeader::from_object(&object)?;
            let arm =
                ResultArm::from_object(header.result_kind, &decode_result_arm(&object, budget)?)?;
            return Ok(Self {
                header,
                index: Index::Base(object),
                arm,
            });
        }
        let checked = InitialRootResult::decode(profile, bytes, budget)?;
        let arm = match checked.sealed {
            Some((actual, sealed)) if Some(actual) == expected => {
                ResultArm::InitialRoot(actual, sealed.into())
            }
            Some(_) => return Err(CodecError::CrossReference),
            None => {
                ResultArm::from_object(FederationResultKind::Failed, &checked.failed_arm(budget)?)?
            }
        };
        Ok(Self {
            header: checked.layout,
            index: Index::Enhanced(checked),
            arm,
        })
    }
}

pub(crate) fn encode_result(
    request: &RequestHeader,
    extension: Option<InitialRootOperation>,
    header: &ResultHeader,
    arm: &ResultArm,
    replies: Vec<SchemaObject>,
) -> Result<Vec<u8>, CodecError> {
    if let Some(expected) = extension {
        return match arm {
            ResultArm::InitialRoot(actual, sealed) if *actual == expected && replies.is_empty() => {
                InitialRootResult::encode_sealed(
                    FederationProfile::InitialRoot,
                    header,
                    expected,
                    sealed,
                )
            }
            ResultArm::Failed { .. } => InitialRootResult::encode_failed(
                FederationProfile::InitialRoot,
                header,
                &arm.to_object()?,
                replies,
            ),
            _ => Err(CodecError::CrossReference),
        };
    }
    if !result_kind_permitted(request.opcode, arm.kind()) {
        return Err(CodecError::CrossReference);
    }
    Ok(header
        .build(&arm.to_object()?, replies)?
        .encode_canonical()?
        .as_slice()
        .to_vec())
}

/// The application service must release the exact protected envelope that was committed.
pub(crate) fn released_response(
    operation: InitialRootOperation,
    committed: &[u8],
    arm: &ResultArm,
) -> bool {
    let ResultArm::InitialRoot(actual, released) = arm else {
        return false;
    };
    if *actual != operation {
        return false;
    }
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    InitialRootResult::decode(FederationProfile::InitialRoot, committed, &mut budget)
        .is_ok_and(|v| v.sealed == Some((operation, released.as_ref())))
}
