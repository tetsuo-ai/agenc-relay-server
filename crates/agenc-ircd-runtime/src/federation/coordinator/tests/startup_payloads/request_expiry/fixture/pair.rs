//! Canonical request and result envelopes for deterministic retained histories.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::request::Decoded;

pub(super) struct Pair {
    pub(super) decoded: Decoded,
    pub(super) key: ReplayKey,
    pub(super) result: Vec<u8>,
    pub(super) result_id: [u8; 32],
}
pub(super) fn create(
    core: &StateCoreFixture,
    executor: &CompanionCoordinator,
    sequence: u64,
) -> TestResult<Pair> {
    let home = *core.identity.server_id.as_bytes();
    let incarnation = *core.identity.server_incarnation.as_bytes();
    let account = agenc_ircd_types::AccountId::from_random(
        agenc_ircd_types::AccountRandomId::from_bytes([30; 16]),
    )
    .to_text();
    let mut parameters = vec![24];
    parameters.extend_from_slice(account.as_bytes());
    let mut request_id = [56; 16];
    request_id[8..].copy_from_slice(&sequence.to_be_bytes());
    let request = IrcFederationRequest {
        profile_version: 1,
        network_id: *core.identity.network_id.as_bytes(),
        home_server_id: home,
        server_incarnation: incarnation,
        origin_id: [55; 16],
        origin_generation: 0,
        operation_sequence: sequence,
        request_id,
        opcode: IrcFederationOpcode::FetchIdentity,
        encoded_parameters: Opaque::new(parameters)?,
        payload_object_id: Opaque::new(Vec::new())?,
    };
    let request_bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationRequest, request.encode()?)?.encode()?;
    let complete = CompleteRequest {
        correlation: Correlation {
            peer_server_id: home,
            server_incarnation: incarnation,
            origin_id: request.origin_id,
            origin_generation: request.origin_generation,
            operation_sequence: request.operation_sequence,
            request_id: request.request_id,
        },
        request: request_bytes,
        payload: None,
    };
    let decoded = request::decode(executor, &complete).map_err(|e| format!("request: {e:?}"))?;
    let outcome = Outcome::scalar(ResultBody::Empty(EmptyKind::Identity));
    let result = request::encode_result(executor, home, &decoded, &outcome, 1, None)
        .map_err(|e| format!("result: {e:?}"))?;
    let result_id = *ObjectId::compute(&result).as_bytes();
    let key = ReplayKey {
        home_server_id: home,
        server_incarnation: incarnation,
        origin_id: decoded.request.origin_id,
        origin_generation: 0,
        operation_sequence: sequence,
    };
    Ok(Pair {
        decoded,
        key,
        result,
        result_id,
    })
}
