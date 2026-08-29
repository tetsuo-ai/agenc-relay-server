#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountServiceEnvelope,
    AccountServiceResponse, AuthError, open_and_parse_request, open_and_parse_response,
};
use agenc_ircd_crypto::{
    ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES, ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES,
    AccountHpkePrivateKey, AccountRequestBinding, open_account_request, seal_account_request,
};
use agenc_ircd_types::{
    AccountServiceMessageKind, AccountServiceResponseKind, NetworkId, RecoveryEpoch, RequestId,
};
use libfuzzer_sys::fuzz_target;

const NETWORK_ID: NetworkId = NetworkId::from_bytes([1_u8; 32]);
const RECOVERY_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([2_u8; 16]);
const REQUEST_ID: RequestId = RequestId::from_bytes([3_u8; 16]);
const REQUEST_KINDS: [AccountServiceMessageKind; 6] = [
    AccountServiceMessageKind::AccountCreateStart,
    AccountServiceMessageKind::AccountCreateFinish,
    AccountServiceMessageKind::OpaqueAuthStart,
    AccountServiceMessageKind::OpaqueAuthFinish,
    AccountServiceMessageKind::CredentialChangeStart,
    AccountServiceMessageKind::CredentialChangeFinish,
];

fn padded<const SIZE: usize>(input: &[u8]) -> [u8; SIZE] {
    let mut output = [0_u8; SIZE];
    let length = input.len().min(SIZE);
    if let (Some(source), Some(destination)) = (input.get(..length), output.get_mut(..length)) {
        destination.copy_from_slice(source);
    }
    output
}

fn response_kind(request_kind: AccountServiceMessageKind) -> AccountServiceResponseKind {
    match request_kind {
        AccountServiceMessageKind::AccountCreateStart => {
            AccountServiceResponseKind::AccountCreateChallenge
        }
        AccountServiceMessageKind::AccountCreateFinish => {
            AccountServiceResponseKind::AccountCreateComplete
        }
        AccountServiceMessageKind::OpaqueAuthStart => {
            AccountServiceResponseKind::OpaqueAuthChallenge
        }
        AccountServiceMessageKind::OpaqueAuthFinish => {
            AccountServiceResponseKind::OpaqueAuthComplete
        }
        AccountServiceMessageKind::CredentialChangeStart => {
            AccountServiceResponseKind::CredentialChangeChallenge
        }
        AccountServiceMessageKind::CredentialChangeFinish => {
            AccountServiceResponseKind::CredentialChangeComplete
        }
    }
}

fn fuzz_request_plaintext(input: &[u8], request_kind: AccountServiceMessageKind) {
    let Ok(private_key) = AccountHpkePrivateKey::from_bytes([7_u8; 32]) else {
        return;
    };
    let Ok(public_key) = private_key.public_key() else {
        return;
    };
    let binding = AccountRequestBinding::new(
        NETWORK_ID,
        RECOVERY_EPOCH,
        public_key.key_id(),
        REQUEST_ID,
        request_kind,
    );
    let plaintext = padded::<ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES>(input);
    let Ok((sealed, _response_token)) = seal_account_request(public_key, binding, &plaintext)
    else {
        return;
    };
    let Ok(envelope) = AccountServiceEnvelope::from_sealed(sealed) else {
        return;
    };
    let result = open_and_parse_request(
        &private_key,
        RECOVERY_EPOCH,
        NETWORK_ID,
        request_kind,
        &envelope,
    );
    // Production sealed this envelope under the same binding, so only the
    // inner plaintext syntax may reject it; a MAC failure is a codec defect.
    assert!(
        !matches!(result, Err(AuthError::AuthenticationFailed)),
        "production-sealed request failed authentication"
    );
}

fn fuzz_response_plaintext(input: &[u8], request_kind: AccountServiceMessageKind) {
    let Ok(private_key) = AccountHpkePrivateKey::from_bytes([7_u8; 32]) else {
        return;
    };
    let Ok(public_key) = private_key.public_key() else {
        return;
    };
    let binding = AccountRequestBinding::new(
        NETWORK_ID,
        RECOVERY_EPOCH,
        public_key.key_id(),
        REQUEST_ID,
        request_kind,
    );
    let request_plaintext = [0_u8; ACCOUNT_HPKE_REQUEST_PLAINTEXT_BYTES];
    let Ok((sealed_request, open_token)) =
        seal_account_request(public_key, binding, &request_plaintext)
    else {
        return;
    };
    let Ok((_opened_request, seal_token)) = open_account_request(
        &private_key,
        binding,
        sealed_request.encapsulated_key(),
        sealed_request.ciphertext(),
    ) else {
        return;
    };
    let plaintext = padded::<ACCOUNT_HPKE_RESPONSE_PLAINTEXT_BYTES>(input);
    let Ok(sealed_response) = seal_token.seal_response(0, response_kind(request_kind), &plaintext)
    else {
        return;
    };
    let Ok(response) = AccountServiceResponse::from_sealed(sealed_response) else {
        return;
    };
    let result = open_and_parse_response(open_token, &response);
    assert!(
        !matches!(result, Err(AuthError::AuthenticationFailed)),
        "production-sealed response failed authentication"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    match usize::from(selector) % 14 {
        0 => {
            let _result =
                AccountServiceEnvelope::parse(padded::<ACCOUNT_SERVICE_ENVELOPE_BYTES>(input));
        }
        1 => {
            let _result =
                AccountServiceResponse::parse(padded::<ACCOUNT_SERVICE_RESPONSE_BYTES>(input));
        }
        mode @ 2..=7 => fuzz_request_plaintext(input, REQUEST_KINDS[mode - 2]),
        mode => fuzz_response_plaintext(input, REQUEST_KINDS[mode - 8]),
    }
});
