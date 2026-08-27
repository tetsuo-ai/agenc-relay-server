#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_auth::{
    ACCOUNT_CREATION_INVITE_BYTES, AccountCreationInvite, OPAQUE_KE1_BYTES, OPAQUE_KE2_BYTES,
    OPAQUE_KE3_BYTES, OPAQUE_REGISTRATION_RECORD_BYTES, OPAQUE_REGISTRATION_REQUEST_BYTES,
    OPAQUE_REGISTRATION_RESPONSE_BYTES, OPAQUE_SERVER_LOGIN_STATE_BYTES, OpaqueKe1, OpaqueKe2,
    OpaqueKe3, OpaqueRegistrationRecord, OpaqueRegistrationRequest, OpaqueRegistrationResponse,
    OpaqueServerLoginState,
};
use agenc_ircd_crypto::{
    AccountHpkePublicKey, DatabaseBinding, Ed25519PublicKey, Ed25519Signature, SealedStorageRecord,
    SignatureDomain, StorageMasterKey, StorageNonce, StorageTable, derive_storage_record_key,
    open_storage_record, verify_canonical,
};
use agenc_ircd_types::{DatabaseId, NetworkId, ServerId, ServerIncarnation};
use libfuzzer_sys::fuzz_target;

fn padded<const SIZE: usize>(input: &[u8]) -> [u8; SIZE] {
    let mut output = [0_u8; SIZE];
    let length = input.len().min(SIZE);
    if let (Some(source), Some(destination)) = (input.get(..length), output.get_mut(..length)) {
        destination.copy_from_slice(source);
    }
    output
}

fn fuzz_signature(input: &[u8]) {
    let public_key = padded::<32>(input);
    let signature = padded::<64>(input.get(32..).unwrap_or_default());
    let content = input.get(96..).unwrap_or_default();
    let Ok(public_key) = Ed25519PublicKey::from_bytes(public_key) else {
        return;
    };
    let _result = verify_canonical(
        public_key,
        SignatureDomain::AccountCreationInvite,
        content,
        Ed25519Signature::from_bytes(signature),
    );
}

fn fuzz_sealed_record(input: &[u8]) {
    let Ok(ciphertext) = SealedStorageRecord::from_bytes(input.to_vec()) else {
        return;
    };
    let binding = DatabaseBinding::new(
        NetworkId::from_bytes([1_u8; 32]),
        ServerId::from_bytes([2_u8; 16]),
        ServerIncarnation::from_bytes([3_u8; 16]),
        DatabaseId::from_bytes([4_u8; 16]),
    );
    let Ok(table) = StorageTable::new(3) else {
        return;
    };
    let Ok(key) =
        derive_storage_record_key(&StorageMasterKey::from_bytes([5_u8; 32]), binding, table, 1)
    else {
        return;
    };
    let nonce = StorageNonce::from_reserved_bytes([6_u8; 24]);
    let _result = open_storage_record(&key, &nonce, 1, b"fuzz-record", &ciphertext);
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    match selector % 11 {
        0 => {
            let _result = OpaqueRegistrationRequest::from_bytes(padded::<
                OPAQUE_REGISTRATION_REQUEST_BYTES,
            >(input));
        }
        1 => {
            let _result = OpaqueRegistrationResponse::from_bytes(padded::<
                OPAQUE_REGISTRATION_RESPONSE_BYTES,
            >(input));
        }
        2 => {
            let _result = OpaqueRegistrationRecord::from_bytes(padded::<
                OPAQUE_REGISTRATION_RECORD_BYTES,
            >(input));
        }
        3 => {
            let _result = OpaqueKe1::from_bytes(padded::<OPAQUE_KE1_BYTES>(input));
        }
        4 => {
            let _result = OpaqueKe2::from_bytes(padded::<OPAQUE_KE2_BYTES>(input));
        }
        5 => {
            let _result = OpaqueKe3::from_bytes(padded::<OPAQUE_KE3_BYTES>(input));
        }
        6 => {
            let _result = OpaqueServerLoginState::from_persisted_bytes(padded::<
                OPAQUE_SERVER_LOGIN_STATE_BYTES,
            >(input));
        }
        7 => {
            let _result =
                AccountCreationInvite::parse(&padded::<ACCOUNT_CREATION_INVITE_BYTES>(input));
        }
        8 => fuzz_signature(input),
        9 => fuzz_sealed_record(input),
        _ => {
            let _result = AccountHpkePublicKey::from_bytes(padded::<32>(input));
        }
    }
});
