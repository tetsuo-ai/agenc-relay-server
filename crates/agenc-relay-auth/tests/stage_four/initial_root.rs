use agenc_relay_auth::client::{registration_finish, registration_start};
use agenc_relay_auth::{
    ACCOUNT_CREATION_TIMEOUT_TICKS, AccountCreationStartParameters, CreationAdmission,
    CreationFinish, CreationStart, CreationTransactionRecord, CreationTransactionRestartMetadata,
    GuardedCreationTransactionRecord, InitialRootServiceEnvelope, InitialRootServiceResponse,
    OpaqueProfile, OpaqueRegistrationRequest, begin_guarded_account_creation, claimed_creation,
    finish_account_creation, finish_registration, open_and_parse_response,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, InitialRootExchange, InitialRootSecret,
    LoginIndexKey, OsEntropy,
};
use agenc_relay_types::{NormalizedLogin, RequestId};

use super::{
    AccountServiceResponsePayload, FallibleOpaqueRng, TEST_NETWORK, TEST_RECOVERY_EPOCH,
    authenticated_creation_finish_with_token, operation_context,
};

type Result<T = ()> = core::result::Result<T, Box<dyn core::error::Error>>;

#[test]
fn only_the_exact_successful_guarded_registration_reserves_the_freshly_allocated_account() -> Result
{
    let private = AccountHpkePrivateKey::from_bytes([7; 32])?;
    let public = private.public_key()?;
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let lookup = LoginIndexKey::from_bytes([0x24; 32]);
    let secret = InitialRootSecret::generate()?;
    for (login_available, finish_id, finish_at, expected) in [
        (true, 34, 11, true),
        (false, 34, 11, false),
        (true, 33, 11, false),
        (true, 34, 10 + ACCOUNT_CREATION_TIMEOUT_TICKS, false),
    ] {
        let start_id = RequestId::from_bytes([33; 16]);
        let binding = AccountRequestBinding::new(
            TEST_NETWORK,
            TEST_RECOVERY_EPOCH,
            public.key_id(),
            start_id,
            InitialRootExchange::ClaimedCreateStart,
        );
        let mut entropy = FallibleOpaqueRng::new(OsEntropy);
        let started = registration_start(&mut entropy, "separate protected test password")?;
        let request = CreationStart {
            network_id: TEST_NETWORK,
            login: NormalizedLogin::prepare("alice")?,
            registration_request: OpaqueRegistrationRequest::from_bytes(started.request)?,
            invitation: None,
        };
        let (sealed, client) = claimed_creation::seal_start(public, binding, &request, &secret)?;
        let forwarded = InitialRootServiceEnvelope::parse(*sealed.as_bytes())?;
        let opened =
            claimed_creation::open_start(&private, TEST_NETWORK, TEST_RECOVERY_EPOCH, &forwarded)?;
        assert!(opened.request().login.as_str() == request.login.as_str());
        let awaiting = begin_guarded_account_creation(
            &profile,
            &lookup,
            AccountCreationStartParameters {
                context: operation_context(10)?,
                request: opened,
                admission: CreationAdmission::Open,
                login_is_available: login_available,
                invitation_is_available: true,
            },
            0,
        )?;
        assert_eq!(awaiting.next_response_count(), 1);
        assert_eq!(awaiting.reserved_login().is_some(), login_available);
        assert!(awaiting.reserved_invitation().is_none());
        let bytes = awaiting.record().expose_for_persistence();
        assert_eq!(bytes.len(), 393);
        assert!(CreationTransactionRecord::parse(bytes).is_err());
        let cleanup = CreationTransactionRestartMetadata::parse(bytes)?;
        assert_eq!(cleanup.transaction_id(), awaiting.transaction_id());
        assert_eq!(
            cleanup.reservation_login_digest().is_some(),
            login_available
        );
        let durable = GuardedCreationTransactionRecord::parse(bytes)?;
        let delivered =
            InitialRootServiceResponse::parse(*awaiting.response_for_commit().as_bytes())?;
        let mut transaction = awaiting.into_committed(&forwarded, &delivered, &durable, 1)?;
        let verified = client.open(&delivered)?;
        assert!(verified.binding() == binding);
        let (transaction_id, credential, challenge) = verified.into_registration();
        let upload = registration_finish(
            &mut entropy,
            started.state,
            "separate protected test password",
            challenge.expose_for_account_response(),
            &TEST_NETWORK,
            &credential,
        )?;
        let (finish, client_finish) = authenticated_creation_finish_with_token(
            finish_id,
            CreationFinish {
                network_id: TEST_NETWORK,
                transaction_id,
                registration_record: finish_registration(*upload.record)?,
            },
        )?;
        let finished =
            finish_account_creation(&mut transaction, operation_context(finish_at)?, finish)?
                .seal(1)?;
        let response =
            open_and_parse_response(client_finish, finished.response_intent().response())?;
        let AccountServiceResponsePayload::CreationCompletion(receipt) = response else {
            return Err("wrong completion".into());
        };
        if expected {
            let intent = finished.result()?;
            let claim = intent
                .initial_root_claim()
                .ok_or("guarded creation lost its reservation")?;
            assert!(claim.binding() == binding && claim.account() == intent.account_id());
            assert_eq!(receipt.account_id(), Some(intent.account_id()));
            let owner = secret
                .precommit(TEST_NETWORK, TEST_RECOVERY_EPOCH, start_id)
                .bind(
                    TEST_NETWORK,
                    TEST_RECOVERY_EPOCH,
                    intent.account_id(),
                    start_id,
                );
            assert!(owner.matches(claim.owner()));
        } else {
            assert!(finished.result().is_err());
            assert_eq!(receipt.account_id(), None);
        }
    }
    Ok(())
}

#[test]
fn guarded_start_releases_only_its_complete_durable_admission() -> Result {
    let private = AccountHpkePrivateKey::from_bytes([7; 32])?;
    let public = private.public_key()?;
    let profile = OpaqueProfile::generate(TEST_NETWORK)?;
    let lookup = LoginIndexKey::from_bytes([0x58; 32]);
    let secret = InitialRootSecret::generate()?;
    let request_id = RequestId::from_bytes([0x75; 16]);
    let binding = AccountRequestBinding::new(
        TEST_NETWORK,
        TEST_RECOVERY_EPOCH,
        public.key_id(),
        request_id,
        InitialRootExchange::ClaimedCreateStart,
    );
    let registration = registration_start(
        &mut FallibleOpaqueRng::new(OsEntropy),
        "guarded registration admission control",
    )?;
    let request = CreationStart {
        network_id: TEST_NETWORK,
        login: NormalizedLogin::prepare("alice")?,
        registration_request: OpaqueRegistrationRequest::from_bytes(registration.request)?,
        invitation: None,
    };
    let (original, _) = claimed_creation::seal_start(public, binding, &request, &secret)?;
    let (other_wire, _) = claimed_creation::seal_start(public, binding, &request, &secret)?;
    let prepare = || -> Result<agenc_relay_auth::GuardedAccountStart> {
        Ok(begin_guarded_account_creation(
            &profile,
            &lookup,
            AccountCreationStartParameters {
                context: operation_context(10)?,
                request: claimed_creation::open_start(
                    &private,
                    TEST_NETWORK,
                    TEST_RECOVERY_EPOCH,
                    &original,
                )?,
                admission: CreationAdmission::Open,
                login_is_available: true,
                invitation_is_available: true,
            },
            3,
        )?)
    };
    let other = prepare()?;
    enum Mismatch {
        Request,
        Reply,
        Record,
        Counter,
    }
    for mismatch in [
        Mismatch::Request,
        Mismatch::Reply,
        Mismatch::Record,
        Mismatch::Counter,
    ] {
        let pending = prepare()?;
        let saved_request = match mismatch {
            Mismatch::Request => &other_wire,
            _ => &original,
        };
        let saved_response = InitialRootServiceResponse::parse(
            *match mismatch {
                Mismatch::Reply => other.response_for_commit(),
                _ => pending.response_for_commit(),
            }
            .as_bytes(),
        )?;
        let saved_record = GuardedCreationTransactionRecord::parse(
            match mismatch {
                Mismatch::Record => other.record(),
                _ => pending.record(),
            }
            .expose_for_persistence(),
        )?;
        let count = match mismatch {
            Mismatch::Counter => 3,
            _ => 5,
        };
        assert!(
            pending
                .into_committed(saved_request, &saved_response, &saved_record, count)
                .is_err()
        );
    }

    let saved = other.record().expose_for_persistence();
    let tag = saved
        .windows(16)
        .position(|bytes| bytes == request_id.as_bytes())
        .ok_or("missing guarded START request ID")?
        + request_id.as_bytes().len();
    let mut shortened = saved.to_vec();
    shortened.pop();
    let mut extended = saved.to_vec();
    extended.push(0);
    for invalid in [&shortened, &extended] {
        assert!(CreationTransactionRestartMetadata::parse(invalid).is_err());
    }
    for (offset, replaced) in [(0, 1_u16), (0, 3), (2, 2), (tag, 8)] {
        let mut invalid = saved.to_vec();
        let field = invalid
            .get_mut(offset..offset + 2)
            .ok_or("missing storage field")?;
        field.copy_from_slice(&replaced.to_be_bytes());
        assert!(CreationTransactionRestartMetadata::parse(&invalid).is_err());
    }
    Ok(())
}
