use agenc_relay_crypto::Sha256Stream;
use agenc_relay_types::AccountRandomId;

use super::*;

type Result<T = ()> = core::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    private: AccountHpkePrivateKey,
    secret: InitialRootSecret,
    owner: InitialRootClaimOwner,
    network: NetworkId,
    epoch: RecoveryEpoch,
    account: AccountId,
    start: RequestId,
}

impl Fixture {
    fn new() -> Result<Self> {
        let network = NetworkId::from_bytes([1; 32]);
        let epoch = RecoveryEpoch::from_bytes([2; 16]);
        let start = RequestId::from_bytes([3; 16]);
        let secret = InitialRootSecret::from_protected_bytes(Zeroizing::new([4; 32]));
        let account = AccountId::from_random(AccountRandomId::from_bytes([5; 16]));
        let owner = secret
            .precommit(network, epoch, start)
            .bind(network, epoch, account, start);
        Ok(Self {
            private: AccountHpkePrivateKey::generate()?,
            secret,
            owner,
            network,
            epoch,
            account,
            start,
        })
    }

    fn issue(
        &self,
        epoch: RecoveryEpoch,
        action: ClaimAction,
    ) -> Result<(InitialRootServiceEnvelope, ClaimOpenToken)> {
        let public = self.private.public_key()?;
        let binding = AccountRequestBinding::new(
            self.network,
            epoch,
            public.key_id(),
            RequestId::from_bytes([6; 16]),
            InitialRootExchange::Claim,
        );
        Ok(seal_claim(
            public,
            binding,
            self.account,
            self.start,
            &self.secret,
            action,
        )?)
    }

    fn record(&self, state: ClaimState) -> ClaimRecord<'_> {
        ClaimRecord {
            network: self.network,
            account: self.account,
            creation_epoch: self.epoch,
            creation_request: self.start,
            owner: &self.owner,
            state,
        }
    }

    fn exchange(
        &self,
        epoch: RecoveryEpoch,
        action: ClaimAction,
        registered: Option<AccountId>,
        row: Option<&ClaimRecord<'_>>,
    ) -> Result<(Option<ClaimState>, Option<[u8; 32]>)> {
        let (sealed, client) = self.issue(epoch, action)?;
        let request = InitialRootServiceEnvelope::parse(*sealed.as_bytes())?;
        let incoming = open_claim(&self.private, self.network, epoch, &request)?;
        let prepared = incoming.prepare(registered, row, 40)?;
        let choice = prepared.new_choice();
        assert_eq!(prepared.next_response_count(), 41);
        let response = InitialRootServiceResponse::parse(*prepared.into_committed(41)?.as_bytes())?;
        let verified = client.open(&response)?;
        assert!(verified.account() == self.account && verified.creation_request() == self.start);
        assert!(verified.action() == action && verified.binding().recovery_epoch() == epoch);
        Ok((verified.state(), choice))
    }
}

#[test]
fn sealed_decisions_are_idempotent_and_old_epochs_can_only_read_an_existing_choice() -> Result {
    let f = Fixture::new()?;
    let root = [7; 32];
    let chosen = ClaimState::Chosen(root);
    let published = ClaimState::Published {
        fingerprint: root,
        object_id: [8; 32],
    };
    let reserved = ClaimState::Reserved;
    let new_epoch = RecoveryEpoch::from_bytes([0x23; 16]);
    for (epoch, prior, action, expected, mutation) in [
        (f.epoch, reserved, ClaimAction::Read, Some(reserved), None),
        (
            f.epoch,
            reserved,
            ClaimAction::Choose(root),
            Some(chosen),
            Some(root),
        ),
        (
            f.epoch,
            chosen,
            ClaimAction::Choose(root),
            Some(chosen),
            None,
        ),
        (
            f.epoch,
            published,
            ClaimAction::Choose(root),
            Some(published),
            None,
        ),
        (f.epoch, chosen, ClaimAction::Choose([9; 32]), None, None),
        (f.epoch, published, ClaimAction::Choose([9; 32]), None, None),
        (new_epoch, reserved, ClaimAction::Read, None, None),
        (new_epoch, reserved, ClaimAction::Choose(root), None, None),
        (new_epoch, chosen, ClaimAction::Choose(root), None, None),
        (new_epoch, published, ClaimAction::Choose(root), None, None),
        (new_epoch, chosen, ClaimAction::Read, Some(chosen), None),
        (
            new_epoch,
            published,
            ClaimAction::Read,
            Some(published),
            None,
        ),
    ] {
        let observed = f.exchange(epoch, action, Some(f.account), Some(&f.record(prior)))?;
        assert!(observed == (expected, mutation));
    }
    Ok(())
}

#[test]
fn private_denials_cover_unknown_owner_session_and_missing_guarded_row() -> Result {
    let f = Fixture::new()?;
    let wrong = AccountId::from_random(AccountRandomId::from_bytes([0x99; 16]));
    let valid = f.record(ClaimState::Reserved);
    let other_owner = InitialRootClaimOwner::from_protected_bytes([0x55; 32]);
    let altered_owner = ClaimRecord {
        owner: &other_owner,
        ..f.record(ClaimState::Reserved)
    };
    let altered_account = ClaimRecord {
        account: wrong,
        ..f.record(ClaimState::Reserved)
    };
    let altered_start = ClaimRecord {
        creation_request: RequestId::from_bytes([0; 16]),
        ..f.record(ClaimState::Reserved)
    };
    let altered_network = ClaimRecord {
        network: NetworkId::from_bytes([0; 32]),
        ..f.record(ClaimState::Reserved)
    };
    for (registered, row) in [
        (None, Some(&valid)),
        (Some(wrong), Some(&valid)),
        (Some(f.account), None),
        (Some(f.account), Some(&altered_owner)),
        (Some(f.account), Some(&altered_account)),
        (Some(f.account), Some(&altered_start)),
        (Some(f.account), Some(&altered_network)),
    ] {
        assert!(
            f.exchange(f.epoch, ClaimAction::Choose([7; 32]), registered, row)? == (None, None)
        );
    }
    Ok(())
}

fn vector_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut digest = Sha256Stream::new();
    digest.update(bytes);
    let mut hex = String::new();
    for byte in digest.finish().as_bytes() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[test]
fn a_sealed_unrelated_positive_result_and_noncanonical_states_cannot_confirm_a_choice() -> Result {
    let f = Fixture::new()?;
    for (state, account, start) in [
        (ClaimState::Reserved, f.account, f.start),
        (ClaimState::Chosen([9; 32]), f.account, f.start),
        (
            ClaimState::Published {
                fingerprint: [9; 32],
                object_id: [8; 32],
            },
            f.account,
            f.start,
        ),
        (
            ClaimState::Chosen([7; 32]),
            AccountId::from_random(AccountRandomId::from_bytes([9; 16])),
            f.start,
        ),
        (
            ClaimState::Chosen([7; 32]),
            f.account,
            RequestId::from_bytes([9; 16]),
        ),
    ] {
        let (sealed, client) = f.issue(f.epoch, ClaimAction::Choose([7; 32]))?;
        let (_, token) = sealed.open(&f.private, f.epoch, f.network, InitialRootExchange::Claim)?;
        let fields = encode_state(account, start, Some(state))?;
        let wrapped = padding::encode(fields.as_ref(), STATE_BYTES..=STATE_BYTES)?;
        let response = InitialRootServiceResponse::from_sealed(token.seal_response(
            40,
            InitialRootExchange::Claim,
            &wrapped,
        )?)?;
        assert!(client.open(&response).is_err());
    }
    for tag in [1, 3, 5] {
        let (sealed, client) = f.issue(f.epoch, ClaimAction::Read)?;
        let (_, token) = sealed.open(&f.private, f.epoch, f.network, InitialRootExchange::Claim)?;
        let mut fields = encode_state(
            f.account,
            f.start,
            Some(ClaimState::Published {
                fingerprint: [7; 32],
                object_id: [8; 32],
            }),
        )?;
        let state_tag = fields.get_mut(2 + 24 + 16).ok_or("missing state tag")?;
        *state_tag = tag;
        let wrapped = padding::encode(fields.as_ref(), STATE_BYTES..=STATE_BYTES)?;
        let response = InitialRootServiceResponse::from_sealed(token.seal_response(
            40,
            InitialRootExchange::Claim,
            &wrapped,
        )?)?;
        assert!(client.open(&response).is_err());
    }
    Ok(())
}

#[test]
fn exact_private_wire_controls_and_previous_reply_or_early_release_are_refused() -> Result {
    let f = Fixture::new()?;
    let (sealed, original) = f.issue(f.epoch, ClaimAction::Read)?;
    assert!(super::super::AccountServiceEnvelope::parse(*sealed.as_bytes()).is_err());
    let (fields, _) = sealed.open(&f.private, f.epoch, f.network, InitialRootExchange::Claim)?;
    let fields = padding::decode(
        fields.expose_for_account_parser(),
        REQUEST_BYTES..=REQUEST_BYTES,
    )?;
    assert_eq!(
        vector_digest(fields),
        "42c1b3501ef9c26866e36c336a467207ff974cb93ab669634930213758838b4d"
    );
    let state = encode_state(f.account, f.start, Some(ClaimState::Reserved))?;
    assert_eq!(
        vector_digest(state.as_ref()),
        "95658aafa0ac3735af633e66b690a8b34a023736599e500150524925310b89ba"
    );
    let incoming = open_claim(&f.private, f.network, f.epoch, &sealed)?;
    let row = f.record(ClaimState::Reserved);
    let prepared = incoming.prepare(Some(f.account), Some(&row), 40)?;
    assert!(prepared.into_committed(40).is_err());
    let incoming = open_claim(&f.private, f.network, f.epoch, &sealed)?;
    let reply = incoming
        .prepare(Some(f.account), Some(&row), 40)?
        .into_committed(41)?;
    assert!(super::super::AccountServiceResponse::parse(*reply.as_bytes()).is_err());
    let (_, independent) = f.issue(f.epoch, ClaimAction::Read)?;
    assert!(independent.open(&reply).is_err());
    assert!(original.open(&reply)?.state() == Some(ClaimState::Reserved));
    Ok(())
}
