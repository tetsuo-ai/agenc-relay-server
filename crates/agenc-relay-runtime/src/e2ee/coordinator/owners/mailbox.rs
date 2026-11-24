//! Logical mailbox bytes follow their durable item owners, including at restart.
use super::{Account, BTreeMap, Code, Ledger, MailboxRow, StoredKey, prefix};
use agenc_relay_e2ee::limits::MAX_MAILBOX_BYTES_PER_ACCOUNT;
use agenc_relay_storage::e2ee_records::MailboxKind;

// Each offline delivery is charged in full even when several devices share one ciphertext.
// This leaves at least half of the coordinator's 256 MiB resident ceiling for other objects.
const MAX_QUEUED_APPLICATION_BYTES: u64 = 2 * MAX_MAILBOX_BYTES_PER_ACCOUNT;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Usage {
    accounts: BTreeMap<[u8; 32], u64>,
    application: u64,
}

fn deliveries(account: &Account) -> impl Iterator<Item = ([u8; 32], MailboxKind)> + '_ {
    account.owners.keys().filter_map(|owner| {
        if !owner.starts_with(prefix::MAILBOX) {
            return None;
        }
        let key = StoredKey::new(owner.clone()).ok()?;
        let item = MailboxRow::parse_item_key(&key).ok()?;
        Some((item.account_digest, item.kind))
    })
}

impl Usage {
    pub(super) fn install(&mut self, account: &Account) {
        for (target, kind) in deliveries(account) {
            let bytes = self.accounts.entry(target).or_default();
            *bytes = bytes.saturating_add(account.size);
            if kind == MailboxKind::Application {
                self.application = self.application.saturating_add(account.size);
            }
        }
    }

    pub(super) fn retire(&mut self, account: &Account) {
        for (target, kind) in deliveries(account) {
            if let Some(bytes) = self.accounts.get_mut(&target) {
                *bytes = bytes.saturating_sub(account.size);
                if *bytes == 0 {
                    self.accounts.remove(&target);
                }
            }
            if kind == MailboxKind::Application {
                self.application = self.application.saturating_sub(account.size);
            }
        }
    }
}

pub(super) fn check(
    ledger: &Ledger,
    changes: &BTreeMap<[u8; 32], Account>,
    account_limit: u64,
) -> Result<(), Code> {
    let mut accounts = BTreeMap::<[u8; 32], i128>::new();
    let mut application = 0_i128;
    for (id, next) in changes {
        for (account, sign) in ledger
            .account(id)
            .map(|a| (a, -1_i128))
            .into_iter()
            .chain([(next, 1)])
        {
            for (owner, kind) in deliveries(account) {
                let bytes = sign * i128::from(account.size);
                *accounts.entry(owner).or_default() += bytes;
                if kind == MailboxKind::Application {
                    application += bytes;
                }
            }
        }
    }
    // A lowered operator ceiling never prevents a fetch, token rollover, ACK or expiry.
    let over = |current: u64, delta: i128, max: u64| {
        delta > 0 && i128::from(current) + delta > i128::from(max)
    };
    if over(
        ledger.mailbox.application,
        application,
        MAX_QUEUED_APPLICATION_BYTES,
    ) || accounts.into_iter().any(|(account, delta)| {
        over(
            ledger.mailbox.accounts.get(&account).copied().unwrap_or(0),
            delta,
            account_limit,
        )
    }) {
        return Err(Code::RateLimited);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_relay_e2ee::object::ArcWireObjectKind;
    use agenc_relay_storage::e2ee_records::RetentionClass;

    #[test]
    fn aggregate_offline_budget_preserves_space_for_other_mailbox_kinds()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = [1; 32];
        let mut ledger = Ledger::default();
        ledger.mailbox.application = MAX_QUEUED_APPLICATION_BYTES - 64;
        let entry = |kind, size| -> Result<Account, Box<dyn std::error::Error>> {
            let owner = MailboxRow::item_key(&target, &[1; 16], kind, 0)?
                .as_bytes()
                .to_vec();
            Ok(Account {
                kind: ArcWireObjectKind::ApplicationMls.value(),
                size,
                retention: RetentionClass::Mailbox,
                accepted_at: 10,
                reconstructed: false,
                retired_at: None,
                owners: BTreeMap::from([(owner, None)]),
            })
        };
        let exact = entry(MailboxKind::Application, 64)?;
        assert_eq!(
            check(&ledger, &BTreeMap::from([([1; 32], exact.clone())]), 128),
            Ok(())
        );
        ledger.install([1; 32], exact);
        assert_eq!(
            check(
                &ledger,
                &BTreeMap::from([([2; 32], entry(MailboxKind::Application, 1)?)]),
                128
            ),
            Err(Code::RateLimited)
        );
        assert_eq!(
            check(
                &ledger,
                &BTreeMap::from([([2; 32], entry(MailboxKind::Welcome, 1)?)]),
                128
            ),
            Ok(())
        );
        ledger.remove(&[1; 32]);
        assert_eq!(
            ledger.mailbox.application,
            MAX_QUEUED_APPLICATION_BYTES - 64
        );
        assert!(ledger.mailbox.accounts.is_empty());
        Ok(())
    }
}
