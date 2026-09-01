//! Transport admission before TLS and connection-task creation.

use std::collections::HashMap;
use std::time::Duration;

use agenc_ircd_types::{MonotonicClock, MonotonicTick};
use tokio::sync::Notify;

use super::{
    BucketDemand, BucketKey, BucketKind, BucketTable, OverloadClass, OverloadState, PrefixRegistry,
    RateLimits,
};
use crate::RuntimeError;
use crate::budget::MemoryBudget;
use crate::listener::{AcceptAdmission, AdmissionVerdict};
use crate::observe::adapter::RuntimeObserver;
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::SourceAddressKey;
use crate::sync::{Arc, Mutex, lock};

/// The rate, per-address, prefix-lifetime, and overload authority consulted
/// before a client TLS handshake begins.
pub struct TransportAdmission {
    state: Mutex<TransportAdmissionState>,
    budget: Arc<MemoryBudget>,
    direct_per_address: u64,
    observer: Mutex<Option<Arc<RuntimeObserver>>>,
    prefix_expiry_changed: Notify,
}

struct TransportAdmissionState {
    clock: Box<dyn MonotonicClock + Send>,
    buckets: BucketTable,
    prefixes: PrefixRegistry,
    direct_hosts: HashMap<SourceAddressKey, u64>,
    overload: OverloadState,
}

impl TransportAdmission {
    /// Creates an empty transport-admission owner.
    pub fn new(
        limits: RateLimits,
        direct_per_address: u64,
        budget: Arc<MemoryBudget>,
        clock: Box<dyn MonotonicClock + Send>,
    ) -> Result<Self, RuntimeError> {
        if direct_per_address == 0 {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            state: Mutex::new(TransportAdmissionState {
                clock,
                buckets: BucketTable::new(limits),
                prefixes: PrefixRegistry::new(),
                direct_hosts: HashMap::new(),
                overload: OverloadState::new(),
            }),
            budget,
            direct_per_address,
            observer: Mutex::new(None),
            prefix_expiry_changed: Notify::new(),
        })
    }

    /// Installs the process observer before listeners begin accepting.
    pub(crate) fn install_observer(&self, observer: Arc<RuntimeObserver>) {
        *lock(&self.observer) = Some(observer);
    }

    /// Erases transport prefix rows that have been idle for ten minutes.
    pub fn erase_idle(&self) {
        let mut state = lock(&self.state);
        let now = state.clock.now();
        state.erase_idle(now);
    }

    /// Returns the delay before the earliest address-derived row must be
    /// erased, or `None` while no idle row exists.
    pub(crate) fn prefix_erasure_delay(&self) -> Option<Duration> {
        let state = lock(&self.state);
        let now = state.clock.now();
        state
            .prefixes
            .millis_until_next_erasure(now)
            .map(Duration::from_millis)
    }

    /// Waits until a connection close may have changed the earliest prefix
    /// erasure deadline. Notifications coalesce without consuming inbox space.
    pub(crate) async fn prefix_expiry_changed(&self) {
        self.prefix_expiry_changed.notified().await;
    }

    /// Atomically installs validated transport bucket rates.
    pub fn reload(&self, limits: RateLimits) {
        lock(&self.state).buckets.reload(limits);
    }
}

impl AcceptAdmission for TransportAdmission {
    fn admit(&self, purpose: ListenerPurpose, source: SourceAddressKey) -> AdmissionVerdict {
        let mut state = lock(&self.state);
        let previous = state.overload.class();
        let current = state
            .overload
            .classify(self.budget.charged(), self.budget.capacity());
        let verdict = if current >= OverloadClass::NoNewConnections {
            AdmissionVerdict::Refuse
        } else {
            let now = state.clock.now();
            let admitted = match purpose {
                ListenerPurpose::ClientTls => {
                    state.admit_direct(source, now, self.direct_per_address)
                }
                ListenerPurpose::ClientOnion => state.admit_onion(now),
                ListenerPurpose::ClientWss
                | ListenerPurpose::Federation
                | ListenerPurpose::AdminLocal
                | ListenerPurpose::AdminTls => false,
            };
            if admitted {
                AdmissionVerdict::Admit
            } else {
                AdmissionVerdict::Refuse
            }
        };
        drop(state);
        if current != previous
            && let Some(observer) = lock(&self.observer).clone()
        {
            observer.overload_transition(current);
        }
        verdict
    }

    fn released(
        &self,
        purpose: ListenerPurpose,
        source: SourceAddressKey,
    ) -> Option<MonotonicTick> {
        let mut state = lock(&self.state);
        let now = state.clock.now();
        let became_idle = match purpose {
            ListenerPurpose::ClientTls => state.release_direct(source, now),
            ListenerPurpose::ClientOnion => state.release_onion(now),
            ListenerPurpose::ClientWss
            | ListenerPurpose::Federation
            | ListenerPurpose::AdminLocal
            | ListenerPurpose::AdminTls => false,
        };
        drop(state);
        if became_idle {
            self.prefix_expiry_changed.notify_one();
        }
        Some(now)
    }
}

impl TransportAdmissionState {
    fn admit_direct(
        &mut self,
        source: SourceAddressKey,
        now: MonotonicTick,
        direct_per_address: u64,
    ) -> bool {
        let host = source.host_key();
        let current = self.direct_hosts.get(&host).copied().unwrap_or(0);
        if current >= direct_per_address {
            return false;
        }
        let Some(next) = current.checked_add(1) else {
            return false;
        };
        if !self.direct_hosts.contains_key(&host) && self.direct_hosts.try_reserve(1).is_err() {
            return false;
        }
        let prefix = source.prefix_key();
        let evicted = {
            let Ok(opening) = self.prefixes.begin_connection_open(prefix, now) else {
                return false;
            };
            if !Self::charge_connection(
                &mut self.buckets,
                now,
                BucketKind::NewDirectTcp,
                BucketKey::Prefix(prefix),
            ) {
                return false;
            }
            self.direct_hosts.insert(host, next);
            opening.commit()
        };
        self.erase_evicted_prefix(evicted);
        true
    }

    fn admit_onion(&mut self, now: MonotonicTick) -> bool {
        let source = SourceAddressKey::onion_listener();
        let evicted = {
            let Ok(opening) = self.prefixes.begin_connection_open(source, now) else {
                return false;
            };
            if !Self::charge_connection(
                &mut self.buckets,
                now,
                BucketKind::NewOnionConnection,
                BucketKey::OnionListener,
            ) {
                return false;
            }
            opening.commit()
        };
        self.erase_evicted_prefix(evicted);
        true
    }

    fn charge_connection(
        buckets: &mut BucketTable,
        now: MonotonicTick,
        connection_kind: BucketKind,
        key: BucketKey,
    ) -> bool {
        let Ok(connection) = BucketDemand::new(connection_kind, key, 1) else {
            return false;
        };
        let Ok(handshake) = BucketDemand::new(BucketKind::TlsHandshake, key, 1) else {
            return false;
        };
        buckets
            .charge_all_or_nothing(now, &[connection, handshake])
            .is_ok()
    }

    fn release_direct(&mut self, source: SourceAddressKey, now: MonotonicTick) -> bool {
        let prefix = source.prefix_key();
        let became_idle =
            self.prefixes.connection_closed(prefix, now).is_ok() && self.prefixes.live(prefix) == 0;
        let host = source.host_key();
        let remove = self.direct_hosts.get_mut(&host).is_some_and(|count| {
            *count = count.saturating_sub(1);
            *count == 0
        });
        if remove {
            self.direct_hosts.remove(&host);
        }
        became_idle
    }

    fn release_onion(&mut self, now: MonotonicTick) -> bool {
        let source = SourceAddressKey::onion_listener();
        self.prefixes.connection_closed(source, now).is_ok() && self.prefixes.live(source) == 0
    }

    fn erase_idle(&mut self, now: MonotonicTick) {
        for prefix in self.prefixes.erase_idle(now) {
            self.erase_prefix_buckets(prefix);
        }
    }

    fn erase_evicted_prefix(&mut self, evicted: Option<SourceAddressKey>) {
        if let Some(prefix) = evicted {
            self.erase_prefix_buckets(prefix);
        }
    }

    fn erase_prefix_buckets(&mut self, prefix: SourceAddressKey) {
        self.buckets.erase_key(BucketKey::Prefix(prefix));
        if prefix == SourceAddressKey::onion_listener() {
            self.buckets.erase_key(BucketKey::OnionListener);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::admission::BucketRate;
    use crate::budget::{BoundedMemoryCharges, MemoryBudgetPort as _, MemoryCharge};

    use super::*;

    #[derive(Clone)]
    struct TestClock(Arc<AtomicU64>);

    impl MonotonicClock for TestClock {
        fn now(&self) -> MonotonicTick {
            MonotonicTick::from_ticks(self.0.load(Ordering::Relaxed))
        }
    }

    fn admission(
        direct_per_address: u64,
        capacity: u64,
    ) -> Result<(TransportAdmission, Arc<AtomicU64>, Arc<MemoryBudget>), RuntimeError> {
        admission_with_rates(direct_per_address, capacity, RateLimits::defaults())
    }

    fn admission_with_rates(
        direct_per_address: u64,
        capacity: u64,
        limits: RateLimits,
    ) -> Result<(TransportAdmission, Arc<AtomicU64>, Arc<MemoryBudget>), RuntimeError> {
        let ticks = Arc::new(AtomicU64::new(0));
        let budget = Arc::new(MemoryBudget::new(capacity));
        let admission = TransportAdmission::new(
            limits,
            direct_per_address,
            Arc::clone(&budget),
            Box::new(TestClock(Arc::clone(&ticks))),
        )?;
        Ok((admission, ticks, budget))
    }

    #[test]
    fn direct_hosts_obey_the_live_ceiling_and_release_exactly_once() -> Result<(), RuntimeError> {
        let (admission, _, _) = admission(2, 1_000)?;
        let source = SourceAddressKey::ipv4([192, 0, 2, 7]);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, source),
            AdmissionVerdict::Admit
        );
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, source),
            AdmissionVerdict::Admit
        );
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, source),
            AdmissionVerdict::Refuse
        );
        let _closed_at = admission.released(ListenerPurpose::ClientTls, source);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, source),
            AdmissionVerdict::Admit
        );
        Ok(())
    }

    #[test]
    fn prefix_ceiling_eviction_erases_the_coupled_rate_bucket() -> Result<(), RuntimeError> {
        let (admission, _, _) = admission(16, 1_000)?;
        lock(&admission.state).prefixes = PrefixRegistry::with_ceiling(1);
        let first = SourceAddressKey::ipv4([192, 0, 2, 1]);
        let second = SourceAddressKey::ipv4([198, 51, 100, 1]);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, first),
            AdmissionVerdict::Admit
        );
        let _closed_at = admission.released(ListenerPurpose::ClientTls, first);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, second),
            AdmissionVerdict::Admit
        );

        let mut state = lock(&admission.state);
        let kind = BucketKind::NewDirectTcp;
        let expected = state.buckets.limits().rate(kind).burst();
        let available = state.buckets.available(
            MonotonicTick::from_ticks(0),
            kind,
            BucketKey::Prefix(first.prefix_key()),
        );
        assert_eq!(available, expected);
        Ok(())
    }

    #[test]
    fn prefix_refusal_consumes_no_connection_or_handshake_credit() -> Result<(), RuntimeError> {
        let mut limits = RateLimits::defaults();
        limits.set(BucketKind::NewDirectTcp, BucketRate::new(1, 3_600, 1)?)?;
        limits.set(BucketKind::TlsHandshake, BucketRate::new(1, 3_600, 1)?)?;
        let (admission, _, _) = admission_with_rates(16, 1_000, limits)?;
        lock(&admission.state).prefixes = PrefixRegistry::with_ceiling(1);
        let first = SourceAddressKey::ipv4([192, 0, 2, 1]);
        let second = SourceAddressKey::ipv4([198, 51, 100, 1]);

        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, first),
            AdmissionVerdict::Admit
        );
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, second),
            AdmissionVerdict::Refuse
        );
        let _closed_at = admission.released(ListenerPurpose::ClientTls, first);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, second),
            AdmissionVerdict::Admit
        );
        Ok(())
    }

    #[test]
    fn direct_prefixes_share_the_new_connection_bucket() -> Result<(), RuntimeError> {
        let (admission, _, _) = admission(16, 1_000)?;
        for host in 1..=8 {
            let source = SourceAddressKey::ipv4([198, 51, 100, host]);
            assert_eq!(
                admission.admit(ListenerPurpose::ClientTls, source),
                AdmissionVerdict::Admit
            );
            let _closed_at = admission.released(ListenerPurpose::ClientTls, source);
        }
        assert_eq!(
            admission.admit(
                ListenerPurpose::ClientTls,
                SourceAddressKey::ipv4([198, 51, 100, 9]),
            ),
            AdmissionVerdict::Refuse
        );
        Ok(())
    }

    #[test]
    fn onion_connections_share_the_global_tls_bucket() -> Result<(), RuntimeError> {
        let (admission, _, _) = admission(16, 1_000)?;
        let source = SourceAddressKey::onion_listener();
        for _ in 0..16 {
            assert_eq!(
                admission.admit(ListenerPurpose::ClientOnion, source),
                AdmissionVerdict::Admit
            );
            let _closed_at = admission.released(ListenerPurpose::ClientOnion, source);
        }
        assert_eq!(
            admission.admit(ListenerPurpose::ClientOnion, source),
            AdmissionVerdict::Refuse
        );
        Ok(())
    }

    #[test]
    fn idle_erasure_drops_the_prefix_buckets_at_the_exact_boundary() -> Result<(), RuntimeError> {
        let mut limits = RateLimits::defaults();
        limits.set(BucketKind::NewDirectTcp, BucketRate::new(1, 3_600, 8)?)?;
        let (admission, ticks, _) = admission_with_rates(16, 1_000, limits)?;
        for host in 1..=8 {
            let source = SourceAddressKey::ipv4([203, 0, 113, host]);
            assert_eq!(
                admission.admit(ListenerPurpose::ClientTls, source),
                AdmissionVerdict::Admit
            );
            let _closed_at = admission.released(ListenerPurpose::ClientTls, source);
        }
        assert_eq!(
            admission.prefix_erasure_delay(),
            Some(Duration::from_millis(
                crate::admission::prefix::PREFIX_ERASURE_MILLIS
            ))
        );
        ticks.store(599_999, Ordering::Relaxed);
        assert_eq!(
            admission.prefix_erasure_delay(),
            Some(Duration::from_millis(1))
        );
        admission.erase_idle();
        assert_eq!(
            admission.admit(
                ListenerPurpose::ClientTls,
                SourceAddressKey::ipv4([203, 0, 113, 9]),
            ),
            AdmissionVerdict::Refuse
        );
        ticks.store(600_000, Ordering::Relaxed);
        admission.erase_idle();
        assert_eq!(admission.prefix_erasure_delay(), None);
        assert_eq!(
            admission.admit(
                ListenerPurpose::ClientTls,
                SourceAddressKey::ipv4([203, 0, 113, 9]),
            ),
            AdmissionVerdict::Admit
        );
        Ok(())
    }

    #[tokio::test]
    async fn idle_deadline_notifications_coalesce_without_losing_the_wakeup()
    -> Result<(), RuntimeError> {
        let (admission, _, _) = admission(16, 1_000)?;
        let first = SourceAddressKey::ipv4([192, 0, 2, 1]);
        let second = SourceAddressKey::ipv4([198, 51, 100, 1]);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, first),
            AdmissionVerdict::Admit
        );
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, second),
            AdmissionVerdict::Admit
        );
        let _closed_at = admission.released(ListenerPurpose::ClientTls, first);
        let _closed_at = admission.released(ListenerPurpose::ClientTls, second);

        tokio::time::timeout(Duration::from_secs(1), admission.prefix_expiry_changed())
            .await
            .map_err(|_| RuntimeError::Cancelled)?;
        assert!(
            tokio::time::timeout(Duration::from_millis(5), admission.prefix_expiry_changed(),)
                .await
                .is_err(),
            "Notify stores at most one pending maintenance wakeup"
        );
        Ok(())
    }

    #[test]
    fn memory_overload_closes_new_connections_at_ninety_percent() -> Result<(), RuntimeError> {
        let (admission, _, budget) = admission(16, 100)?;
        let charges = BoundedMemoryCharges::new(&[MemoryCharge::fixed(90)])?;
        let permit = budget.try_acquire_batch(charges)?;
        let source = SourceAddressKey::ipv4([192, 0, 2, 1]);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, source),
            AdmissionVerdict::Refuse
        );
        drop(permit);
        assert_eq!(
            admission.admit(ListenerPurpose::ClientTls, source),
            AdmissionVerdict::Admit
        );
        Ok(())
    }
}
