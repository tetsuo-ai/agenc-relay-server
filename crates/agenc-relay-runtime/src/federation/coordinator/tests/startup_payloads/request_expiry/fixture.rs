//! One validated request/result pair and an independently committed origin sequence floor.
#![forbid(unsafe_code)]
use super::*;
mod io;
mod pair;

pub(super) struct Fixture {
    pub(super) core: StateCoreFixture,
    pub(super) coordinator: FederationCoordinator,
    pub(super) key: ReplayKey,
    pub(super) request_object_id: [u8; 32],
    pub(super) result_id: [u8; 32],
}
impl Fixture {
    pub(super) async fn new(retain_replay: bool) -> TestResult<Self> {
        Box::pin(Self::many(1, retain_replay)).await
    }

    pub(super) async fn many(count: u64, retain_replay: bool) -> TestResult<Self> {
        if count == 0 {
            return Err("empty fixture".into());
        }
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        let retain_until = 1000 + agenc_relay_e2ee::limits::S2S_IDEMPOTENCY_RETENTION_SECONDS;
        core.context_mut()?.set_wall_for_test(retain_until);
        let mut coordinator = empty_coordinator(&core)?;
        let executor = coordinator.companion_executor().ok_or("executor")?;
        let mut first = None;
        let mut writes = Vec::new();
        for sequence in 0..count {
            let pair = pair::create(&core, executor, sequence)?;
            let (row, write) = request::replay_write(
                &pair.key,
                &pair.decoded,
                &pair.result,
                &[],
                false,
                retain_until,
            )
            .map_err(|e| format!("replay: {e:?}"))?;
            writes.push(
                CompanionCoordinator::object_write(&pair.result)
                    .map_err(|e| format!("object: {e:?}"))?,
            );
            if retain_replay {
                writes.push(write);
            }
            if first.is_none() {
                first = Some((pair, row));
            }
        }
        let (first, row) = first.ok_or("first pair")?;
        let origin_key = CompanionOriginKey {
            home_server_id: first.key.home_server_id,
            server_incarnation: first.key.server_incarnation,
            origin_id: first.key.origin_id,
        };
        let floor = OriginSequenceRow {
            origin_generation: 0,
            next_sequence: count,
        };
        writes.push(
            request::origin_sequence_write(&origin_key, floor)
                .map_err(|e| format!("floor: {e:?}"))?,
        );
        helpers::commit(&mut core, writes).await?;
        coordinator.startup(core.context_mut()?);
        helpers::drive(&mut coordinator, &mut core).await?;
        assert!(coordinator.loaded());
        assert_eq!(coordinator.counters().violations, 0);
        let executor = coordinator.companion_executor().ok_or("executor")?;
        if retain_replay {
            assert_eq!(executor.state.replays.get(&first.key), Some(&row));
            assert_eq!(
                executor
                    .state
                    .results
                    .get(&first.decoded.request_object_id)
                    .ok_or("stored result")?
                    .result,
                first.result
            );
            assert_eq!(
                executor.state.objects.get(&first.result_id),
                Some(&first.result)
            );
        }
        assert_eq!(
            executor.state.origin_sequences.get(&origin_key),
            Some(&floor)
        );
        Ok(Self {
            core,
            coordinator,
            key: first.key,
            request_object_id: first.decoded.request_object_id,
            result_id: first.result_id,
        })
    }
    pub(super) fn idle(&mut self) -> TestResult {
        let context = self.core.context_mut()?;
        let now = context.now();
        for _ in 0..32 {
            let Some(entry) = context.timers_mut().pop_due(now) else {
                break;
            };
            self.coordinator.timer_fired(context, entry);
            if self.coordinator.pending.is_some() {
                break;
            }
        }
        self.coordinator.continue_restore(context);
        Ok(())
    }
}
