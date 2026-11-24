//! Companion 11.4 control boundaries and backing ownership on the daemon filesystem.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::MemoryBudget;
use crate::test_support::{TestDirectory, TestResult, signed_test_qualification};
use agenc_relay_e2ee::TlsEncode;
use agenc_relay_e2ee::limits::{MAX_WELCOME_MAILBOX_OBJECT, WIRE_OBJECT_ENVELOPE_BYTES};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_e2ee::wire::assembly::{Direction, Sender};
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_storage::StateDirectory;

const MAX: usize = MAX_WELCOME_MAILBOX_OBJECT;
const PEER: [u8; 16] = [4; 16];

struct Fixture {
    _directory: TestDirectory,
    resources: SpoolResources,
    process: Arc<MemoryBudget>,
    link: Arc<Semaphore>,
    assembler: E2eeAssembler,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::with_reserve(0)
    }

    fn with_reserve(percent: u8) -> TestResult<Self> {
        let directory = TestDirectory::create()?;
        let qualification = signed_test_qualification(StateDirectory::probe(&directory.0)?)?;
        let state = StateDirectory::open(&directory.0, &[qualification])?;
        let process = Arc::new(MemoryBudget::new(16 * 1024 * 1024));
        let resources = SpoolResources {
            directory: Arc::new(state.companion_spool_directory(0, percent)?),
            disk: CompanionDisk::new(8 * 1024 * 1024)?,
            memory: BackingReservationPort::new(Arc::clone(&process)),
        };
        Ok(Self {
            _directory: directory,
            resources,
            process,
            link: Arc::new(Semaphore::new(2 * MAX)),
            assembler: E2eeAssembler::default(),
        })
    }

    fn ingest(
        &mut self,
        tag: &FragmentTag,
        authenticated: bool,
    ) -> Result<Ingest<ReservedObject>, AssemblyError> {
        let carrier = CarrierCommand::Response(ArcWireObjectKind::WelcomeMls);
        self.resources.ingest(
            &mut self.assembler,
            Admission {
                key: AssemblyKey {
                    direction: Direction::Response,
                    sender: Sender::Peer(PEER),
                    command: carrier,
                    route: [3; 32],
                    scope: None,
                    object_id: tag.object_id,
                },
                carrier,
                scopes: QuotaScopes {
                    peer: Some(PEER),
                    account: Some([1; 32]),
                    route: Some([3; 32]),
                    ..QuotaScopes::default()
                },
                authenticated_spool: authenticated,
            },
            tag,
            100,
            Some(Arc::clone(&self.link)),
        )
    }

    fn returned(&self) {
        assert_eq!(self.assembler.open_count(), 0);
        assert_eq!(self.assembler.quotas().reserved_bytes(), 0);
        assert_eq!(self.link.available_permits(), 2 * MAX);
        assert_eq!(self.process.available(), 16 * 1024 * 1024);
        assert!(self.resources.disk.reserve_extent(8 * 1024 * 1024).is_ok());
    }
}

fn welcome_envelope(total: usize) -> TestResult<Vec<u8>> {
    let body = vec![0x79; total - WIRE_OBJECT_ENVELOPE_BYTES];
    Ok(ArcWireObject::new(ArcWireObjectKind::WelcomeMls, body)?.encode()?)
}

#[test]
fn a_four_mib_control_holds_its_exact_bytes_until_the_last_dispatch_owner_drops() -> TestResult {
    let mut fixture = Fixture::new()?;
    let bytes = welcome_envelope(MAX)?;
    assert_eq!(bytes.len(), MAX);
    let fragments = fragment_object(&bytes)?;
    let (first, later) = fragments.split_first().ok_or("missing fragment zero")?;
    for tag in later.iter().rev() {
        assert!(matches!(fixture.ingest(tag, true)?, Ingest::Incomplete));
    }
    let duplicate = later.last().ok_or("missing fragment")?;
    assert!(matches!(
        fixture.ingest(duplicate, true)?,
        Ingest::Duplicate
    ));
    assert_eq!(fixture.assembler.quotas().reserved_bytes(), MAX);
    let Ingest::Complete(object) = fixture.ingest(first, true)? else {
        return Err("all parts did not complete the control".into());
    };
    let first_owner = CompanionBytes::from(object);
    let second_owner = first_owner.clone();
    drop(first_owner);
    assert!(second_owner.as_ref() == bytes);
    assert_eq!(fixture.assembler.open_count(), 0);
    assert_eq!(fixture.assembler.quotas().reserved_bytes(), MAX);
    assert_eq!(fixture.link.available_permits(), MAX);
    drop(second_owner);
    fixture.returned();
    Ok(())
}

#[test]
fn unsupported_controls_and_refused_headers_return_every_resource() -> TestResult {
    let mut fixture = Fixture::new()?;
    let bytes = welcome_envelope(MAX)?;
    let tags = fragment_object(&bytes)?;
    let first = tags.first().ok_or("missing fragment zero")?;
    let later = tags.get(1).ok_or("missing second part")?;
    assert!(matches!(
        fixture.ingest(later, false),
        Err(AssemblyError::ReassemblyLimit)
    ));
    fixture.returned();
    let mut over = first.clone();
    over.total += 1;
    assert!(matches!(
        fixture.ingest(&over, true),
        Err(AssemblyError::ObjectTooLarge)
    ));
    fixture.returned();
    assert!(matches!(fixture.ingest(later, true)?, Ingest::Incomplete));
    let mut truncated = first.clone();
    truncated.segment.clear();
    assert!(matches!(
        fixture.ingest(&truncated, true),
        Err(AssemblyError::InvalidFragment)
    ));
    fixture.returned();
    assert!(matches!(fixture.ingest(later, true)?, Ingest::Incomplete));
    assert_eq!(fixture.assembler.expire(u64::MAX).len(), 1);
    fixture.returned();
    Ok(())
}

#[test]
fn the_filesystem_reserve_refuses_before_writing_and_releases_every_charge() -> TestResult {
    let mut fixture = Fixture::with_reserve(100)?;
    let bytes = welcome_envelope(MAX)?;
    let fragments = fragment_object(&bytes)?;
    let first = fragments.first().ok_or("missing fragment")?;
    assert!(matches!(
        fixture.ingest(first, true),
        Err(AssemblyError::ReassemblyLimit)
    ));
    fixture.returned();
    Ok(())
}

#[test]
fn a_completed_control_keeps_each_nested_allowance_until_dispatch_releases_it() -> TestResult {
    use agenc_relay_e2ee::wire::assembly::QuotaLimits;
    let total = MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION + 1;
    let bytes = welcome_envelope(total)?;
    let fragments = fragment_object(&bytes)?;
    let mut other = bytes;
    *other.last_mut().ok_or("empty Welcome")? = 0x70;
    let other_fragments = fragment_object(&other)?;
    let next = other_fragments.first().ok_or("missing first fragment")?;
    let ceiling = (8, total);
    let defaults = QuotaLimits::default();
    for limits in [
        QuotaLimits {
            account: ceiling,
            ..defaults
        },
        QuotaLimits {
            route: ceiling,
            ..defaults
        },
        QuotaLimits {
            peer: ceiling,
            ..defaults
        },
        QuotaLimits {
            global: ceiling,
            ..defaults
        },
    ] {
        let mut fixture = Fixture::new()?;
        fixture.assembler = E2eeAssembler::new(limits);
        let mut complete = None;
        for fragment in &fragments {
            if let Ingest::Complete(object) = fixture.ingest(fragment, true)? {
                complete = Some(object);
            }
        }
        let owner = complete.ok_or("missing completed Welcome")?;
        assert_eq!(fixture.assembler.open_count(), 0);
        assert_eq!(fixture.assembler.quotas().reserved_bytes(), total);
        assert!(matches!(
            fixture.ingest(next, true),
            Err(AssemblyError::ReassemblyLimit)
        ));
        drop(owner);
        assert!(matches!(fixture.ingest(next, true)?, Ingest::Incomplete));
        assert_eq!(fixture.assembler.expire(u64::MAX).len(), 1);
        fixture.returned();
    }
    Ok(())
}
