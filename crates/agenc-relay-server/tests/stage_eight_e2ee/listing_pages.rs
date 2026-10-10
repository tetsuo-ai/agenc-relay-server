//! Companion 11.6, 11.7 and 16 through the production daemons of the Stage
//! 08 network: an account whose roster holds more devices than one batch
//! publishes a capability statement for each, and `EKEY FETCH
//! CAPABILITIES` pages the set through edge A over one immutable cut. Every
//! page repeats one snapshot token and names the next cursor, the last page
//! names `*`, the pages hold every device exactly once in Device-ID order,
//! a statement published between the pages stays out of the cut, and a
//! consumed or forged cursor is refused for its request alone while the
//! link stays up.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use super::link_faults::link_events;
use super::recovery_submission::{attach_again, settle};
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The signing seed of the account's root.
const ROOT: u8 = 0x79;
/// The account's devices: more than one batch of 32.
const DEVICES: std::ops::Range<u8> = 0x80..0xa8;
/// The account request seed of the session.
const REQUEST_SEED: u8 = 77;

/// One page of `EKEY FETCH CAPABILITIES` as the edge renders it.
struct Page {
    snapshot: String,
    next: String,
    objects: Vec<Vec<u8>>,
}

/// The objects of one object batch in the order their fragments open.
fn ordered_objects(lines: &[String]) -> TestResult<Vec<Vec<u8>>> {
    let mut order: Vec<[u8; 32]> = Vec::new();
    let mut parts: BTreeMap<[u8; 32], Vec<FragmentTag>> = BTreeMap::new();
    for line in lines {
        let Some(value) = tag_value(line, SERVER_FRAGMENT_TAG) else {
            continue;
        };
        let fragment = FragmentTag::parse(&value)?;
        let id = *fragment.object_id.as_bytes();
        if !order.contains(&id) {
            order.push(id);
        }
        parts.entry(id).or_default().push(fragment);
    }
    order
        .iter()
        .map(|id| {
            let mut fragments = parts.remove(id).ok_or_else(|| failure("fragments"))?;
            fragments.sort_by_key(|fragment| fragment.part);
            Ok(fragments
                .into_iter()
                .flat_map(|fragment| fragment.segment)
                .collect())
        })
        .collect()
}

/// Asks for the page `cursor` names, `*` for the first; returns the reply.
fn ask(client: &mut ArcClient, user: &mut Principal, cursor: &str) -> TestResult<Vec<String>> {
    let account = base64url_encode(&user.account);
    let label = user.label();
    client.send(&format!(
        "@label={label} EKEY FETCH CAPABILITIES {account} {cursor}"
    ))?;
    labeled_reply(client, &label)
}

/// The page `cursor` names, read from its batch opener and objects.
fn page(client: &mut ArcClient, user: &mut Principal, cursor: &str) -> TestResult<Page> {
    let reply = ask(client, user, cursor)?;
    let opener = reply
        .iter()
        .find(|line| line.contains(" BATCH +"))
        .ok_or_else(|| failure(format!("no batch in {reply:?}")))?;
    let fields = words(opener);
    let position = fields
        .iter()
        .position(|word| word == "agenc.ag/e2ee-objects")
        .ok_or_else(|| failure(format!("no object batch: {opener}")))?;
    let field = |offset: usize| {
        fields
            .get(position + offset)
            .cloned()
            .ok_or_else(|| failure(format!("short opener: {opener}")))
    };
    assert_eq!(field(1)?, "EKEY");
    assert_eq!(field(2)?, "CAPABILITIES");
    Ok(Page {
        snapshot: field(4)?,
        next: field(5)?,
        objects: ordered_objects(&reply)?,
    })
}

/// Publishes `user`'s statement of generation zero for its attached device.
fn publish_statement(client: &mut ArcClient, user: &mut Principal) -> TestResult<Vec<u8>> {
    let capabilities = builders::capabilities(
        user.device,
        &user.keys.roster,
        0,
        [0; 32],
        (200, 3_600),
        vec![1],
    )?;
    let object = wire_object(ArcWireObjectKind::DeviceCapabilities, &capabilities)?;
    let label = user.label();
    send_object(
        client,
        &label,
        &format!("EKEY PUBLISH CAPABILITIES {}", user.device_token()),
        &object,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY STORED CAPABILITIES ")?;
    Ok(object)
}

/// [`publish_statement`], asked again while the device's new attachment is
/// still being declared.
fn settled_statement(client: &mut ArcClient, user: &mut Principal) -> TestResult<Vec<u8>> {
    settle("the statement", || publish_statement(client, user))
}

#[test]
fn a_capability_set_longer_than_one_batch_pages_through_an_edge_over_one_cut() -> TestResult {
    super::encrypted_clients::run_network(|network, _coordinator, _edge_a, _edge_b| {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_account_authority(&network.edge_a)?;
        let (mut client, account_id) = step(
            "session",
            authenticated_client(&network.edge_a, "pager", "pager-account", REQUEST_SEED),
        )?;
        let devices: Vec<u8> = DEVICES.collect();
        let account: [u8; 24] = account_id
            .to_text()
            .as_bytes()
            .try_into()
            .map_err(|_| failure("account text is 24 bytes"))?;
        let mut user = Principal {
            keys: builders::principal(ROOT, &account, &devices)?,
            device: *devices.first().ok_or_else(|| failure("a device"))?,
            account,
            labels: 0,
        };
        // The edge answers for the account once its session is the
        // coordinator's.
        settle("the account", || {
            let label = user.label();
            client.send(&format!("@label={label} EKEY WHOAMI"))?;
            let reply = labeled_reply(&mut client, &label)?;
            if reply.iter().any(|line| line.contains(" FAIL ")) {
                return Err(failure(format!("WHOAMI: {reply:?}")));
            }
            assert_contains(&reply, " EKEY ACCOUNT ")
        })?;
        step("publish", publish_and_attach(&mut client, &mut user))?;
        let mut statements = Vec::new();
        for device in &devices {
            if !statements.is_empty() {
                user.device = *device;
                step(
                    "attach",
                    settle("the attach", || attach_again(&mut client, &mut user)),
                )?;
            }
            statements.push(step(
                "statement",
                settled_statement(&mut client, &mut user),
            )?);
        }
        let before = link_events(network);
        let first = step("first page", page(&mut client, &mut user, "*"))?;
        assert_eq!(first.objects.len(), 32);
        assert_ne!(first.next, "*", "a longer cut names its next cursor");
        // The last device publishes its next statement between the pages.
        let last = statement_id(statements.last().ok_or_else(|| failure("a statement"))?)?;
        let next_statement = builders::capabilities(
            user.device,
            &user.keys.roster,
            1,
            last,
            (200, 3_600),
            vec![1],
        )?;
        let next_object = wire_object(ArcWireObjectKind::DeviceCapabilities, &next_statement)?;
        let label = user.label();
        send_object(
            &mut client,
            &label,
            &format!("EKEY PUBLISH CAPABILITIES {}", user.device_token()),
            &next_object,
        )?;
        assert_contains(
            &labeled_reply(&mut client, &label)?,
            " EKEY STORED CAPABILITIES ",
        )?;
        let second = step("second page", page(&mut client, &mut user, &first.next))?;
        assert_eq!(
            second.snapshot, first.snapshot,
            "every page repeats its cut"
        );
        assert_eq!(second.next, "*", "the last page names no cursor");
        let mut cut = first.objects;
        cut.extend(second.objects);
        assert_eq!(cut, statements, "every device once, in Device-ID order");
        // The consumed cursor and a forged one are refused for their request
        // alone.
        for cursor in [first.next.clone(), base64url_encode(&[0x33; 32])] {
            let reply = ask(&mut client, &mut user, &cursor)?;
            assert_contains(&reply, "FAIL EKEY E2EE_OBJECT_NOT_FOUND")?;
        }
        // A new cut holds the device's next statement.
        let fresh = page(&mut client, &mut user, "*")?;
        let rest = page(&mut client, &mut user, &fresh.next)?;
        assert_eq!(rest.objects.last(), Some(&next_object));
        if link_events(network) != before {
            return Err(failure(
                "edge A's coordinator link failed while the cut was paged",
            ));
        }
        Ok(())
    })
}

/// The semantic identifier of a published capability statement object.
fn statement_id(object: &[u8]) -> TestResult<[u8; 32]> {
    let mut budget = DecodeBudget::new(1 << 17, 1 << 12);
    let decoded = ArcWireObject::decode_kind(
        object,
        Some(ArcWireObjectKind::DeviceCapabilities),
        &mut budget,
    )?;
    let statement =
        agenc_relay_testkit::e2ee::objects::identity::ArcDeviceCapabilities::decode_exact(
            decoded.body(),
            &mut budget,
        )?;
    Ok(semantic_id_of(
        SemanticHashDomain::CapabilityId,
        &statement.tbs,
    )?)
}
