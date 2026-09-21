//! The maximum supported shape of one approved account: all
//! `MAX_ACTIVE_DEVICES_PER_ACCOUNT` devices hold one old leaf each, sit on
//! the finality council, and continue into the successor, so activation
//! needs exactly one proof-identified ACK per device and a 33-of-64 quorum.

#![forbid(unsafe_code)]

use super::*;

/// Devices 7, 8, and 100 through 161: sixty-four in all.
fn devices() -> Vec<u8> {
    let mut devices = vec![DEVICE, SECOND_DEVICE];
    devices.extend(100..=161);
    devices
}

fn members(devices: &[u8]) -> Result<Vec<Member>> {
    devices
        .iter()
        .enumerate()
        .map(|(index, device)| {
            let leaf = u32::try_from(index)?;
            if index == 0 {
                return Ok(CREATOR);
            }
            let offset = u8::try_from(index)?;
            Ok(Member {
                device: *device,
                leaf,
                leaf_seed: 169 + offset,
                reference: Some(20 + offset),
            })
        })
        .collect()
}

#[test]
fn the_maximum_device_shape_activates_only_with_every_continuing_ack() -> Result {
    let devices = devices();
    assert_eq!(
        devices.len(),
        usize::from(agenc_relay_e2ee::limits::MAX_ACTIVE_DEVICES_PER_ACCOUNT)
    );
    let members = members(&devices)?;
    let mut harness = Harness::with_devices(&devices)?;
    let conversation = harness.bind_channel()?;
    for member in members.iter().skip(1) {
        harness.attach_as(member.device)?;
        let proof =
            harness.leaf_proof(conversation, member.device, member.leaf_seed, member.leaf)?;
        harness.publish_membership(conversation, &proof)?;
    }
    harness.attach_as(DEVICE)?;
    let (receipt, attempt) = stage(&mut harness, conversation, &members)?;
    assert_eq!(attempt.key_package_plan.entries.as_slice().len(), 64);
    let acks = members
        .iter()
        .map(|member| member_ack(conversation, &receipt, *member))
        .collect::<Result<Vec<_>>>()?;
    let voters: Vec<u8> = devices.iter().copied().take(33).collect();
    // One missing continuing ACK at the maximum shape is refused.
    let short = activation(
        &harness,
        &receipt,
        &attempt,
        acks.iter().take(63).cloned().collect(),
        &voters,
    )?;
    refused(
        &mut harness,
        Op::SubmitReinitActivate,
        &conversation,
        &short,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    let request = activation(&harness, &receipt, &attempt, acks, &voters)?;
    let outcome = ok(harness.run(Op::SubmitReinitActivate, &conversation, Some(&request))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    Ok(())
}
