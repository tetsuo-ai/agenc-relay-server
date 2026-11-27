use super::*;
use agenc_relay_federation_wire::{DecodeBudget, access::vector};

/// Exercise the public command maxima through the actual edge encoder and registered wire decoder.
#[test]
fn every_supported_directory_target_count_encodes_and_round_trips()
-> Result<(), Box<dyn std::error::Error>> {
    fn check(
        command: &CanonicalCommand,
        schema: &str,
        field: &str,
        count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_, arm) = command_arm(command.view())?;
        let wire = arm.encode_canonical()?;
        let decoded =
            SchemaObject::decode_exact(schema, wire.as_slice(), &mut DecodeBudget::new(4096, 256))?;
        assert_eq!(vector(&decoded, field)?.len(), count);
        assert_eq!(decoded.encode_canonical()?.as_slice(), wire.as_slice());
        Ok(())
    }
    for count in 0..=20 {
        let channels = (0..count)
            .map(|i| ChannelNameValue::parse(&format!("#channel{i:02}")))
            .collect::<Result<Vec<_>, _>>()?;
        check(
            &CanonicalCommand::names(channels.clone())?,
            "directory.names",
            "channels",
            count,
        )?;
        check(
            &CanonicalCommand::list(channels)?,
            "directory.list",
            "channels",
            count,
        )?;
        if count == 0 {
            continue;
        }
        let names = (0..count)
            .map(|i| NicknameValue::parse(&format!("watched{i:02}")))
            .collect::<Result<Vec<_>, _>>()?;
        check(
            &CanonicalCommand::presence(PresenceCommand::MonitorAdd(names.clone()))?,
            "directory.monitor_add",
            "nicknames",
            count,
        )?;
        check(
            &CanonicalCommand::presence(PresenceCommand::MonitorRemove(names.clone()))?,
            "directory.monitor_remove",
            "nicknames",
            count,
        )?;
        check(
            &CanonicalCommand::user_query(UserQuery::Ison(names.clone()))?,
            "directory.ison",
            "nicknames",
            count,
        )?;
        if count <= 5 {
            check(
                &CanonicalCommand::user_query(UserQuery::Userhost(names))?,
                "directory.userhost",
                "nicknames",
                count,
            )?;
        }
    }
    Ok(())
}
