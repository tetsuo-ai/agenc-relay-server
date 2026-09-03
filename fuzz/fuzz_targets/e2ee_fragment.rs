#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, E2eeAssembler, QuotaScopes, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::command::parse_command;
use agenc_ircd_e2ee::wire::fragment::{FragmentTag, ReceiptTag};
use libfuzzer_sys::fuzz_target;

// Tag values, receipt values, and command lines never panic; a parsed
// fragment re-renders to its exact input and can be offered to a fresh
// assembler without panicking.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(tag) = FragmentTag::parse(text) {
        assert_eq!(tag.render(), text);
        let mut assembler = E2eeAssembler::default();
        let key = AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Peer([1; 16]),
            command: CarrierCommand::Tagmsg,
            route: [2; 32],
            scope: None,
            object_id: tag.object_id,
        };
        let _ = assembler.ingest(
            key,
            QuotaScopes::default(),
            CarrierCommand::Tagmsg.limit(),
            &tag,
            0,
        );
    }
    if let Ok(receipt) = ReceiptTag::parse(text) {
        assert_eq!(receipt.render(), text);
    }
    let mut words = text.split(' ');
    if let Some(command) = words.next() {
        let params: Vec<&str> = words.collect();
        let _ = parse_command(command, &params);
    }
});
