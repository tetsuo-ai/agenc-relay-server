# Storage schema generation 5

Generation 5 is the fresh AgenC Relay ARC baseline. Ordinary startup accepts
only generation 5, with the ARC profile, ARCD control-record magic, and current
sealed-record contract. Release candidate `1.0.0-rc.3` uses this generation.

Earlier private development databases and backups are not input for a running
ARC node. Initialize a fresh directory with `arcd init`; retain any old data
separately if needed. Startup rejects an incompatible format and must not
delete, rename, or migrate it. No deployment migration is provided.

The schema retains the bounded replay-owner and acknowledgement-range
records used for durable E2EE delivery. Their storage keys bind the complete
delivery scope and generation. ACK advancement, retention cutoffs, paired
barriers, and their persistent records share a commit receipt. Physical cleanup
runs in bounded batches; uncollected objects count against the disk limit.

The schema registry is `crates/agenc-relay-storage/src/schema.rs`; the release
storage contract is `conformance/stage-five-storage-profile.toml`. Backup,
restore, recovery, and qualification tests must use this exact baseline.
