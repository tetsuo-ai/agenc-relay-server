# Stage 10 sequencer credentials through `arcd`

This record covers AUD-02 of the SDK readiness audit (2026-10-01, SDK
program, outside master #35). No `arcd` command produced the public sequencer
credentials document that every node of an encrypted network names in
`e2ee.sequencer_credentials_file` (architecture Appendix C.7). The only
producer was the testkit's `sequencer_credentials_document`
(`crates/agenc-relay-testkit/src/e2ee_client.rs`), so an encrypted network
could be provisioned only with test code, and the operator guide described
rotation documents but not the first one.

## The command

```text
arcd sequencer-credentials create --config <file> --sequencer-key-file <file>
  --not-before <unix-seconds> --not-after <unix-seconds> --output <new-file>
  [--service-user <name>]
```

`create_sequencer_credentials`
(`crates/agenc-relay-runtime/src/offline/sequencer_credentials.rs`) writes
the document of a new network:

- set generation zero holding one credential at key generation zero, with
  profile version 1, the all-zero previous key ID and an empty continuity
  signature, valid from `--not-before` through `--not-after`;
- the network ID from the configuration, loaded and validated as
  `print-onboarding` loads it;
- the sequencer public key derived from the raw 32-byte seed in the key
  file, read under the protected-file rules (Section 22.2); the seed copy is
  zeroized and the process is hardened before any file is read, as for the
  other offline commands;
- the bytes from the shared canonical encoders of `agenc-relay-e2ee`
  (`SequencerCredentialsFile`, `ArcSequencerCredential`), the same
  structures the testkit builder fills.

Before anything is published, the document is parsed and verified as the
network's key set by the same `SequencerCredentialsFile::parse` and
`key_set` that startup's `load_sequencer_credentials` runs. It is written to
a staged name in the output's directory with mode 0644 (before the umask),
synchronized, and moved into place with a no-replace rename, so an existing
output path is refused and never replaced and no reader sees a partial
document. The command prints the key set's `sequencer-key-set-generation=`
and `sequencer-key-set-hash=` lines in the descriptor's form, so an operator
can compare them with every node's `print-onboarding`.

Refused before anything is written: an empty or reversed interval, an
output that is relative, unnamed, below a group- or world-writable directory
or already present, a configuration that does not validate, a key file that
fails the protected-file rules or is not 32 bytes, and an unknown or
unpermitted `--service-user`. The interval values are canonical decimal
`u64`, the rule `--expires-in` follows. `arcd`'s usage text gains the
command's line.

The operator guide gains the procedure: the field sources of the
`[[federation.peer]]` records, the command, the installation of the same
bytes on every node, the coordinator's and the edges' `[e2ee]` settings and
the `print-onboarding` check. Rotation and retirement documents keep the
guide's existing out-of-band procedure.

No wire byte, configuration key, stored row or protocol identifier changes,
and no dependency is added: the runtime already depends on
`agenc-relay-e2ee` and `agenc-relay-config`.

## Regressions

- `offline::tests::sequencer_credentials_equal_the_testkit_document`: the
  document equals, byte for byte, the testkit's for the same network, key
  and interval; the daemon's own reader accepts it with exactly the
  generation and hash the command reports; the output is owner-readable and
  neither group- nor world-writable; a second run is refused with the
  document unchanged.
- `offline::tests::sequencer_credentials_refuse_bad_intervals_outputs_and_keys`:
  the refusals above, with nothing written.
- `tests::sequencer_credentials_parser_requires_every_value_in_canonical_form`
  in `crates/agenc-relay-server/src/daemon_cli.rs`: every option is
  required, values are canonical, other subcommands print the usage, and an
  unknown service user is refused before any file is read.
- `stage_zero_refusal`: the usage text names the command.
- `stage_eight_e2ee::cli_provisioning::a_network_provisioned_only_with_arcd_links_and_advertises_e2ee`:
  a coordinator and two edges created by `arcd init`, the coordinator's
  credentials created by `arcd sequencer-credentials create` (byte-equal to
  the testkit document for the key `init` wrote), and each edge's
  `print-onboarding` naming the printed generation and hash. Both edges
  link, advertise `agenc.ag/e2ee-mls` and the coordinator's recovery epoch,
  and register a client. The AUD-01 daemon case uses the same provisioning.

With the command's dispatch disabled, the CLI parser case and both daemon
cases fail, the daemon cases at their first `arcd sequencer-credentials` call
with the usage refusal. With the credential's `not_after` one second short of
the request, the offline case and both daemon cases fail at the byte
comparison with the testkit document; with the document at set generation 1,
the offline case fails at that comparison and the daemon cases at the printed
generation.

## Limitations

- The command writes only a new network's generation-zero document. A
  successor or retirement document needs the previous key's continuity
  signature and stays the operator guide's out-of-band procedure.
- The daemon cases are provisioned through `arcd` plus the operator's edits:
  their TLS certificates come from the test CA, as an operator's come from
  its CA, and each `[[federation.peer]]` record's `signing_public_key` is
  derived from the seed `init` wrote, because no `arcd` command prints a
  federation signing public key; the operator guide says so.
- The output's mode is subject to the caller's umask; the daemon's
  protected read accepts any resulting mode that is not group- or
  world-writable, owned by root or the service account.
