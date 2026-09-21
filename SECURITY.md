# Security Policy

## Project status

AgenC Relay (ARCD) is pre-alpha and has no supported production release. Security
reports against `main`, the specifications, test vectors, build policy, and
implemented foundational crates are still welcome.

## Report privately

Do not open a public issue or pull request for a suspected vulnerability.
Email **security@agenc.tech** with:

- the affected commit, crate, command, or specification section;
- the expected and observed behavior;
- a minimal reproduction or malformed input when safe;
- the likely confidentiality, integrity, privacy, or availability impact; and
- any suggested mitigation.

Do not include live credentials, private keys, user content, network
addresses, or third-party secrets. The maintainers will acknowledge a
good-faith report, establish a private coordination channel, and agree on
disclosure timing before publication.

## High-value report areas

Reports are especially useful when they concern parser totality, unchecked
allocation, panic or denial of service, identity or authorization confusion,
cryptographic-profile integration, downgrade behavior, federation replay or
equivocation, persistence rollback, secret exposure, or metadata leakage.

Ordinary feature requests and non-security correctness bugs may use the normal
issue tracker once the repository is public.
