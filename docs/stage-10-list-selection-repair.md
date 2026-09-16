# LIST selection and scan charging repair

This record closes RUN-02 (issue #54). It changes no wire format, numeric,
reply code, registry, configured limit, or rate table; the 200-row page, the
20-name selector, the query pools, and the privacy buckets are unchanged.

## Defects

`DomainState::project_channel_list` counted every listed channel, took the
first 200 in `ChannelInstanceId` order, and both renderers applied the
request's explicit name vector only afterwards, so `LIST #name` for a listed
channel that sorted after the first 200 returned an empty page. The domain
charged exactly one expensive-query token for every LIST regardless of the
records it scanned, while Architecture 14.3 requires one query token per 20
scanned records, and the pre-count traversed the whole channel map without
any charge.

## Repair

`DomainState::select_channel_list(selected)` resolves the request before the
ceiling. An explicit vector of at most 20 canonical, duplicate-free names
(validated by `CanonicalCommand::list`) resolves each name through the name
index, so a listed channel is returned wherever it sorts; an absent, secret,
or unlisted name yields the same omission with the same scan count and no
row shape. An empty vector scans the bounded table prefix: at most
`MAX_LIST_SCAN_RECORDS` (200) records, listed or not, and at most 200 rows.
`ChannelListScan::scanned_records` reports the records examined, never above
the bound. `project_channel_list` is now the unselected case of the same API,
and both the local renderer (`render_list_snapshot`) and the federated
renderer (`list_frames`) call the selection API with no post-filter, so the
edge/coordinator path and the local path share one semantics.

`DomainState::list_scan_bound(selected)` is the records a request will
examine (one per explicit name, otherwise `min(channels, 200)`), computed
without a scan, and `list_query_tokens` is that bound divided by 20 rounded
up and never below one. `assess_charges` now charges exactly those tokens to
the requester's expensive-query bucket, before any scan or allocation, so an
empty bucket refuses the request side-effect-free and a refilled bucket
admits the retry. The other expensive queries keep their single token. Under
the default `expensive_query` rate (one token per five seconds, burst two) an
unselected LIST over more than forty channels is refused until the bucket
holds enough tokens, which is the Section 14.3 rule; the hard maximum (burst
ten) admits the full 200-record page. No cursor field was added: slicing a
larger directory remains the coordinator's immutable snapshot cursor
contract.

## Tests

- `decision.rs` tests: 201 listed channels where the last name is absent from
  the unselected page but returned by name (and by a first-and-last pair);
  199 and 200 channels fill the page without truncation; mixed absent,
  secret, unlisted, and listed names return one row with identical omission
  for the hidden and absent cases; duplicate names and a case variant of a
  name are refused at parsing; scan tokens at 0, 1, 19, 20, 21, 40, 41, 200,
  201, and 250 channels are 1, 1, 1, 1, 2, 2, 3, 10, 10, and 10, a single or
  twenty explicit names cost one, NAMES keeps one, and the actual scan never
  examines more records than the bound it was charged for.
- Daemon transcript `list_selection_precedes_the_page_and_the_scan_is_charged_first`:
  four guests create 204 listed channels; a fifth client's unselected LIST
  returns exactly 200 rows for ten tokens, an immediate second unselected
  LIST is refused before scanning, a named LIST for a channel the page could
  not hold returns its row after one token refilled, and a two-name request
  with one absent name returns one row.
- Existing local and federated LIST renderer, query admission, receipt, and
  cursor tests are unchanged and pass.
