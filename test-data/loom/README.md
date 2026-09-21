# Loom schedule models

Record model names, schedule bounds, and minimized concurrency regressions
here. Executable Loom tests remain in their owning crate.

`models.toml` lists every model in
`crates/agenc-relay-runtime/tests/loom_models.rs` with its thread count, the
operations it interleaves, the property it asserts, and the Section 27
invariants it supports. The bounds recorded there are set explicitly by the
test through `loom::model::Builder` (`preemption_bound = 2`,
`max_branches = 20000`, no checkpoint file), so an inherited `LOOM_*`
variable cannot weaken a run. Loom is a dev-only dependency of the runtime
crate; it never enters the release graph.

Two scopes appear in `models.toml`:

- `production source under the loom scheduler`: the storage bridge source
  (`crates/agenc-relay-runtime/src/bridge/storage.rs`) is compiled unchanged
  into the test through a `#[path]` module under a loom replacement of the
  crate-local `sync` alias, so every interleaving of its mutex-guarded
  ledger transitions is enumerated.
- `public API under loom threads`: the memory budget, permit, and sink
  reservation types cannot be included the same way because their source
  files carry inline unit tests that construct the alias primitives outside
  a loom model, which loom rejects at run time. Those models drive the
  public API from loom threads and enumerate the thread-level interleavings
  loom can observe around spawn and join.

Minimized regressions go in `regressions/<model>-<n>.md` as an ordered
interleaving paired with a named regression test in the owning crate. There
are none yet.
