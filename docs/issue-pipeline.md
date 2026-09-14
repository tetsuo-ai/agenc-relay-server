# Automated issue execution

The controller follows the dependency graph in [master issue #35](https://github.com/tetsuo-ai/agenc-ircd/issues/35). It runs two issue pipelines concurrently, with at most four fresh Codex sessions and one full validation/merge lane. The installed policy is a private, fixed copy of `.codex/issue-pipeline.toml`; editing a candidate checkout cannot replace the running controller.

The initial deployment uses this Linux machine and its existing `codex login` and `gh auth` credentials. It uses [`codex exec`](https://learn.chatgpt.com/docs/non-interactive-mode), the supported noninteractive CLI interface. Codex's removed MCP-server interface is not a dependency. No additional API key is required for the existing login. Usage is charged against that account's limits; timeouts, bounded attempts and concurrency limits bound individual runs, not total subscription usage.

## Execution and acceptance

1. Read and validate the live master JSON DAG and every native child/blocker relationship. Revalidate the whole prerequisite chain against current issue bodies, task definitions and the exact accepted prerequisite receipt identities. Revoked or replaced proof invalidates dependent completion. Qualification source must include its prerequisites' source. Labels alone are insufficient.
2. Claim the issue's integration scopes. A planner in a detached read-only worktree reads the complete issue, requirements, code and tests. A fresh reviewer checks the plan covers every acceptance criterion. Claim the exact proposed files atomically; overlapping files or scopes wait.
3. Run each phase in its own branch and worktree. Normative contracts merge before dependent implementation phases. A worker edits only declared files, runs focused checks and supplies an acceptance matrix. The controller commits those edits. Workers do not own GitHub mutations, commits or merges.
4. Serialize integration. Refresh `main`, resolve changes and obtain two fresh reviews on the committed candidate: acceptance/specification and security/failure behavior. Rebased or changed source requires new reviews and new gate evidence.
5. Run `AGENC_IRCD_RECORD_GATE=1 bash scripts/check-stage-nine.sh` in one persistent detached validation worktree. Validate the entire recorded artifact, including source, toolchain, manifest, commands and timings, with the repository's evidence checker. Retain the artifact and complete log outside all agent worktrees. Ordinary candidates cannot rewrite the controller, mandatory checker programs or toolchain policy, remove/reorder checks, or lower coverage floors.
6. Publish a PR with receipt hashes only after both reviews and the recorded full gate pass. Evaluate hosted checks separately. Actual failed or pending jobs block merging. This repository currently has zero-job Actions startup failures and no private-plan branch protection; an empty check list is never called passing. The local recorded gate is the configured merge authority while issue #41 tracks hosted CI qualification.
7. Verify the issue/dependencies, candidate and evidence again. Prove the candidate descends from the expected `main` commit, then push with an exact expected-old-ref lease. That compare-and-swap refuses a concurrent base change and cannot rewrite main history. Verify GitHub reports the PR merged at the reviewed source before closing anything.
8. Close the issue only after all phase PRs merge and final acceptance covers the whole issue. Retain immutable receipts and update the master execution-status comment. Delete only the controller-owned, merged branch and worktree. `target/` and `fuzz/target/` are disposable build outputs; unknown files, foreign refs and uncertain work are preserved.

Each model runs in a systemd cgroup with a two-hour timeout, 64 GiB memory ceiling and eight CPU equivalents. The full gate has a three-hour timeout, 256 GiB ceiling and sixteen CPU equivalents. Limits are configurable. Before accepting output, the controller verifies that model processes have stopped and that both the gate launcher and its Docker container have stopped. Docker processes belong to the daemon, so stopping the launcher alone is insufficient. Uncertain gate cleanup stops the controller before another candidate can change the shared validation checkout. Recovery attempts cleanup of all independently verified children before reporting damaged or unresolved ownership records. Separate subagents are separate CLI sessions and worktrees; nested uncontrolled fan-out is disabled.

Model commands use an explicit [Codex permission profile](https://learn.chatgpt.com/docs/permissions). The profile denies general filesystem access, permits the selected worktree and required read-only tools/Git metadata, and provides private temporary and Cargo metadata directories. Shared dependency packages remain read-only. Candidate project configuration is untrusted. Every session runs benign positive and denial controls with the same profile before model work begins. Failure prevents model launch; there is no fallback to broader access. Reviewers receive read access to qualification artifacts only through explicit controller-selected file paths.

The full gate requires the local Docker daemon and the exact image ID pinned in `scripts/issue_pipeline/sandbox.py`; it never pulls an image during a gate. The controller creates an inert container, verifies and durably records its immutable ID, then authorizes execution by that ID. The container runs as the existing user with dropped capabilities, no privilege escalation, a private process namespace and a read-only root. It hides account credentials and host runtime sockets, makes candidate source and existing dependency packages read-only, and exposes the required toolchain, private Cargo cache and controlled build/artifact paths. A private disk-backed home preserves the storage suite's filesystem properties while keeping the `HOME` string unchanged. Before every gate, harmless positive and denial controls verify that the restrictions actually work. Unsupported or ineffective containment blocks execution. New dependency packages require preparation of the private cache before they can be built; candidate code cannot make existing package bodies writable.

Functional storage qualification fixtures use separate private 8 GiB temporary filesystems at `target/tmp` and `target/llvm-cov-target/tmp`. This isolates their filesystem-wide free-space measurements from unrelated host writes. Every gate verifies each mount's independent device, exact capacity, private ownership and writable scratch controls. The daemon's private home, general temporary directory and package storage scratch remain disk-backed. These functional checks do not replace native release filesystem qualification.

The gate log has a hard 64 MiB file-size limit on both attach/forwarding clients; duplicate Docker daemon logging is disabled. Gate and model monitors check free disk every second while outputs are written and stop at the configured reserve. Failed attempts retain their output for diagnosis. Host evidence validation loads only the exact protected checker files and never adds candidate directories to Python's import search path.

The controller stores SQLite WAL checkpoints, claims, model transcripts, proof hashes and remote-action intent under `~/.local/state/agenc-ircd-pipeline`. On restart it stops recorded launcher units, then reconciles their containers even when a launcher unit has already disappeared. Container cleanup verifies private ownership records, immutable IDs, image identity and all labels; a successful daemon query must prove absence. It never prunes unrelated containers. Ambiguous remote responses are read back; an uncertain PR creation or merge pauses its issue instead of blindly repeating it. Failed checks get at most three worker attempts per phase. Exhausted or ambiguous work remains inspectable and appears in the master status comment. It is not deleted or called complete.

Branch pushes and deletion have durable local journals, including recovery after a worktree has already been removed. An interruption between a new worktree, commit or rebase and its ownership-ledger update is preserved for inspection; the controller does not adopt an unexpectedly changed Git head. This is an explicit recovery handoff, rather than permission to discard unverified work.

Confirmed container removal has a terminal receipt bound to its immutable ID; restart does not repeatedly query the daemon for completed gates. An ambiguous create response cannot authorize a start and retains its attempt for reconciliation. Agent launch intent is fsynced before dispatch, actual registration is recorded from the owned unit, and successful cleanup has a terminal receipt. An abrupt crash cannot erase unresolved intent merely by bypassing an exception handler. Unresolved or legacy launch records retain their worktrees and block restart after other known children are stopped. Keep the service stopped and inspect the exact recorded unit, client process and systemd journal; only retire uncertain records after independently establishing that no submitted launch can still run. A currently absent unit is insufficient by itself.

## Installation and operation

Install from the clean, committed source revision that passed the full gate:

```sh
python3 scripts/test-issue-pipeline.py
python3 scripts/issue-pipeline.py --config .codex/issue-pipeline.toml doctor
python3 scripts/issue-pipeline.py --config .codex/issue-pipeline.toml install --source-commit "$(git rev-parse HEAD)"
systemctl --user enable --now agenc-ircd-issue-pipeline.service
```

The installer creates a content-addressed bundle under `~/.local/share/agenc-ircd-pipeline/releases/`, a private configuration file, and a stopped user service. It neither changes account credentials nor activates itself. Installation does not establish test evidence: the setup/upgrade PR must receive its own independent review and full gate before activation. Controller/policy upgrades require this same explicit release procedure and cannot self-install through ordinary issue work.

At startup, the controller holds the supervisor lock, reconciles owned children, and prepares `state_dir/gate-cache/cargo` before admitting its first agent session. It seeds only public crates.io registry data from the existing Cargo cache and creates the exact read-only permission controls; host credentials, Cargo configuration and private dependencies are excluded. No earlier gate or manual cache initialization is required. Repeated starts validate the controls without copying the host cache again. Invalid controls or an interrupted `.seed-*` copy block dispatch and remain available for inspection. Keep the service stopped while investigating a retained partial copy; only remove that partial staging directory after confirming no owned child or cache-copy process is still running. Preparation bounds each registry inventory and the total copy deadline, so automatic service restarts cannot accumulate partial copies.

Useful commands from a repository checkout:

```sh
python3 scripts/issue-pipeline.py status
python3 scripts/issue-pipeline.py plan
python3 scripts/issue-pipeline.py pause
python3 scripts/issue-pipeline.py resume
journalctl --user -u agenc-ircd-issue-pipeline.service -f
systemctl --user stop agenc-ircd-issue-pipeline.service
python3 scripts/issue-pipeline.py retry 36
systemctl --user start agenc-ircd-issue-pipeline.service
```

`pause` stops dispatching new tasks; `stop` cancels current sessions and retains checkpoints. Stop the service before retrying a blocked issue or importing specialized qualification evidence. User services survive logout/reboot only if the account's user manager remains running (for example, user lingering is enabled). Disk must remain above the configured 256 GiB floor; the persistent full gate cache can itself exceed 200 GiB. Do not place it in `/tmp` or delete its active files. Back up the state directory: GitHub issue closure is deliberately insufficient to reconstruct lost acceptance receipts.

Legacy and master closure have their own immutable preparation, publication intent and terminal receipts. Both eligible closures bind the graph, aggregate requirements and accepted prerequisite receipts before the status comment changes. The master also binds the exact accepted legacy terminal receipt. Publication and closure are read back against those original bindings; an interrupted response resumes the same intent. Completed legacy evidence remains valid across unrelated backlog additions while its own requirements and transitive prerequisite evidence remain unchanged. A stale task completion is displayed as `completion evidence invalid` and is not silently rescheduled.

If aggregate evidence changes, the controller journals a blocked reconciliation and reopens only aggregates that its durable close-attempt provenance authorizes. It attempts both owned aggregates even when one reopen remains uncertain. Keep the service stopped while investigating the retained `aggregate_closure` checkpoint and its immutable receipts. After independently restoring the original requirements, native links and accepted evidence, `retry 13` and/or `retry 35` permit reconciliation of the same intent; they do not approve changed requirements or replace receipt bindings. An externally closed aggregate without controller close provenance is neither adopted nor reopened automatically. Changed acceptance that cannot restore the original binding requires an explicit reviewed operator handoff; preserve the old journal and receipts rather than deleting them to force dispatch. Startup repairs approved discovery journals before checking aggregate closures, so interrupted graph publication can finish first.

## Specialized qualification and new discoveries

Upstream redb fixes, native release runs, service-user checks, independent encryption review and signing tasks use explicit specialized routes. Their handoff includes the live issue and source. The controller does not substitute a generic repository PR or a model's opinion for the required environment, external review or signature. It continues unrelated ready work and keeps the qualification issue open.

After an operator has obtained and checked the actual qualification, `accept-external ISSUE --evidence FILE` imports an explicit attestation. This command is never called by an agent. Its JSON schema is:

```json
{
  "version": 1,
  "issue": 43,
  "route": "host",
  "source": "FULL_40_CHARACTER_COMMIT_SHA",
  "approver": "Name and qualification role",
  "qualification_url": "https://github.com/tetsuo-ai/agenc-ircd/issues/43#issuecomment-EVIDENCE",
  "acceptance": [{"criterion": "Exact issue acceptance requirement", "evidence": "Observed result and artifact location"}],
  "artifacts": [{"path": "/absolute/path/to/qualification.json", "sha256": "FULL_SHA256"}]
}
```

Every acceptance requirement must be included. JSON is limited to 1 MiB, with at most 64 artifacts, 8 GiB per artifact and 32 GiB total. Artifact paths must be absolute ordinary files with lowercase SHA-256 hashes. The importer checks the task route, dependency proof, source ancestry and artifact hashes, preserves the artifacts, and explicitly identifies the human attestation on GitHub. These structural checks cannot establish the scientific or security adequacy of an external review: that remains the named approver's responsibility. Keep release-bound evidence tied to the release candidate specified by the issue. If an import is interrupted or its GitHub response is uncertain, leave the service stopped and repeat `python3 scripts/issue-pipeline.py accept-external ISSUE --evidence /absolute/path/to/the-original-import.json`. Use the identical JSON; its retained artifacts and receipt are reused, and an already-closed issue is read back. The task stays blocked until this explicit import completes. Ordinary `retry ISSUE` does not resume an import. Interrupted copies never publish partial final artifacts; mismatched retained evidence is preserved and rejected for operator inspection.

Workers report newly required work as discoveries. A fresh reviewer checks each claim against source and a complete snapshot of the current managed backlog, including full issue bodies and closed tasks. The immutable snapshot is limited to 16 MiB and granted through one exact read-only file; repository issues outside the master DAG and its legacy umbrella are outside that stated review scope. Changed coverage requires a fresh review before a new registration begins. The controller then creates a detailed prerequisite, adds native links, and updates master ordering, locks and counts. A durable queue preserves every proposed discovery, its accepted review and backlog snapshot, and registration progress across interruption. Existing registration journals resume with their original approval; missing or damaged proof blocks recovery. Explicit `retry` resets only the remaining discovery review budgets and preserves completed entries and evidence. A durable journal makes each publication step reconcilable. Our writers share one graph lock; GitHub issue-body edits have no atomic version precondition, so unrelated writers must not concurrently edit the master during a graph update. Detected divergent edits stop reconciliation and preserve the journal. Vulnerability reports still follow `SECURITY.md`.

## Limits of automation

Passing checks and model reviews do not prove absence of defects. Independent reviews use separate contexts but may share a model's blind spots. The pipeline enforces evidence and ordering; it cannot manufacture native machines, upstream authority, third-party review or release-signing authority. Blocked issues and retained diagnostics are explicit handoffs, not silent success. The server becomes production-ready only when the final release issue and all its prerequisites have actual accepted qualification evidence.
