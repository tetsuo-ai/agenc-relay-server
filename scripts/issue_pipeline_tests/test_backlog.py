"""Offline discovery registration, publication ambiguity and restart reconciliation."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from issue_pipeline.backlog import Backlog, BacklogError, MasterBlockerInvalid
from issue_pipeline.graph import Graph
from issue_pipeline_tests.test_github import issue_row


REVIEW = {"verdict": "approve", "summary": "Independent source inspection confirms the missing bound.",
          "findings": [], "acceptance_complete": True, "contract_separated": True}
DISCOVERY = {"title": "Bound request decoding before allocation", "description":
             "src/service.rs:42 allocates from an unchecked peer length. The accepted contract caps it at 4096 bytes. "
             "A 4097-byte request currently allocates first; refusal must happen before allocation.",
             "acceptance": ["Accept exactly 4096 bytes.", "Reject 4097 bytes before allocation."]}
SOURCE = "b" * 40


def record():
    return {"version": 1, "source": "a" * 40, "master_issue": 35, "final_issue": 86,
            "lock_policy": "Claim scopes and exact files.",
            "legacy_umbrella": {"issue": 13, "depends_on": [36]},
            "tasks": [{"key": "ENC-01", "issue": 36, "depends_on": [], "locks": ["normative"],
                       "external_gate": False, "level": 0},
                      {"key": "RUN-01", "issue": 41, "depends_on": [36], "locks": ["runtime", "tests"],
                       "external_gate": False, "level": 1},
                      {"key": "REL-13", "issue": 86, "depends_on": [41], "locks": ["signing"],
                       "external_gate": True, "level": 2}]}


def master_body():
    return ("Current execution plan: **3 actionable work items, 2 prerequisite edges, and 3 dependency levels**.\n\n"
            "Audited inventory: **782 production-inventory files, 244 requirement records, and all 103 historical findings**.\n\n"
            "Completion requires all 3 children and the legacy issue closed with evidence.\n\n"
            "## Ordered backlog\n\nRows follow prerequisite order.\n\n"
            "| Order | Level | Work item | Must finish first |\n|---:|---:|---|---|\n"
            "| 1 | 0 | [ENC-01 #36](https://github.com/example/private/issues/36): Define contract | Ready |\n"
            "| 2 | 1 | [RUN-01 #41](https://github.com/example/private/issues/41): Implement decoder | #36 |\n"
            "| 3 | 2 | [REL-13 #86](https://github.com/example/private/issues/86): Release acceptance | #41 |\n\n"
            "## Completion checklist\n\n- [x] #36\n- [ ] #41\n- [ ] #86\n- [ ] #13 — legacy umbrella\n\n"
            "## Machine-readable scheduling graph\n\nThis is the initial audited DAG.\n\n```json\n"
            + json.dumps(record()) + "\n```\n")


class Crash(BaseException):
    """Simulate process death after GitHub applied a mutation."""


class FakeGithub:
    repo = "example/private"

    def __init__(self):
        self.issues = {number: {"number": number, "id": number + 1000, "state": "open",
                                "title": f"Issue {number}", "body": f"Original issue {number} acceptance."}
                       for number in (13, 35, 36, 41, 86)}
        self.issues[35]["body"] = master_body()
        self.child_links = {35: {13, 36, 41, 86}}
        self.dependencies = {35: set(), 13: {36}, 36: set(), 41: {36}, 86: {41}}
        self.mutations = []
        self.after = None
        self.before = None
        self.next_issue = 90

    def issue(self, number):
        return {**issue_row(number, self.repo), **copy.deepcopy(self.issues[number])}

    def children(self, number):
        return [self.issue(child) for child in sorted(self.child_links.get(number, set()))]

    def blockers(self, number):
        return [self.issue(child) for child in sorted(self.dependencies.get(number, set()))]

    def api(self, path, method="GET", data=None):
        if method == "GET" and path.startswith("issues?"):
            page = int(path.rsplit("page=", 1)[1])
            return [self.issue(number) for number in sorted(self.issues, reverse=True)][(page - 1) * 100:page * 100]
        self.mutations.append((path, method, copy.deepcopy(data)))
        if self.before:
            self.before(path, method, data)
        if path == "issues" and method == "POST":
            number = self.next_issue
            self.next_issue += 1
            self.issues[number] = {"number": number, "id": number + 1000, "state": "open", **data}
            result = self.issue(number)
        elif path.endswith("sub_issues"):
            owner = int(path.split("/")[1])
            child = next(number for number, issue in self.issues.items() if issue["id"] == data["sub_issue_id"])
            self.child_links.setdefault(owner, set()).add(child)
            result = self.issue(child)
        elif path.endswith("dependencies/blocked_by"):
            owner = int(path.split("/")[1])
            child = next(number for number, issue in self.issues.items() if issue["id"] == data["issue_id"])
            self.dependencies.setdefault(owner, set()).add(child)
            result = self.issue(child)
        elif method == "PATCH":
            owner = int(path.split("/")[1])
            self.issues[owner].update(data)
            result = self.issue(owner)
        else:
            raise AssertionError((path, method, data))
        if self.after:
            self.after(path, method, data)
        return result


class BacklogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.github = FakeGithub()
        self.backlog = Backlog(self.github, self.state, 35)

    def register(self, **kwargs):
        return self.backlog.register(kwargs.get("parent", 41), kwargs.get("discovery", DISCOVERY),
                                     kwargs.get("source", SOURCE), kwargs.get("review", REVIEW))

    def journal(self):
        paths = list((self.state / "backlog").glob("*.json"))
        self.assertEqual(len(paths), 1)
        return paths[0], json.loads(paths[0].read_text())

    def assert_registration(self, number=90):
        graph = Graph.from_master(self.github.issues[35]["body"])
        task = graph.by_issue[number]
        self.assertEqual(task.key, "FIX-01")
        self.assertEqual(task.depends_on, (36,))
        self.assertEqual(task.locks, ("runtime", "tests"))
        self.assertIn(number, graph.by_issue[41].depends_on)
        self.assertEqual(graph.by_issue[41].level, 2)
        self.assertEqual(graph.by_issue[86].level, 3)
        self.assertEqual(self.github.dependencies[number], {36})
        self.assertEqual(self.github.dependencies[41], {36, number})
        self.assertIn(number, self.github.child_links[35])
        self.assertIn(f"FIX-01 #{number} must close", self.github.issues[41]["body"])
        graph.validate_native_links(self.github.child_links[35], self.github.dependencies)

    def test_registers_detailed_reviewed_child_and_synchronized_master(self):
        self.assertEqual(self.register(), 90)
        self.assert_registration()
        body = self.github.issues[90]["body"]
        self.assertIn(DISCOVERY["description"], body)
        self.assertIn(SOURCE, body)
        self.assertTrue(all(criterion in body for criterion in DISCOVERY["acceptance"]))
        master = self.github.issues[35]["body"]
        self.assertIn("**4 actionable work items, 4 prerequisite edges, and 4 dependency levels**", master)
        self.assertIn("Original audited backlog snapshot: 3 work items, 2 prerequisite edges, 3 dependency levels.", master)
        self.assertIn("**782 production-inventory files, 244 requirement records, and all 103 historical findings**", master)
        self.assertIn("Completion requires all 4 children", master)
        self.assertIn("- [x] #36", master)
        self.assertIn("- [ ] #90", master)
        self.assertLess(master.index("[FIX-01 #90]"), master.index("[RUN-01 #41]"))
        path, journal = self.journal()
        self.assertEqual(journal["status"], "complete")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_managed_master_blockers_are_valid_during_registration(self):
        self.github.dependencies[35] = {13, 36, 86}
        self.assertEqual(self.register(), 90)
        self.assert_registration()

    def add_unmanaged_master_blocker(self):
        self.github.issues[99] = {"number": 99, "id": 1099, "state": "open", "title": "Unmanaged", "body": "Additional acceptance"}
        self.github.dependencies[35] = {99}

    def test_unmanaged_master_blocker_prevents_new_registration(self):
        self.add_unmanaged_master_blocker()
        with self.assertRaises(BacklogError):
            self.register()
        self.assertEqual(self.github.mutations, [])
        self.assertEqual(list(self.backlog.directory.glob("*.json")), [])

    def test_master_blocker_inserted_after_creation_stops_replay_before_further_writes(self):
        def change(path, method, data):
            if path == "issues":
                self.add_unmanaged_master_blocker()
        self.github.after = change
        with self.assertRaisesRegex(BacklogError, "master blocker"):
            self.register()
        self.github.after = None
        self.assertEqual([m[0] for m in self.github.mutations], ["issues"])
        with self.assertRaisesRegex(BacklogError, "master blocker"):
            Backlog(self.github, self.state, 35).reconcile()
        self.assertEqual([m[0] for m in self.github.mutations], ["issues"])
        self.github.dependencies[35] = set()
        self.assertEqual(Backlog(self.github, self.state, 35).reconcile(), [90])
        self.assert_registration()

    def test_master_blocker_added_at_final_body_write_prevents_completed_journal(self):
        def change(path, method, data):
            if path == "issues/35" and method == "PATCH":
                self.add_unmanaged_master_blocker()
        self.github.after = change
        with self.assertRaisesRegex(BacklogError, "master blocker"):
            self.register()
        self.assertEqual(self.journal()[1]["status"], "pending")
        self.github.after = None
        self.github.dependencies[35] = set()
        count = len(self.github.mutations)
        self.assertEqual(Backlog(self.github, self.state, 35).reconcile(), [90])
        self.assertEqual(len(self.github.mutations), count)
        self.assert_registration()

    def test_lost_create_response_allows_exact_prospective_child_as_master_blocker(self):
        def crash(path, method, data):
            if path == "issues":
                self.github.dependencies[35] = {90}
                self.github.child_links[35].add(90)
                raise Crash()
        self.github.after = crash
        with self.assertRaises(Crash):
            self.register()
        self.assertIsNone(self.journal()[1]["child"])
        self.github.after = None
        self.assertEqual(Backlog(self.github, self.state, 35).reconcile(), [90])
        self.assertEqual(sum(m[0] == "issues" for m in self.github.mutations), 1)
        self.assert_registration()

    def test_changed_prospective_child_does_not_authorize_a_new_master_blocker(self):
        def crash(path, method, data):
            if path == "issues":
                self.github.dependencies[35] = {90}
                self.github.issues[90]["body"] += " Unreviewed additional requirements."
                raise Crash()
        self.github.after = crash
        with self.assertRaises(Crash):
            self.register()
        self.github.after = None
        with self.assertRaisesRegex(BacklogError, "master blocker"):
            Backlog(self.github, self.state, 35).reconcile()
        self.assertEqual(len(self.github.mutations), 1)

    def test_confirmed_master_identity_revocation_is_typed_during_pending_replay(self):
        self.github.after = lambda *args: (_ for _ in ()).throw(Crash())
        with self.assertRaises(Crash):
            self.register()
        self.github.after = None
        blockers = self.github.blockers
        for rows in ([issue_row(36, "foreign/private")], [self.github.issue(36), self.github.issue(36)],
                     [issue_row(36, self.github.repo, node_id="I_other")]):
            with self.subTest(rows=rows), mock.patch.object(self.github, "blockers", side_effect=lambda n: rows if n == 35 else blockers(n)):
                with self.assertRaises(MasterBlockerInvalid):
                    Backlog(self.github, self.state, 35).reconcile()
        self.assertEqual(len(self.github.mutations), 1)

    def test_exact_registration_replays_but_changed_source_or_review_is_refused(self):
        number = self.register()
        mutations = copy.deepcopy(self.github.mutations)
        self.assertEqual(self.register(), number)
        for arguments in ({"source": "c" * 40}, {"review": {**REVIEW, "summary": "Another approval"}}):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(BacklogError, "different approved intent"):
                self.register(**arguments)
        self.assertEqual(self.github.mutations, mutations)
        self.assertEqual(self.backlog.reconcile(), [])

    def prepare_unpublished_registration(self):
        with mock.patch.object(self.backlog, "_resume", side_effect=Crash("prepared, before publication")):
            with self.assertRaises(Crash):
                self.register()
        self.assertEqual(self.github.mutations, [])
        return self.journal()

    def test_fresh_registration_cannot_replay_another_prepared_journal_after_coverage_review(self):
        path, _ = self.prepare_unpublished_registration()
        raw = path.read_bytes()
        original_issues = copy.deepcopy(self.github.issues)
        with self.assertRaisesRegex(BacklogError, "reconcile existing discovery journals"):
            self.register(discovery={**DISCOVERY, "title": "A separately reviewed proposed prerequisite"})
        self.assertEqual(self.github.issues, original_issues)
        self.assertEqual(self.github.mutations, [])
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(list(self.backlog.directory.glob("*.json")), [path])
        # The exact original approval remains resumable; refusal did not adopt,
        # rewrite or abandon its durable publication intent.
        self.assertEqual(self.register(), 90)
        self.assert_registration()

    def test_pending_descriptors_are_read_only_and_bound_to_exact_approved_identity(self):
        path, journal = self.prepare_unpublished_registration()
        raw = path.read_bytes()
        self.assertEqual(self.backlog.pending_registrations(), [{"path": str(path), "parent": 41,
            "discovery": DISCOVERY, "source": SOURCE, "review": REVIEW}])
        self.assertEqual(path.read_bytes(), raw)
        for changes in ({"source": "HEAD"}, {"parent": True}, {"status": "unknown"},
                        {"discovery": {**DISCOVERY, "title": "Another identity"}},
                        {"review": {**REVIEW, "verdict": "request_changes", "acceptance_complete": False}}):
            with self.subTest(changes=changes):
                path.write_text(json.dumps({**journal, **changes}))
                changed = path.read_bytes()
                with self.assertRaises(BacklogError):
                    self.backlog.pending_registrations()
                self.assertEqual(path.read_bytes(), changed)
        self.assertEqual(self.github.mutations, [])

    def test_registration_started_is_read_only_and_bound_to_original_approval(self):
        self.assertFalse(self.backlog.registration_started(41, DISCOVERY, SOURCE, REVIEW))
        self.assertEqual(self.github.mutations, [])
        self.register()
        mutations = copy.deepcopy(self.github.mutations)
        self.assertTrue(self.backlog.registration_started(41, DISCOVERY, SOURCE, REVIEW))
        self.assertFalse(self.backlog.registration_started(41, {**DISCOVERY, "title": "Different work"}, SOURCE, REVIEW))
        for source, review in (("c" * 40, REVIEW), (SOURCE, {**REVIEW, "summary": "Another review"})):
            with self.subTest(source=source, review=review):
                with self.assertRaisesRegex(BacklogError, "different approved intent"):
                    self.backlog.registration_started(41, DISCOVERY, source, review)
        self.assertEqual(self.github.mutations, mutations)

    def test_registration_started_recognizes_prepared_journal_without_remote_mutations(self):
        def before(path, method, data):
            raise Crash("before the provider applied creation")
        self.github.before = before
        with self.assertRaises(Crash):
            self.register()
        self.assertEqual(self.github.next_issue, 90)
        mutations = copy.deepcopy(self.github.mutations)
        self.assertTrue(self.backlog.registration_started(41, DISCOVERY, SOURCE, REVIEW))
        self.assertEqual(self.github.mutations, mutations)

    def test_different_discovery_gets_next_key_and_preserves_audit_snapshot(self):
        self.register()
        discovery = {**DISCOVERY, "title": "Bound response encoding"}
        self.assertEqual(self.register(discovery=discovery), 91)
        graph = Graph.from_master(self.github.issues[35]["body"])
        self.assertEqual(graph.by_issue[91].key, "FIX-02")
        self.assertEqual(set(graph.by_issue[91].depends_on), {36, 90})
        self.assertEqual(self.github.issues[35]["body"].count("Original audited backlog snapshot:"), 1)
        self.assertIn("snapshot: 3 work items, 2 prerequisite edges, 3 dependency levels.", self.github.issues[35]["body"])

    def test_nonapproving_or_malformed_review_never_mutates(self):
        for field, value in (("verdict", "blocked"), ("acceptance_complete", False),
                             ("contract_separated", 1), ("findings", [{}])):
            review = {**REVIEW, field: value}
            with self.subTest(field=field), self.assertRaises(BacklogError):
                self.register(review=review)
        self.assertEqual(self.github.mutations, [])

    def test_bad_discovery_source_parent_and_master_layout_fail_before_create(self):
        for arguments in ({"source": "HEAD"}, {"source": True}, {"discovery": {**DISCOVERY, "acceptance": []}},
                          {"discovery": {**DISCOVERY, "title": "two\nlines"}}, {"parent": True}):
            with self.subTest(arguments=arguments), self.assertRaises(BacklogError):
                self.register(**arguments)
        self.github.issues[35]["body"] = self.github.issues[35]["body"].replace("## Ordered backlog", "## Unstructured backlog")
        with self.assertRaises(BacklogError):
            self.register()
        self.assertEqual(self.github.mutations, [])

    def test_closed_parent_and_native_drift_block_registration(self):
        self.github.issues[41]["state"] = "closed"
        with self.assertRaises(BacklogError):
            self.register()
        self.github.issues[41]["state"] = "open"
        self.github.dependencies[41].clear()
        with self.assertRaises(BacklogError):
            self.register()
        self.assertEqual(self.github.mutations, [])

    def test_every_mutation_has_durable_intent_before_network_write(self):
        intents = []
        def inspect(path, method, data):
            _, journal = self.journal()
            intents.append(journal["intent"])
            self.assertNotEqual(journal["status"], "complete")
        self.github.before = inspect
        self.register()
        self.assertEqual(len(intents), 6)
        self.assertEqual(intents[0], "create_issue")
        self.assertEqual(intents[-1], "body:35")

    def test_applied_but_lost_mutation_responses_reconcile_without_repeating_posts(self):
        def lost_response(path, method, data):
            raise ConnectionError("transport lost response after GitHub applied request")
        self.github.after = lost_response
        self.assertEqual(self.register(), 90)
        self.assert_registration()
        self.assertEqual(len(self.github.mutations), 6)

    def test_registration_rejects_foreign_or_wrong_id_links_before_any_write(self):
        for relationship in ("children", "blockers"):
            reader = getattr(self.github, relationship)
            for replacement in (issue_row(36, "foreign/private"), issue_row(36, id=9000),
                                issue_row(36, node_id="I_another_issue")):
                def altered(number):
                    return [replacement if row["number"] == 36 else row for row in reader(number)]
                with self.subTest(relationship=relationship, replacement=replacement), \
                        mock.patch.object(self.github, relationship, side_effect=altered):
                    with self.assertRaisesRegex(BacklogError, "identity"):
                        self.register()
                self.assertEqual(self.github.mutations, [])
                self.assertEqual(list(self.backlog.directory.iterdir()), [])

    def test_restart_does_not_adopt_matching_number_with_foreign_or_changed_identity(self):
        for replacement in (issue_row(90, "foreign/private"), issue_row(90, id=9000),
                            issue_row(90, node_id="I_another_issue")):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                github = FakeGithub()
                backlog = Backlog(github, Path(directory), 35)
                github.after = lambda *args: (_ for _ in ()).throw(Crash())
                with self.assertRaises(Crash):
                    backlog.register(41, DISCOVERY, SOURCE, REVIEW)
                github.after = None
                children = github.children
                with mock.patch.object(github, "children", side_effect=lambda number: children(number) + [replacement]):
                    with self.assertRaisesRegex(BacklogError, "identity"):
                        Backlog(github, Path(directory), 35).reconcile()
                self.assertEqual(len(github.mutations), 1)
                journal = json.loads(next(backlog.directory.glob("*.json")).read_text())
                self.assertEqual(journal["status"], "pending")
                self.assertNotIn(90, github.child_links[35])

    def test_lost_link_response_requires_the_exact_pinned_target_identity(self):
        for replacement in (issue_row(90, "foreign/private"), issue_row(90, id=9000),
                            issue_row(90, node_id="I_another_issue")):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                github = FakeGithub()
                backlog = Backlog(github, Path(directory), 35)
                attempted = []
                def failed_link(path, method, data):
                    if path.endswith("sub_issues"):
                        attempted.append(path)
                        raise ConnectionError("ambiguous link response")
                github.before = failed_link
                children = github.children
                with mock.patch.object(github, "children", side_effect=lambda number: children(number) + (
                        [replacement] if attempted else [])):
                    with self.assertRaisesRegex(BacklogError, "identity"):
                        backlog.register(41, DISCOVERY, SOURCE, REVIEW)
                self.assertEqual([entry[0] for entry in github.mutations], ["issues", "issues/35/sub_issues"])
                journal = json.loads(next(backlog.directory.glob("*.json")).read_text())
                self.assertEqual(journal["status"], "pending")
                self.assertNotIn(90, github.child_links[35])

    def test_restart_recovers_after_each_remote_mutation_boundary(self):
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                github = FakeGithub()
                backlog = Backlog(github, Path(directory), 35)
                def crash(path, method, data):
                    if len(github.mutations) == boundary:
                        raise Crash()
                github.after = crash
                with self.assertRaises(Crash):
                    backlog.register(41, DISCOVERY, SOURCE, REVIEW)
                github.after = None
                restarted = Backlog(github, Path(directory), 35)
                self.assertEqual(restarted.reconcile(), [90])
                self.assertEqual(len(github.mutations), 6)
                self.assertEqual(restarted.reconcile(), [])
                graph = Graph.from_master(github.issues[35]["body"])
                graph.validate_native_links(github.child_links[35], github.dependencies)

    def test_unknown_create_outcome_without_visible_marker_never_repeats_post(self):
        self.github.before = lambda *args: (_ for _ in ()).throw(ConnectionError("request may not have reached server"))
        with self.assertRaisesRegex(BacklogError, "ambiguous"):
            self.register()
        self.github.before = None
        with self.assertRaisesRegex(BacklogError, "do not repeat POST"):
            self.backlog.reconcile()
        self.assertEqual(len(self.github.mutations), 1)
        _, journal = self.journal()
        self.assertTrue(journal["create_started"])
        self.assertIsNone(journal["child"])

    def test_duplicate_marker_matches_require_manual_reconciliation(self):
        def duplicate(path, method, data):
            if path == "issues":
                self.github.issues[91] = {**copy.deepcopy(self.github.issues[90]), "number": 91, "id": 1091}
                raise ConnectionError("ambiguous duplicate issue")
        self.github.after = duplicate
        with self.assertRaises(BacklogError):
            self.register()
        self.github.after = None
        with self.assertRaisesRegex(BacklogError, "multiple issues"):
            self.backlog.reconcile()
        self.assertEqual(len(self.github.mutations), 1)

    def test_changed_master_or_parent_preserves_unrelated_edit_and_journal(self):
        for changed in (35, 41):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                github = FakeGithub()
                backlog = Backlog(github, Path(directory), 35)
                def edit_after_create(path, method, data):
                    if path == "issues":
                        github.issues[changed]["body"] += "\nUnrelated human edit."
                github.after = edit_after_create
                with self.assertRaisesRegex(BacklogError, "changed since discovery preparation"):
                    backlog.register(41, DISCOVERY, SOURCE, REVIEW)
                self.assertTrue(github.issues[changed]["body"].endswith("Unrelated human edit."))
                self.assertEqual(len(github.mutations), 1)
                self.assertEqual(len(list((Path(directory) / "backlog").glob("*.json"))), 1)

    def test_specialized_parent_discovery_cannot_become_generic_repository_work(self):
        number = self.register(parent=86)
        graph = Graph.from_master(self.github.issues[35]["body"])
        self.assertTrue(graph.by_issue[number].external_gate)
        self.assertEqual(graph.by_issue[number].route, "external")
        self.assertIn("Inherited execution route:** external", self.github.issues[number]["body"])


if __name__ == "__main__":
    unittest.main()
