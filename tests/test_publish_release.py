from __future__ import annotations

import copy
import urllib.error
import unittest
from unittest import mock

from tools.publish_release import (
    GitHub,
    gate,
    load_policy,
    publish,
    tag_commit,
    validate_policy,
    workflow_gaps,
)


TARGET = "a" * 40
OLD = "b" * 40


class FakeGitHub:
    def __init__(self, runs, policy):
        self.runs = runs
        self.policy = policy
        self.main = TARGET
        self.reference = None
        self.release = None
        self.commands = []

    def get(self, path, *, optional=False):
        if path == "/git/ref/heads/main":
            return {"object": {"sha": self.main}}
        if path.startswith("/actions/runs?"):
            page = int(path.rsplit("=", 1)[1])
            return {"workflow_runs": self.runs[(page - 1) * 100 : page * 100]}
        if path.startswith("/git/ref/tags/"):
            return self.reference
        if path.startswith("/releases/tags/"):
            return self.release
        if path.startswith("/git/tags/"):
            return {"object": {"type": "commit", "sha": OLD}}
        raise AssertionError(path)

    def command(self, command, **kwargs):
        if kwargs.get("check") is not True or kwargs.get("capture_output") is not True:
            raise AssertionError("publication commands must be checked and captured")
        self.commands.append(command)
        if command[:2] == ["gh", "api"]:
            if "PATCH" in command:
                raise AssertionError("tag updates are prohibited")
            self.reference = {"object": {"type": "commit", "sha": TARGET}}
        else:
            if "--verify-tag" not in command:
                raise AssertionError("release must verify the existing tag")
            from tools.publish_release import ROOT

            self.release = {
                "tag_name": "v1.0.0",
                "name": self.policy["release_title"],
                "draft": False,
                "prerelease": False,
                "body": (ROOT / self.policy["notes_path"]).read_text(encoding="utf-8"),
            }


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()
        self.runs = [
            {
                "id": index + 1,
                "name": name,
                "path": path,
                "head_sha": TARGET,
                "head_branch": "main",
                "head_repository": {"full_name": self.policy["repository"]},
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "run_attempt": 1,
            }
            for index, (path, name) in enumerate(self.policy["required_workflows"].items())
        ]

    def api(self, runs=None):
        return FakeGitHub(self.runs if runs is None else runs, self.policy)

    def published_release(self):
        from tools.publish_release import ROOT

        return {
            "tag_name": "v1.0.0",
            "name": self.policy["release_title"],
            "draft": False,
            "prerelease": False,
            "body": (ROOT / self.policy["notes_path"]).read_text(encoding="utf-8"),
        }

    def test_policy_matches_stable_gate_and_governance_contexts(self):
        self.assertEqual(self.policy["release_version"], "1.0.0")
        self.assertFalse(self.policy["prerelease"])
        self.assertFalse(self.policy["package_index_publication_authorized"])
        self.assertFalse(self.policy["deployment_authorized"])
        self.assertEqual(len(self.policy["required_workflows"]), 9)
        self.assertEqual(len(self.policy["required_check_contexts"]), 11)

    def test_all_exact_main_push_workflows_are_required(self):
        self.assertEqual(workflow_gaps(self.runs, self.policy, TARGET), [])
        self.assertEqual(gate(self.api(), self.policy, TARGET), [])
        self.assertTrue(workflow_gaps(self.runs[:-1], self.policy, TARGET))

    def test_untrusted_missing_or_non_successful_runs_block_publication(self):
        cases = [
            ("head_sha", OLD),
            ("head_branch", "agent/untrusted"),
            ("head_repository", {"full_name": "untrusted/fork"}),
            ("event", "pull_request"),
            ("path", ".github/workflows/other.yml"),
            ("name", "Other"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("conclusion", "cancelled"),
            ("conclusion", "skipped"),
            ("conclusion", None),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                runs = copy.deepcopy(self.runs)
                runs[0][field] = value
                api = self.api(runs)
                with self.assertRaisesRegex(ValueError, "publication blocked"):
                    publish(api, self.policy, TARGET, api.command)
                self.assertEqual(api.commands, [])

    def test_new_failed_run_or_incomplete_rerun_overrides_success(self):
        newer = dict(self.runs[0], id=50, conclusion="failure")
        self.assertTrue(workflow_gaps([*self.runs, newer], self.policy, TARGET))
        rerun = dict(self.runs[0], run_attempt=2, status="queued", conclusion=None)
        self.assertTrue(workflow_gaps([*self.runs, rerun], self.policy, TARGET))

    def test_main_moving_short_sha_and_pagination_fail_closed(self):
        api = self.api()
        api.main = OLD
        with self.assertRaisesRegex(ValueError, "current main SHA"):
            publish(api, self.policy, TARGET, api.command)
        with self.assertRaisesRegex(ValueError, "exact 40-character SHA"):
            gate(self.api(), self.policy, TARGET[:7])
        unrelated = dict(self.runs[0], path=".github/workflows/other.yml")
        self.assertEqual(gate(self.api([unrelated] * 100 + self.runs), self.policy, TARGET), [])

    def test_new_release_creates_tag_once_and_is_idempotent(self):
        api = self.api()
        self.assertIn("Published v1.0.0", publish(api, self.policy, TARGET, api.command))
        self.assertEqual(len(api.commands), 2)
        self.assertIn("sha=" + TARGET, api.commands[0])
        self.assertIn("--verify-tag", api.commands[1])
        self.assertIn("no writes", publish(api, self.policy, TARGET, api.command))
        self.assertEqual(len(api.commands), 2)

    def test_existing_release_is_retained_but_never_moved_or_edited(self):
        api = self.api()
        api.reference = {"object": {"type": "commit", "sha": OLD}}
        api.release = self.published_release()
        self.assertIn(OLD, publish(api, self.policy, TARGET, api.command))
        self.assertEqual(api.commands, [])

    def test_annotated_existing_tag_is_resolved_without_writing(self):
        api = self.api()
        api.reference = {"object": {"type": "tag", "sha": "c" * 40}}
        api.release = self.published_release()
        self.assertIn(OLD, publish(api, self.policy, TARGET, api.command))
        self.assertEqual(api.commands, [])

    def test_orphaned_wrong_tag_is_not_reused(self):
        api = self.api()
        api.reference = {"object": {"type": "commit", "sha": OLD}}
        with self.assertRaisesRegex(ValueError, "will not be moved"):
            publish(api, self.policy, TARGET, api.command)
        self.assertEqual(api.commands, [])

    def test_interrupted_matching_tag_can_finish_release(self):
        api = self.api()
        api.reference = {"object": {"type": "commit", "sha": TARGET}}
        publish(api, self.policy, TARGET, api.command)
        self.assertEqual(len(api.commands), 1)
        self.assertEqual(api.commands[0][:3], ["gh", "release", "create"])

    def test_inconsistent_existing_release_fails_closed(self):
        for field, value in (
            ("draft", True),
            ("prerelease", True),
            ("name", "Changed title"),
            ("body", "Changed notes"),
        ):
            with self.subTest(field=field):
                api = self.api()
                api.reference = {"object": {"type": "commit", "sha": TARGET}}
                api.release = self.published_release()
                api.release[field] = value
                with self.assertRaisesRegex(ValueError, "refusing any overwrite"):
                    publish(api, self.policy, TARGET, api.command)
                self.assertEqual(api.commands, [])

    def test_invalid_or_cyclic_tag_object_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "bounded commit identity"):
            tag_commit(self.api(), {"object": {"type": "tree", "sha": TARGET}})
        api = self.api()
        api.get = lambda path, optional=False: {"object": {"type": "tag", "sha": "c" * 40}}
        with self.assertRaisesRegex(ValueError, "bounded commit identity"):
            tag_commit(api, {"object": {"type": "tag", "sha": "c" * 40}})

    def test_permission_and_service_errors_are_not_absence(self):
        for status in (403, 429, 500):
            with self.subTest(status=status):
                failure = urllib.error.HTTPError(
                    "https://api.github.com", status, "failure", {}, None
                )
                with mock.patch("urllib.request.urlopen", side_effect=failure):
                    with self.assertRaisesRegex(RuntimeError, f"HTTP {status}"):
                        GitHub("owner/repo", "synthetic-token").get("/releases/tags/v1", optional=True)

    def test_optional_404_is_distinct_from_permission_failure(self):
        missing = urllib.error.HTTPError("https://api.github.com", 404, "missing", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=missing):
            self.assertIsNone(GitHub("owner/repo", "synthetic-token").get("/tags/v1", optional=True))

    def test_policy_requires_explicit_authorization_and_exact_workflow_identity(self):
        for field, value, pattern in (
            ("authorized", False, "explicitly authorized"),
            ("authorization_date", "not-a-date", "ISO calendar date"),
            ("prerelease", True, "cannot be published as a prerelease"),
            ("package_index_publication_authorized", True, "must not authorize package-index"),
            ("deployment_authorized", True, "must not authorize deployment"),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.policy)
                mutated[field] = value
                with self.assertRaisesRegex(ValueError, pattern):
                    validate_policy(mutated)
        mutated = copy.deepcopy(self.policy)
        first = next(iter(mutated["required_workflows"]))
        mutated["required_workflows"][first] = "Wrong workflow name"
        with self.assertRaisesRegex(ValueError, "workflow identity differs"):
            validate_policy(mutated)
        mutated = copy.deepcopy(self.policy)
        mutated["required_check_contexts"] = mutated["required_check_contexts"][:-1]
        with self.assertRaisesRegex(ValueError, "check contexts differ"):
            validate_policy(mutated)


if __name__ == "__main__":
    unittest.main()
