"""Publish the authorized GitHub release after every exact-main gate succeeds.

The workflow token is the only credential used. Tags and published releases are
never moved, replaced, or edited, and every write is preceded by a live gate check.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_-]+\.yml")
POLICY_KEYS = {
    "schema_version",
    "repository",
    "authorized",
    "authorized_by",
    "authorization_date",
    "authorization_scope",
    "release_version",
    "release_title",
    "notes_path",
    "prerelease",
    "package_index_publication_authorized",
    "deployment_authorized",
    "required_workflows",
    "required_check_contexts",
}


class GitHub:
    def __init__(self, repository: str, token: str):
        if not REPOSITORY.fullmatch(repository):
            raise ValueError("invalid repository")
        if not token:
            raise ValueError("GH_TOKEN is required")
        self.base = "https://api.github.com/repos/" + repository
        self.token = token

    def get(self, path: str, *, optional: bool = False):
        request = urllib.request.Request(
            self.base + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if optional and exc.code == 404:
                return None
            raise RuntimeError(f"GitHub read failed: HTTP {exc.code}") from None


def _workflow_name(path: Path) -> str:
    match = re.search(r"(?m)^name:\s*(.+?)\s*$", path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"workflow has no top-level name: {path}")
    return match.group(1).strip("'\"")


def validate_policy(policy: dict, root: Path = ROOT) -> dict:
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise ValueError("publication policy fields differ from the frozen policy schema")
    if policy["schema_version"] != "doraops.github-release-policy.v1":
        raise ValueError("unknown publication policy")
    if not isinstance(policy["repository"], str) or not REPOSITORY.fullmatch(policy["repository"]):
        raise ValueError("invalid publication repository")
    if policy["authorized"] is not True:
        raise ValueError("publication has not been explicitly authorized")
    if not isinstance(policy["authorized_by"], str) or not policy["authorized_by"].strip():
        raise ValueError("publication authorizer must be recorded")
    try:
        date.fromisoformat(policy["authorization_date"])
    except (TypeError, ValueError):
        raise ValueError("authorization date must be an ISO calendar date") from None
    if not isinstance(policy["authorization_scope"], str) or not policy["authorization_scope"].strip():
        raise ValueError("authorization scope must be recorded")

    version = policy["release_version"]
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("only an explicitly authorized stable version may be published")
    if not isinstance(policy["release_title"], str) or not policy["release_title"].strip():
        raise ValueError("release title must be recorded")
    if policy["prerelease"] is not False:
        raise ValueError("the stable release cannot be published as a prerelease")
    if policy["package_index_publication_authorized"] is not False:
        raise ValueError("this policy must not authorize package-index publication")
    if policy["deployment_authorized"] is not False:
        raise ValueError("this policy must not authorize deployment")

    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project.get("name") != "doraops" or project.get("version") != version:
        raise ValueError("package identity differs from the authorized release")
    if "Development Status :: 5 - Production/Stable" not in project.get("classifiers", []):
        raise ValueError("package must declare the stable reference boundary")

    gate_document = json.loads(
        (root / "configs" / "release-candidate-gate.json").read_text(encoding="utf-8")
    )
    if (
        gate_document.get("required_release_version") != version
        or gate_document.get("candidate_version") != version
        or gate_document.get("formal_stable_reference_release_eligible") is not True
        or gate_document.get("repository_governance_enforcement_verified") is not False
    ):
        raise ValueError("stable release gate differs from the authorized publication")
    for field in (
        "production_readiness_determined",
        "dora_compliance_determined",
        "supervisory_acceptance_determined",
    ):
        if gate_document.get(field) is not False:
            raise ValueError(f"stable release gate cannot set {field}=true")

    for contract_name in ("stable-api-contract.json", "stable-schema-contract.json"):
        contract = json.loads((root / "configs" / contract_name).read_text(encoding="utf-8"))
        if contract.get("release_version") != version or contract.get("frozen_for_v1") is not True:
            raise ValueError(f"{contract_name} differs from the stable release boundary")

    notes = (root / policy["notes_path"]).resolve()
    release_root = (root / "release").resolve()
    if not notes.is_relative_to(release_root) or not notes.is_file():
        raise ValueError("release notes must be a committed release file")

    required = policy["required_workflows"]
    if not isinstance(required, dict) or not required:
        raise ValueError("required workflow set must not be empty")
    if len(set(required.values())) != len(required):
        raise ValueError("required workflow names must be unique")
    for relative, expected_name in required.items():
        if (
            not isinstance(relative, str)
            or not WORKFLOW_PATH.fullmatch(relative)
            or not isinstance(expected_name, str)
            or not expected_name
        ):
            raise ValueError("invalid required workflow identity")
        workflow = root / relative
        if not workflow.is_file() or _workflow_name(workflow) != expected_name:
            raise ValueError(f"required workflow identity differs from policy: {relative}")

    governance = json.loads(
        (root / "configs" / "repository-governance-policy.json").read_text(encoding="utf-8")
    )
    contexts = policy["required_check_contexts"]
    if (
        not isinstance(contexts, list)
        or contexts != sorted(contexts)
        or len(contexts) != len(set(contexts))
        or contexts != governance.get("required_workflows")
    ):
        raise ValueError("publication check contexts differ from repository governance policy")
    return policy


def load_policy(root: Path = ROOT) -> dict:
    policy = json.loads((root / "release" / "publish-policy.json").read_text(encoding="utf-8"))
    return validate_policy(policy, root)


def workflow_gaps(runs: list[dict], policy: dict, sha: str) -> list[str]:
    gaps: list[str] = []
    for path, name in policy["required_workflows"].items():
        matches = [
            run
            for run in runs
            if run.get("head_sha") == sha
            and run.get("head_branch") == "main"
            and run.get("event") == "push"
            and run.get("head_repository", {}).get("full_name") == policy["repository"]
            and run.get("path") == path
            and run.get("name") == name
        ]
        if not matches:
            gaps.append(f"{name}: missing exact-SHA main push run")
            continue
        latest = max(matches, key=lambda item: (item["id"], item.get("run_attempt", 1)))
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            gaps.append(f"{name}: latest attempt is not successful")
    return gaps


def gate(api, policy: dict, sha: str) -> list[str]:
    if not SHA.fullmatch(sha):
        raise ValueError("candidate must be an exact 40-character SHA")
    if api.get("/git/ref/heads/main")["object"]["sha"] != sha:
        return ["candidate is no longer the current main SHA"]
    runs: list[dict] = []
    for page in range(1, 11):
        batch = api.get(
            f"/actions/runs?head_sha={sha}&event=push&branch=main&per_page=100&page={page}"
        )["workflow_runs"]
        runs.extend(batch)
        if len(batch) < 100:
            return workflow_gaps(runs, policy, sha)
    raise ValueError("workflow pagination limit reached; refusing incomplete evidence")


def tag_commit(api, reference: dict) -> str:
    obj = reference["object"]
    seen: set[str] = set()
    for _ in range(5):
        if obj["type"] == "commit" and SHA.fullmatch(obj["sha"]):
            return obj["sha"]
        if obj["type"] != "tag" or not SHA.fullmatch(obj["sha"]) or obj["sha"] in seen:
            break
        seen.add(obj["sha"])
        obj = api.get("/git/tags/" + obj["sha"])["object"]
    raise ValueError("tag does not resolve to a bounded commit identity")


def _verify_existing_release(api, policy: dict, reference: dict | None, release: dict) -> str:
    tag = "v" + policy["release_version"]
    expected_notes = (ROOT / policy["notes_path"]).read_text(encoding="utf-8").rstrip("\n")
    if (
        reference is None
        or release.get("tag_name") != tag
        or release.get("name") != policy["release_title"]
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("body", "").rstrip("\n") != expected_notes
    ):
        raise ValueError("existing publication is inconsistent; refusing any overwrite")
    return tag_commit(api, reference)


def publish(api, policy: dict, sha: str, run_command=subprocess.run) -> str:
    if gaps := gate(api, policy, sha):
        raise ValueError("publication blocked: " + "; ".join(gaps))
    tag = "v" + policy["release_version"]
    ref_path = "/git/ref/tags/" + tag
    reference = api.get(ref_path, optional=True)
    release = api.get("/releases/tags/" + tag, optional=True)
    if release is not None:
        retained = _verify_existing_release(api, policy, reference, release)
        return f"Existing {tag} retained at {retained}; no writes"

    repository = policy["repository"]
    if reference is None:
        run_command(
            [
                "gh",
                "api",
                "--method",
                "POST",
                f"repos/{repository}/git/refs",
                "-f",
                f"ref=refs/tags/{tag}",
                "-f",
                f"sha={sha}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        reference = api.get(ref_path)
    if tag_commit(api, reference) != sha:
        raise ValueError("existing tag differs from the tested candidate; it will not be moved")
    if gaps := gate(api, policy, sha):
        raise ValueError("publication blocked after tag verification: " + "; ".join(gaps))
    run_command(
        [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repository,
            "--verify-tag",
            "--target",
            sha,
            "--title",
            policy["release_title"],
            "--notes-file",
            str(ROOT / policy["notes_path"]),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    created = api.get("/releases/tags/" + tag)
    if _verify_existing_release(api, policy, reference, created) != sha:
        raise ValueError("created release tag differs from the tested candidate")
    return f"Published {tag} at exact tested SHA {sha}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["gate", "publish"])
    parser.add_argument("--sha", required=True)
    args = parser.parse_args(argv)
    policy = load_policy()
    if os.environ.get("GITHUB_REPOSITORY") != policy["repository"]:
        raise ValueError("workflow repository differs from publication policy")
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if actual != args.sha:
        raise ValueError("checkout differs from candidate SHA")
    api = GitHub(policy["repository"], os.environ.get("GH_TOKEN", ""))
    if args.mode == "publish":
        print(publish(api, policy, args.sha))
    else:
        gaps = gate(api, policy, args.sha)
        print(json.dumps({"sha": args.sha, "ready": not gaps, "gaps": gaps}, sort_keys=True))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"ready={'false' if gaps else 'true'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
