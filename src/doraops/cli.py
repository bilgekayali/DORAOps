from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

import jsonschema

from .canonical import sha256_digest
from .dossier import RELEASE_VERSION, verify_dossier_document
from .inventory import GovernanceError


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="doraops",
        description="Offline DORAOps governance evidence integrity tools.",
    )
    parser.add_argument("--version", action="version", version=f"doraops {RELEASE_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest = subparsers.add_parser("digest", help="Print canonical SHA-256 for a JSON document.")
    digest.add_argument("document")

    schema = subparsers.add_parser("schema", help="Validate a JSON document against a JSON Schema.")
    schema.add_argument("schema")
    schema.add_argument("document")

    dossier = subparsers.add_parser("dossier", help="Governance dossier operations.")
    dossier_sub = dossier.add_subparsers(dest="dossier_command", required=True)
    verify = dossier_sub.add_parser("verify", help="Verify dossier and embedded artifact integrity.")
    verify.add_argument("document")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "digest":
            print(sha256_digest(_load_json(args.document)))
            return 0
        if args.command == "schema":
            schema = _load_json(args.schema)
            document = _load_json(args.document)
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.Draft202012Validator(schema).validate(document)
            print("valid")
            return 0
        if args.command == "dossier" and args.dossier_command == "verify":
            print(verify_dossier_document(_load_json(args.document)))
            return 0
    except (GovernanceError, OSError, json.JSONDecodeError, jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        print(f"doraops: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
