from __future__ import annotations

PACKAGE_VERSION = "0.3.0"


def apply_release_version() -> None:
    """Keep the unchanged v1 dossier envelope aligned with the current package release."""
    from . import dossier as dossier_module

    dossier_module.RELEASE_VERSION = PACKAGE_VERSION
