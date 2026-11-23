"""Shared helpers for the real-world dataset tests: recorded responses and a routing transport."""

import json
from collections.abc import Callable
from datetime import date

import httpx

from app.dataset_collection.sources.base import CollectionContext, MetadataClient
from app.ml.realworld.manifest import (
    DATASET_VERSION,
    GroundTruth,
    ManifestRecord,
    RealLabel,
    canonical_sha256,
    record_id_for,
)
from tests.conftest import FIXTURES

RECORDED = json.loads((FIXTURES / "realworld" / "recorded.json").read_text())
TODAY = date(2026, 11, 22)

Route = Callable[[httpx.Request], httpx.Response | None]


def router(
    routes: dict[str, object], log: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    """Serve JSON by 'METHOD host/path' key; a callable value gets the request. 404 otherwise."""

    def handler(request: httpx.Request) -> httpx.Response:
        if log is not None:
            log.append(request)
        key = f"{request.method} {request.url.host}{request.url.path}"
        value = routes.get(key)
        if callable(value):
            value = value(request)
        if isinstance(value, httpx.Response):
            return value
        if value is None:
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json=value)

    return httpx.MockTransport(handler)


def make_ctx(routes: dict[str, object], log: list[httpx.Request] | None = None, **kw: object):
    client = MetadataClient(
        transport=router(routes, log), max_retries=0, sleep=lambda _: None, **kw
    )
    return CollectionContext(client=client, today=TODAY)


def record(**overrides: object) -> ManifestRecord:
    """A valid benign software record; override any field."""
    identifier = str(overrides.get("artifact_identifier", "github.com/pallets/flask"))
    revision = overrides.get("revision", "22d924701a6ae2e4cd01e9a15bbaf3946094af65")
    artifact_type = str(overrides.get("artifact_type", "software"))
    base: dict[str, object] = {
        "data_source": "github",
        "source_url": "https://github.com/pallets/flask",
        "collection_date": TODAY,
        "artifact_identifier": identifier,
        "artifact_type": artifact_type,
        "label": RealLabel.BENIGN,
        "label_justification": "Benign by criteria (test record).",
        "license": "BSD-3-Clause",
        "dataset_version": DATASET_VERSION,
        "preprocessing": ["test"],
        "record_id": record_id_for(artifact_type, identifier, revision),  # type: ignore[arg-type]
        "family_id": "github:pallets/flask",
        "ground_truth_status": GroundTruth.CRITERIA_BASED,
        "revision": revision,
        "scan_url": "https://github.com/pallets/flask",
        "scan_eligible": True,
        "sha256_status": "pending_scan",
        "source_record_sha256": canonical_sha256({"test": identifier}),
    }
    base.update(overrides)
    return ManifestRecord(**base)
