"""Security boundaries of the chain integration: what goes on-chain and what never leaks."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
BLOCKCHAIN = ROOT / "backend" / "app" / "blockchain"
EIGHT_FIELDS = [
    "artifactId",
    "artifactHash",
    "bomHash",
    "provenanceHash",
    "riskScore",
    "decision",
    "scannerVersion",
    "timestamp",
]
FORBIDDEN_ON_CHAIN = re.compile(r"(?i)sbom|trace|source|model|path|cvss|probab|finding|scanid")
HEX_KEY = re.compile(r"\b0x[0-9a-fA-F]{64}\b")


def _abi() -> list[dict]:
    return json.loads((BLOCKCHAIN / "abi.json").read_text(encoding="utf-8"))


def _named(kind: str, name: str) -> dict:
    return next(i for i in _abi() if i["type"] == kind and i["name"] == name)


def test_anchor_takes_exactly_the_eight_fields():
    assert [i["name"] for i in _named("function", "anchor")["inputs"]] == EIGHT_FIELDS


def test_stored_struct_is_exactly_the_eight_fields():
    output = _named("function", "getAnchor")["outputs"][0]
    assert [i["name"] for i in output["components"]] == EIGHT_FIELDS


def test_event_is_the_eight_fields_plus_position():
    names = [i["name"] for i in _named("event", "EvidenceAnchored")["inputs"]]
    assert names == ["artifactId", "anchorIndex", *EIGHT_FIELDS[1:]]


def test_contract_has_one_state_changing_function():
    writers = [
        i["name"]
        for i in _abi()
        if i["type"] == "function" and i["stateMutability"] not in ("view", "pure")
    ]
    assert writers == ["anchor"]


def test_no_forbidden_data_name_is_on_chain():
    names = [i["name"] for i in _named("function", "anchor")["inputs"]]
    assert [n for n in names if FORBIDDEN_ON_CHAIN.search(n)] == []


def test_forbidden_name_pattern_detects_a_bad_field():
    assert FORBIDDEN_ON_CHAIN.search("sbomContent")


@pytest.mark.parametrize("path", sorted(BLOCKCHAIN.glob("*")), ids=lambda p: p.name)
def test_no_key_is_committed_in_the_blockchain_package(path):
    if path.is_file():
        assert not HEX_KEY.search(path.read_text(encoding="utf-8"))


def test_provider_never_passes_exception_text_on():
    source = (BLOCKCHAIN / "web3_provider.py").read_text(encoding="utf-8")
    assert "str(exc)" not in source
    assert "{exc}" not in source


def test_verification_does_not_build_paths_from_stored_stage_names():
    source = (BLOCKCHAIN / "verification.py").read_text(encoding="utf-8")
    assert "sbom_file" not in source
    assert "stages" not in source
