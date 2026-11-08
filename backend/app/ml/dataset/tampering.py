"""Controlled tampering recipes and the variants built from them.

A label comes only from which recipes were applied, never from thresholding features. Each
recipe's content is inert and is only parsed.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np

from app.ml.dataset.templates import ArtifactState, Family, read_seed
from app.ml.feature_schema import Label

# An inert opcode sequence naming os.system. It is written as bytes and only parsed.
INERT_FLAGGED_PICKLE = b"cposix\nsystem\n(S'true'\ntR."
LABEL_PRECEDENCE = (Label.SUSPICIOUS, Label.PROVENANCE_WEAK, Label.VULNERABLE)
MAX_ADVISORIES = 3


def _bump_commit(state: ArtifactState, tag: str) -> None:
    state.commit = f"{tag[:8]}{state.commit[8:]}"
    if state.revision and "." not in state.revision:
        state.revision = state.commit


def inject_advisories(state: ArtifactState, _family: Family, rng: np.random.Generator) -> None:
    count = int(rng.integers(1, min(MAX_ADVISORIES, len(state.components)) + 1))
    picks = rng.choice(len(state.components), size=count, replace=False)
    for number, pick in enumerate(sorted(int(p) for p in picks)):
        scored = rng.random() >= 0.15  # some real advisories carry no CVSS score
        state.advisories.append(
            {
                "id": f"SYNTH-{pick:04d}-{number}",
                "component": state.components[pick][0],
                "cvss": round(float(rng.uniform(3.0, 9.8)), 1) if scored else None,
            }
        )


def changed_hash(state: ArtifactState, _family: Family, _rng: np.random.Generator) -> None:
    """Content differs while the commit stays the same."""
    state.files["README.md"] += b"\nAltered after release.\n"


def removed_provenance(state: ArtifactState, _family: Family, rng: np.random.Generator) -> None:
    for path in [p for p in state.files if p.endswith((".intoto.jsonl", ".sig"))]:
        del state.files[path]
    if rng.random() < 0.5:
        _bump_commit(state, "cafef00d")


def docs_update(state: ArtifactState, _family: Family, _rng: np.random.Generator) -> None:
    """A legitimate new commit that only edits documentation. Stays benign."""
    state.files["README.md"] += b"\nDocumentation update.\n"
    _bump_commit(state, "d0c5d0c5")


def altered_config(state: ArtifactState, _family: Family, rng: np.random.Generator) -> None:
    config = json.loads(state.files["config.json"])
    if rng.random() < 0.5:
        config["auto_map"] = {"AutoModel": "remote_loader.Item"}
    else:
        config["hidden_size"] = int(config["hidden_size"]) + 32
    state.files["config.json"] = json.dumps(config, indent=2, sort_keys=True).encode()
    if rng.random() < 0.5:  # tampering can arrive as a new commit as easily as a rewrite
        _bump_commit(state, "c0f1c0f1")


def replaced_dependency(state: ArtifactState, _family: Family, rng: np.random.Generator) -> None:
    """Swap one package for a look-alike name, keeping the declared release."""
    pick = int(rng.integers(0, len(state.components)))
    old, version = state.components[pick]
    new = old.replace("synthlib", "synth1ib")
    state.components[pick] = (new, version)
    state.edges = [(new if a == old else a, new if b == old else b) for a, b in state.edges]
    state.files["README.md"] += b"\nDependency updated.\n"
    _bump_commit(state, "deadbeef")


def version_mismatch(state: ArtifactState, family: Family, _rng: np.random.Generator) -> None:
    state.revision = f"v{family.major + 7}.{family.minor}.0"


def suspicious_code(state: ArtifactState, family: Family, rng: np.random.Generator) -> None:
    state.files["helper_ext.py"] = read_seed("inert_suspicious.py.txt", family.name)
    if family.is_software and family.ecosystem == "pypi" and rng.random() < 0.3:
        state.files["setup.py"] = read_seed("inert_setup_hook.py.txt", family.name)
    if "pytorch_model.pkl" in state.files:
        state.files["pytorch_model.pkl"] = INERT_FLAGGED_PICKLE
    if rng.random() < 0.5:
        _bump_commit(state, "5a5a5a5a")


def suspicious_behavior(state: ArtifactState, _family: Family, _rng: np.random.Generator) -> None:
    state.trace_kind = "suspicious"


def _all(_family: Family) -> bool:
    return True


def _attested(family: Family) -> bool:
    return family.has_attestation and not family.is_upload


def _ai_with_history(family: Family) -> bool:
    return not family.is_software and not family.is_upload


def _software_with_history(family: Family) -> bool:
    return family.is_software and not family.is_upload


def _tagged(family: Family) -> bool:
    return family.uses_tag and not family.is_upload


def _with_history(family: Family) -> bool:
    return not family.is_upload


@dataclass(frozen=True)
class Recipe:
    name: str
    label: Label
    apply: Callable[[ArtifactState, Family, np.random.Generator], None]
    applicable: Callable[[Family], bool]
    evidence_stage: str  # the label can only be observed if this stage completed
    needs_prior: bool = False  # the change is only visible against an earlier scan


_PROVENANCE = "provenance"
RECIPES = {
    r.name: r
    for r in (
        Recipe("docs_update", Label.BENIGN, docs_update, _all, _PROVENANCE),
        Recipe("inject_advisories", Label.VULNERABLE, inject_advisories, _all, "vulnerabilities"),
        Recipe(
            "changed_hash", Label.PROVENANCE_WEAK, changed_hash, _with_history, _PROVENANCE, True
        ),
        Recipe(
            "removed_provenance",
            Label.PROVENANCE_WEAK,
            removed_provenance,
            _attested,
            _PROVENANCE,
            True,
        ),
        Recipe("version_mismatch", Label.PROVENANCE_WEAK, version_mismatch, _tagged, _PROVENANCE),
        Recipe("altered_config", Label.SUSPICIOUS, altered_config, _ai_with_history, "aibom", True),
        Recipe(
            "replaced_dependency",
            Label.SUSPICIOUS,
            replaced_dependency,
            _software_with_history,
            "graph",
            True,
        ),
        Recipe("suspicious_code", Label.SUSPICIOUS, suspicious_code, _all, "static"),
        Recipe("suspicious_behavior", Label.SUSPICIOUS, suspicious_behavior, _all, "sandbox"),
    )
}

TAMPERING_CASES = (
    "changed_hash",
    "removed_provenance",
    "altered_config",
    "replaced_dependency",
    "version_mismatch",
)


@dataclass(frozen=True)
class Variant:
    name: str
    recipes: tuple[str, ...]
    prior: str  # baseline | older; whether it is actually available is drawn per record


VARIANTS = (
    Variant("clean_docs_update", ("docs_update",), "baseline"),
    Variant("clean_rescan", (), "baseline"),
    Variant("clean_new_release", (), "older"),
    Variant("vulnerable", ("inject_advisories",), "baseline"),
    Variant("vulnerable_new_release", ("inject_advisories",), "older"),
    Variant("changed_hash", ("changed_hash",), "baseline"),
    Variant("removed_provenance", ("removed_provenance",), "baseline"),
    Variant("version_mismatch", ("version_mismatch",), "baseline"),
    Variant("altered_config", ("altered_config",), "baseline"),
    Variant("replaced_dependency", ("replaced_dependency",), "baseline"),
    Variant("suspicious_code", ("suspicious_code",), "baseline"),
    Variant("suspicious_behavior", ("suspicious_behavior",), "baseline"),
    Variant("vulnerable_changed_hash", ("inject_advisories", "changed_hash"), "baseline"),
    Variant("vulnerable_suspicious_code", ("inject_advisories", "suspicious_code"), "baseline"),
)


def variant_applies(variant: Variant, family: Family) -> bool:
    if family.is_upload and variant.prior == "older":
        return False  # uploads have no release history, so this would duplicate another variant
    return all(RECIPES[name].applicable(family) for name in variant.recipes)


def resolve_label(recipes: tuple[str, ...]) -> Label:
    """The most severe label among the applied recipes; no recipes means benign."""
    applied = {RECIPES[name].label for name in recipes}
    return next((label for label in LABEL_PRECEDENCE if label in applied), Label.BENIGN)
