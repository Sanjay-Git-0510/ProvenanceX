import pytest

from app.scanners.manifests import classify, detect_manifests
from tests.conftest import SIMPLE_PROJECT


def test_fixture_project_manifests():
    result = detect_manifests(SIMPLE_PROJECT)
    assert [(m.path, m.ecosystem, m.kind) for m in result.manifests] == [
        ("pyproject.toml", "pypi", "manifest"),
        ("requirements.txt", "pypi", "manifest"),
    ]
    assert result.truncated is False


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("requirements-dev.txt", ("pypi", "manifest")),
        ("requirements.in.txt", ("pypi", "manifest")),
        ("poetry.lock", ("pypi", "lockfile")),
        ("package-lock.json", ("npm", "lockfile")),
        ("go.mod", ("go", "manifest")),
        ("App.csproj", ("nuget", "manifest")),
        ("Dockerfile", ("docker", "container")),
        ("README.md", None),
        ("requirements.md", None),
        ("package.json.bak", None),
    ],
)
def test_classify(name, expected):
    assert classify(name) == expected


def test_nested_and_skipped_dirs(tmp_path):
    for rel in [
        "web/package.json",
        "web/node_modules/left-pad/package.json",
        ".git/package.json",
        "svc/go.mod",
        "Dockerfile",
    ]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}")
    paths = [m.path for m in detect_manifests(tmp_path).manifests]
    assert paths == ["Dockerfile", "svc/go.mod", "web/package.json"]


def test_symlinked_manifest_not_reported(tmp_path):
    (tmp_path / "real.txt").write_text("x")
    (tmp_path / "package.json").symlink_to(tmp_path / "real.txt")
    assert detect_manifests(tmp_path).manifests == []


def test_limit_sets_truncated(tmp_path):
    for i in range(5):
        (tmp_path / f"d{i}").mkdir()
        (tmp_path / f"d{i}" / "package.json").write_text("{}")
    result = detect_manifests(tmp_path, limit=3)
    assert len(result.manifests) == 3
    assert result.truncated is True
