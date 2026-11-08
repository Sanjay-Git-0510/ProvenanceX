"""Mock Hugging Face provider: serves a synthetic benign fixture repo, tagged source="mock".

The fixture (app/scanners/mock_data/hf_mock_repo) is synthetic: a tiny LoRA adapter with
zero weights, written for development and tests. The provider returns it for EVERY
requested repository, so its output must never be presented as a real Hub result. The
"commit sha" is derived from the fixture contents and is labeled mock.
"""

import hashlib
import shutil
from pathlib import Path

from app.scanners.hf.base import HfFetchLimits, HfFetchResult, HfFile
from app.security.url_validation import HfRepo

MOCK_HF_REPO = Path(__file__).resolve().parent.parent / "mock_data" / "hf_mock_repo"


class MockHfProvider:
    name = "mock"

    def __init__(self, fixture_dir: Path = MOCK_HF_REPO) -> None:
        self.fixture_dir = fixture_dir

    def fetch(
        self, repo: HfRepo, revision: str | None, dest: Path, limits: HfFetchLimits
    ) -> HfFetchResult:  # noqa: ARG002
        files: list[HfFile] = []
        commit = hashlib.sha1(b"provenancex-mock-hf", usedforsecurity=False)
        for src in sorted(p for p in self.fixture_dir.rglob("*") if p.is_file()):
            rel = src.relative_to(self.fixture_dir).as_posix()
            data = src.read_bytes()
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            digest = hashlib.sha256(data).hexdigest()
            commit.update(f"{rel}\0{digest}\n".encode())
            files.append(
                HfFile(
                    path=rel,
                    size=len(data),
                    git_oid=None,
                    lfs_sha256=None,
                    downloaded=True,
                    local_sha256=digest,
                    hash_verified=None,
                    status="downloaded",
                    reason="mock fixture (not fetched from the Hub)",
                )
            )
        return HfFetchResult(
            source="mock",
            repo=repo,
            commit_sha=commit.hexdigest(),
            files=files,
            meta={
                "repo_id": repo.repo_id,
                "author": "provenancex-fixtures",
                "library_name": "peft",
                "pipeline_tag": "text-generation",
                "last_modified": None,
                "created_at": None,
                "tags": ["provenancex-mock"],
                "downloads": None,
                "likes": None,
            },
            card_data=None,
            warnings=["Mock Hugging Face provider: synthetic fixture served for every repo"],
        )
