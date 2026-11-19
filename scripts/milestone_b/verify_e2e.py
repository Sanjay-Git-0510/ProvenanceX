"""End-to-end check of Milestone B against the running verification stack (scripts/milestone_b).

Submits a GitHub software scan (octocat/Hello-World) and a Hugging Face model scan
(sshleifer/tiny-gpt2), both pinned to immutable revisions, through the real API. They run in the
real scan-runner container, fetcher containers, egress proxy and analyzer containers. Then it
checks every evidence endpoint, compares the artifact identity with independently obtained
references, verifies the blockchain anchor, and checks that nothing was left behind.

Run with the backend venv (it reuses the backend's hashing code for the reference digests):
    backend/.venv/bin/python scripts/milestone_b/verify_e2e.py
Exit 0: every check passed. Exit 1: a check failed (the report says which). Exit 3: NOT RUN.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from app.core.hashing import tree_digest  # noqa: E402
from app.pipeline.model import hf_manifest_digest  # noqa: E402
from app.scanners.hf.base import HfFetchResult, HfFile  # noqa: E402
from app.security.url_validation import HfRepo  # noqa: E402

API = os.environ.get("API", "http://127.0.0.1:18180/api/v1")
PROJECT = os.environ.get("PROJECT", "pxmb")
STATE_DIR = Path(os.environ.get("STATE_DIR", tempfile.gettempdir()))
GITHUB = ("https://github.com/octocat/Hello-World", "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")
HF = ("https://huggingface.co/sshleifer/tiny-gpt2", "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be")
CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: object = None) -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"), flush=True)
    return bool(ok)


def call(method: str, path: str, form: dict | None = None) -> tuple[int, dict]:
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)  # noqa: S310 - local API
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def fetch_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed public URLs
        return json.loads(resp.read())


def wait(scan_id: str, timeout: float = 1200) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, body = call("GET", f"/scans/{scan_id}")
        if body.get("status") in ("completed", "failed"):
            return body
        time.sleep(3)
    return body


def docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607


def common_checks(label: str, body: dict, commit: str, expected_modes: list[str]) -> None:
    sid = body["scan_id"]
    check(f"{label}: scan completed", body["status"] == "completed", body.get("error"))
    check(
        f"{label}: pinned commit fetched",
        body["artifact"]["version"] == commit,
        body["artifact"].get("version"),
    )
    runs = (body.get("sandbox") or {}).get("runs") or []
    modes = [r.get("mode") for r in runs]
    check(f"{label}: sandbox runs {expected_modes}", modes == expected_modes, modes)
    check(
        f"{label}: every run ok and runtime-verified",
        all(r.get("status") == "ok" and r.get("runtime_verified") for r in runs),
        runs,
    )
    for run in runs:
        if run.get("mode") != "hold":
            iso = run.get("isolation") or {}
            check(
                f"{label}: {run['mode']} self-check all true ({len(iso)} checks)",
                iso and all(v is True for v in iso.values()),
                iso,
            )
    fetch = next((r for r in runs if r.get("mode") == "fetch"), {})
    rt = fetch.get("runtime") or {}
    check(
        f"{label}: fetcher ran on the internal network",
        rt.get("network_internal") is True and rt.get("network") == f"{PROJECT}_fetch",
        rt,
    )
    check(
        f"{label}: fetcher read-only, cap-drop ALL, no-new-privileges",
        rt.get("read_only_rootfs") and rt.get("cap_drop") == "ALL" and rt.get("no_new_privileges"),
        rt,
    )
    hold = next((r for r in runs if r.get("mode") == "hold"), {})
    check(
        f"{label}: staging was a tmpfs volume",
        (hold.get("staging") or {}).get("type") == "tmpfs",
        hold.get("staging"),
    )
    stages = body.get("stages") or {}
    check(
        f"{label}: risk stage completed",
        (stages.get("risk") or {}).get("status") == "completed",
        stages.get("risk"),
    )
    code, findings = call("GET", f"/scans/{sid}/findings")
    check(f"{label}: findings endpoint", code == 200, code)
    code, graph = call("GET", f"/scans/{sid}/graph")
    check(f"{label}: graph has nodes", code == 200 and len(graph.get("nodes", [])) > 0, code)
    code, risk = call("GET", f"/scans/{sid}/risk")
    check(
        f"{label}: risk decision",
        code == 200
        and risk.get("decision") in ("ALLOW", "REVIEW", "BLOCK")
        and risk.get("risk_score") is not None,
        (risk.get("decision"), risk.get("risk_score")),
    )
    code, evidence = call("GET", f"/scans/{sid}/evidence")
    check(f"{label}: evidence endpoint", code == 200, code)
    code, chain = call("GET", f"/scans/{sid}/blockchain")
    check(
        f"{label}: anchored on the local chain",
        code == 200 and chain.get("anchor_recorded"),
        chain.get("note"),
    )
    code, verified = call("POST", f"/scans/{sid}/verify")
    check(
        f"{label}: verification state VERIFIED",
        verified.get("state") == "VERIFIED",
        (verified.get("state"), verified.get("reason")),
    )


def main() -> int:
    code, health = call("GET", "/health/ready")
    if code != 200:
        print(f"NOT RUN: the verification stack is not up at {API} (scripts/milestone_b/up.sh)")
        return 3

    # ---- GitHub
    _, created = call("POST", "/scans/software", {"source_url": GITHUB[0], "revision": GITHUB[1]})
    gh = wait(created["scan_id"])
    common_checks("github", gh, GITHUB[1], ["hold", "fetch", "analyze", "persist"])
    with tempfile.TemporaryDirectory() as ref:
        readme = urllib.request.urlopen(  # noqa: S310 - fixed public URL
            f"https://raw.githubusercontent.com/octocat/Hello-World/{GITHUB[1]}/README", timeout=60
        ).read()
        (Path(ref) / "README").write_bytes(readme)
        expected = tree_digest(Path(ref)).sha256
    check(
        "github: artifact sha256 equals an independent digest",
        gh["artifact"]["sha256"] == expected,
        (gh["artifact"]["sha256"], expected),
    )
    check(
        "github: SBOM stage completed",
        (gh["stages"].get("sbom") or {}).get("status") in ("completed", "partial"),
        gh["stages"].get("sbom"),
    )

    # ---- Hugging Face
    _, created = call("POST", "/scans/model", {"source_url": HF[0], "revision": HF[1]})
    hf = wait(created["scan_id"])
    common_checks("huggingface", hf, HF[1], ["hold", "fetch", "analyze", "persist"])
    listing = fetch_json(f"https://huggingface.co/api/models/sshleifer/tiny-gpt2/tree/{HF[1]}")
    files = [
        HfFile(e["path"], e["size"], e.get("oid"), (e.get("lfs") or {}).get("oid"))
        for e in listing
        if e.get("type") == "file"
    ]
    reference = hf_manifest_digest(
        HfFetchResult("huggingface", HfRepo("model", "sshleifer/tiny-gpt2"), HF[1], files)
    )
    meta = (hf.get("ingest") or {}).get("hf") or {}
    check(
        "huggingface: manifest digest equals the Hub's own listing",
        meta.get("manifest_sha256") == reference,
        (meta.get("manifest_sha256"), reference),
    )
    counts = meta.get("counts") or {}
    check(
        "huggingface: every listed file downloaded and verified",
        counts.get("listed") == counts.get("downloaded") == len(files),
        counts,
    )
    check(
        "huggingface: AI-BOM stage completed",
        (hf["stages"].get("aibom") or {}).get("status") in ("completed", "partial"),
        hf["stages"].get("aibom"),
    )

    # ---- Boundaries of the running stack
    runner = f"{PROJECT}-scan-runner-1"
    no_git = docker("exec", runner, "sh", "-c", "command -v git")
    check("runner container has no git binary", no_git.returncode != 0, no_git.stdout)
    proxy_nets = docker(
        "inspect", "--format", "{{json .NetworkSettings.Networks}}", f"{PROJECT}-egress-proxy-1"
    ).stdout
    nets = set(json.loads(proxy_nets or "{}"))
    check(
        "egress proxy is only on the fetch and egress networks",
        nets == {f"{PROJECT}_fetch", f"{PROJECT}_egress"},
        nets,
    )
    internal = docker("network", "inspect", "--format", "{{.Internal}}", f"{PROJECT}_fetch")
    check("fetch network is internal", internal.stdout.strip() == "true", internal.stdout)
    leftovers = docker("ps", "-aq", "--filter", f"label=io.provenancex.instance={PROJECT}").stdout
    check("no sandbox containers left behind", leftovers.strip() == "", leftovers)
    volumes = docker(
        "volume",
        "ls",
        "-q",
        "--filter",
        "label=io.provenancex.role=staging",
        "--filter",
        f"label=io.provenancex.instance={PROJECT}",
    ).stdout
    check("no staging volumes left behind", volumes.strip() == "", volumes)
    logs = docker("logs", f"{PROJECT}-egress-proxy-1")
    hosts = {
        json.loads(line[line.index("{") :]).get("host")
        for line in (logs.stdout + logs.stderr).splitlines()
        if '"outcome": "tunneled"' in line
    }
    check(
        "proxy tunneled only to allowlisted hosts",
        hosts
        and hosts
        <= {"github.com", "huggingface.co", "us.aws.cdn.hf.co", "cas-bridge.xethub.hf.co"},
        sorted(hosts),
    )

    report = {
        "api": API,
        "scans": {"github": gh["scan_id"], "huggingface": hf["scan_id"]},
        "checks": CHECKS,
    }
    (STATE_DIR / "e2e-report.json").write_text(
        json.dumps(report, indent=2, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
    )
    failed = [c for c in CHECKS if not c["ok"]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
