"""A fake `docker` CLI for unit tests of app/analysis/docker_analyzer.py. Benign test fixture.

The tests copy this file to an executable with a shebang. Its behavior comes from
$DOCKER_CONFIG/fake.json ($DOCKER_CONFIG is one of the few variables the analyzer passes to the
Docker CLI). It records every call in $DOCKER_CONFIG/calls.jsonl.

fake.json keys:
  daemon_exit    exit code of `docker version` (default 0; non-zero: daemon unreachable)
  image_exit     exit code of `docker image inspect` (default 0)
  create_exit    exit code of `docker create` (default 0)
  tamper         list of runtime-config fields to falsify in `docker inspect`
                 (network, readonly, ..., labels, deadline, restart)
  start          "ok" | "sleep" | "huge" | "silent"
  output_file    file whose bytes `docker start` prints for "ok"
  exit_code      the container's exit code (default 0)
  oom_killed     the container's OOMKilled flag (default false)
"""

import json
import os
import sys
import time
from pathlib import Path

MB = 1024 * 1024
STATE = Path(os.environ["DOCKER_CONFIG"])
CONFIG = json.loads((STATE / "fake.json").read_text()) if (STATE / "fake.json").exists() else {}


def log(args: list[str]) -> None:
    with (STATE / "calls.jsonl").open("a") as fh:
        fh.write(json.dumps(args) + "\n")


def parse_create(args: list[str]) -> dict:
    flags: dict[str, list[str]] = {}
    i = 0
    while i < len(args) and args[i].startswith("--"):
        key, _, value = args[i].partition("=")
        flags.setdefault(key, []).append(value)
        i += 1
    return {"flags": flags, "rest": args[i:]}


def mounts(values: list[str]) -> list[dict]:
    out = []
    for value in values:
        parts = dict(p.split("=", 1) if "=" in p else (p, "") for p in value.split(","))
        m = {
            "Type": parts["type"],
            "Source": parts["src"],
            "Target": parts["dst"],
            "ReadOnly": "readonly" in parts,
        }
        if "volume-subpath" in parts:
            m["VolumeOptions"] = {"Subpath": parts["volume-subpath"]}
        out.append(m)
    return out


def inspect_doc(created: dict) -> list[dict]:
    f = created["flags"]
    memory = int(f["--memory"][0][:-1]) * MB
    tmp_path, _, tmp_opts = f["--tmpfs"][0].partition(":")
    host = {
        "NetworkMode": f["--network"][0],
        "ReadonlyRootfs": "--read-only" in f,
        "Privileged": False,
        "CapDrop": f["--cap-drop"],
        "CapAdd": None,
        "SecurityOpt": f["--security-opt"],
        "Memory": memory,
        "MemorySwap": int(f["--memory-swap"][0][:-1]) * MB,
        "PidsLimit": int(f["--pids-limit"][0]),
        "NanoCpus": round(float(f["--cpus"][0]) * 1e9),
        "IpcMode": f["--ipc"][0],
        "PidMode": "",
        "UsernsMode": "",
        "UTSMode": "",
        "Devices": [],
        "Binds": None,
        "VolumesFrom": None,
        "Tmpfs": {tmp_path: tmp_opts},
        "LogConfig": {"Type": f["--log-driver"][0]},
        "Mounts": mounts(f["--mount"]),
    }
    config = {
        "User": f["--user"][0],
        "Env": ["PATH=/usr/bin", "PX_ANALYZER_WORKER=1"],
        "Labels": dict(v.split("=", 1) for v in f.get("--label", [])),
        "Cmd": created["rest"][1:],
    }
    host["RestartPolicy"] = {"Name": "no"}
    for field in CONFIG.get("tamper", []):
        if field == "network":
            host["NetworkMode"] = "bridge"
        elif field == "readonly":
            host["ReadonlyRootfs"] = False
        elif field == "privileged":
            host["Privileged"] = True
        elif field == "capadd":
            host["CapAdd"] = ["SYS_ADMIN"]
        elif field == "memory":
            host["Memory"] = 0
        elif field == "pids":
            host["PidsLimit"] = None
        elif field == "socket":
            host["Mounts"].append(
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Target": "/var/run/docker.sock",
                    "ReadOnly": False,
                }
            )
        elif field == "writable_artifact":
            for m in host["Mounts"]:
                m["ReadOnly"] = False
        elif field == "secret_env":
            config["Env"].append("DATABASE_URL=postgresql://x")
        elif field == "user":
            config["User"] = "0:0"
        elif field == "labels":
            config["Labels"] = {}
        elif field == "deadline":
            config["Cmd"] = [a for a in config["Cmd"] if a != "--deadline"]
        elif field == "restart":
            host["RestartPolicy"] = {"Name": "always"}
    return [{"Image": "sha256:" + "f" * 64, "HostConfig": host, "Config": config}]


def main() -> int:
    args = sys.argv[1:]
    log(args)
    if args[:1] == ["version"]:
        print("1.47")
        return int(CONFIG.get("daemon_exit", 0))
    if args[:2] == ["image", "inspect"]:
        print("sha256:" + "f" * 64)
        return int(CONFIG.get("image_exit", 0))
    if args[:1] in (["rm"], ["kill"]):
        return 0
    if args[:1] == ["create"]:
        (STATE / "created.json").write_text(json.dumps(parse_create(args[1:])))
        return int(CONFIG.get("create_exit", 0))
    if args[:3] == ["inspect", "--format", "{{json .State}}"]:
        state = {
            "ExitCode": int(CONFIG.get("exit_code", 0)),
            "OOMKilled": bool(CONFIG.get("oom_killed", False)),
        }
        print(json.dumps(state))
        return 0
    if args[:1] == ["inspect"]:
        print(json.dumps(inspect_doc(json.loads((STATE / "created.json").read_text()))))
        return 0
    if args[:1] == ["start"]:
        (STATE / "stdin.json").write_bytes(sys.stdin.buffer.read())
        mode = CONFIG.get("start", "ok")
        if mode == "sleep":
            time.sleep(30)
        elif mode == "huge":
            chunk = b"x" * MB
            for _ in range(200):
                sys.stdout.buffer.write(chunk)
        elif mode == "ok":
            sys.stdout.buffer.write(Path(CONFIG["output_file"]).read_bytes())
        sys.stdout.flush()
        return int(CONFIG.get("exit_code", 0))
    print(f"fake docker: unsupported {args}", file=sys.stderr)
    return 125


if __name__ == "__main__":
    sys.exit(main())
