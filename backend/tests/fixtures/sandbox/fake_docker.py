"""A fake `docker` CLI for unit tests of app/analysis/docker_analyzer.py. Benign test fixture.

The tests copy this file to an executable with a shebang. Its behavior comes from
$DOCKER_CONFIG/fake.json ($DOCKER_CONFIG is one of the few variables the analyzer passes to the
Docker CLI). It records every call in $DOCKER_CONFIG/calls.jsonl.

fake.json keys:
  daemon_exit    exit code of `docker version` (default 0; non-zero: daemon unreachable)
  image_exit     exit code of `docker image inspect` (default 0)
  create_exit    exit code of `docker create` (default 0)
  tamper         list of runtime-config fields to falsify in `docker inspect`
                 (network, readonly, ..., labels, deadline, restart, and the L3 fields:
                 seccomp, apparmor, masked, readonly_paths, runtime, ulimits, oomkill, sysctls,
                 shm, cgroupns, devices_req, entrypoint, missing_runtime)
  network_internal  `docker network inspect` reports Internal (default true)
  volume_tamper  list of staging-volume fields to falsify in `docker volume inspect`
                 (type, size, labels)
  volume_ls      extra tab-separated lines printed by `docker volume ls`
  ps_quiet       lines printed by `docker ps --quiet` (default none)
  hold_running   `docker inspect` State.Running of the holder container (default true)
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
        if "volume-nocopy" in parts:
            m.setdefault("VolumeOptions", {})["NoCopy"] = True
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
        # The values Docker 29 reports for a hardened unprivileged container (audit L3).
        "Runtime": "runc",
        "OomKillDisable": False,
        "ShmSize": 64 * MB,
        "MaskedPaths": [
            "/proc/acpi",
            "/proc/asound",
            "/proc/interrupts",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/sys/devices/virtual/powercap",
            "/sys/firmware",
        ],
        "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        "Ulimits": [{"Name": "core", "Hard": 0, "Soft": 0}],
        "CgroupnsMode": "private",
        "OomScoreAdj": 0,
        "PortBindings": {},
        "PublishAllPorts": False,
        "Isolation": "",
        "CgroupParent": "",
    }
    fetcher = created["rest"][0].startswith("provenancex-fetcher")
    worker = "app.fetch_worker" if fetcher else "app.sandbox_worker"
    config = {
        "User": f["--user"][0],
        "Env": ["PATH=/usr/bin", "PX_FETCH_WORKER=1" if fetcher else "PX_ANALYZER_WORKER=1"],
        "Labels": dict(v.split("=", 1) for v in f.get("--label", [])),
        "Cmd": created["rest"][1:],
        "Entrypoint": ["python", "-B", "-m", worker],
    }
    host["RestartPolicy"] = {"Name": "no"}
    network = f["--network"][0]
    settings = {"Networks": {} if network == "none" else {network: {}}}
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
        elif field == "seccomp":
            host["SecurityOpt"] = [*host["SecurityOpt"], "seccomp=unconfined"]
        elif field == "apparmor":
            host["SecurityOpt"] = [*host["SecurityOpt"], "apparmor=unconfined"]
        elif field == "masked":
            host["MaskedPaths"] = []
        elif field == "readonly_paths":
            host["ReadonlyPaths"] = []
        elif field == "runtime":
            host["Runtime"] = "runsc-custom"
        elif field == "missing_runtime":
            del host["Runtime"]
        elif field == "ulimits":
            host["Ulimits"] = [{"Name": "nofile", "Hard": 1048576, "Soft": 1048576}]
        elif field == "oomkill":
            host["OomKillDisable"] = True
        elif field == "sysctls":
            host["Sysctls"] = {"net.ipv4.ip_forward": "1"}
        elif field == "shm":
            host["ShmSize"] = 2048 * MB
        elif field == "cgroupns":
            host["CgroupnsMode"] = "host"
        elif field == "devices_req":
            host["DeviceRequests"] = [{"Driver": "nvidia", "Count": -1}]
        elif field == "entrypoint":
            config["Entrypoint"] = ["sh", "-c"]
        elif field == "extra_network":
            settings["Networks"]["bridge"] = {}
        elif field == "proxy_env":
            config["Env"].append("HTTPS_PROXY=http://elsewhere:3128")
    return [
        {
            "Image": "sha256:" + "f" * 64,
            "HostConfig": host,
            "Config": config,
            "NetworkSettings": settings,
        }
    ]


def volume_doc(name: str) -> list[dict]:
    created = json.loads((STATE / f"volume-{name}.json").read_text())
    options = dict(o.split("=", 1) for o in created["opts"])
    labels = dict(v.split("=", 1) for v in created["labels"])
    for field in CONFIG.get("volume_tamper", []):
        if field == "type":
            options["type"] = "none"
        elif field == "size":
            options["o"] = options["o"].replace("size=", "size=9")
        elif field == "labels":
            labels = {}
    return [{"Name": name, "Driver": created["driver"], "Options": options, "Labels": labels}]


def volume(args: list[str]) -> int:
    verb = args[0]
    if verb == "create":
        opts, labels, driver, i = [], [], "local", 1
        while i < len(args) - 1:
            if args[i] == "--opt":
                opts.append(args[i + 1])
            elif args[i] == "--label":
                labels.append(args[i + 1])
            elif args[i] == "--driver":
                driver = args[i + 1]
            i += 2
        name = args[-1]
        doc = {"opts": opts, "labels": labels, "driver": driver}
        (STATE / f"volume-{name}.json").write_text(json.dumps(doc))
        print(name)
        return int(CONFIG.get("volume_create_exit", 0))
    if verb == "inspect":
        path = STATE / f"volume-{args[1]}.json"
        if not path.exists():
            return 1
        print(json.dumps(volume_doc(args[1])))
        return 0
    if verb == "rm":
        for name in args[1:]:
            if not name.startswith("-"):
                (STATE / f"volume-{name}.json").unlink(missing_ok=True)
        return int(CONFIG.get("volume_rm_exit", 0))
    if verb == "ls":
        for path in sorted(STATE.glob("volume-px-stg-*.json")):
            name = path.name[len("volume-") : -len(".json")]
            labels = dict(v.split("=", 1) for v in json.loads(path.read_text())["labels"])
            print(
                "\t".join(
                    [
                        name,
                        labels.get("io.provenancex.role", ""),
                        labels.get("io.provenancex.instance", ""),
                        labels.get("io.provenancex.scan-id", ""),
                        labels.get("io.provenancex.claim", ""),
                        labels.get("io.provenancex.size-mb", ""),
                    ]
                )
            )
        for line in CONFIG.get("volume_ls", []):
            print(line)
        return 0
    return 125


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
    if args[:1] == ["volume"]:
        return volume(args[1:])
    if args[:2] == ["network", "inspect"]:
        print(
            json.dumps(
                [
                    {
                        "Name": args[2],
                        "Driver": "bridge",
                        "Scope": "local",
                        "Internal": bool(CONFIG.get("network_internal", True)),
                    }
                ]
            )
        )
        return int(CONFIG.get("network_exit", 0))
    if args[:1] == ["ps"]:
        for line in CONFIG.get("ps_quiet", []):
            print(line)
        return 0
    if args[:1] == ["create"]:
        (STATE / "created.json").write_text(json.dumps(parse_create(args[1:])))
        return int(CONFIG.get("create_exit", 0))
    if args[:3] == ["inspect", "--format", "{{json .State}}"]:
        state = {
            "ExitCode": int(CONFIG.get("exit_code", 0)),
            "OOMKilled": bool(CONFIG.get("oom_killed", False)),
        }
        if args[3].endswith("-hold"):
            state = {"Running": bool(CONFIG.get("hold_running", True)), "ExitCode": 0}
        print(json.dumps(state))
        return 0
    if args[:1] == ["inspect"]:
        print(json.dumps(inspect_doc(json.loads((STATE / "created.json").read_text()))))
        return 0
    if args[:1] == ["start"] and "--attach" not in args:
        return int(CONFIG.get("hold_start_exit", 0))  # the detached staging holder
    if args[:1] == ["start"]:
        (STATE / "stdin.json").write_bytes(sys.stdin.buffer.read())
        mode = CONFIG.get("start", "ok")
        if mode == "sleep":
            time.sleep(30)
        elif mode == "huge":
            # A well-formed frame header that announces a 200 MB envelope, then the bytes.
            sys.stdout.buffer.write(b"PXF1\n" + b"E" + (200 * MB).to_bytes(8, "big"))
            chunk = b"x" * MB
            for _ in range(200):
                sys.stdout.buffer.write(chunk)
        elif mode == "ok":
            sys.stdout.buffer.write(Path(CONFIG["output_file"]).read_bytes())
            if CONFIG.get("stderr"):
                sys.stderr.buffer.write(CONFIG["stderr"].encode())
        sys.stdout.flush()
        return int(CONFIG.get("exit_code", 0))
    print(f"fake docker: unsupported {args}", file=sys.stderr)
    return 125


if __name__ == "__main__":
    sys.exit(main())
