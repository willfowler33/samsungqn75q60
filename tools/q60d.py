"""Exact-build Q60D voice policy using the shared transport and transactions."""

import asyncio
import datetime
import hashlib
import json
import os
import re
import secrets
import shlex
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP_STATE = "/opt/usr/home/owner/share/samshush-q60d-voice-v1"
SOUND_STATE = "/opt/usr/home/owner/share/samshush-q60d-sound-v1"
RUNTIME_STATE = "/run/samshush-q60d-voice-v1"
UI_STATE = "/opt/usr/home/owner/share/samshush-q60d-voice-ui-refresh-v1"


def policy():
    return json.loads((HERE / "profiles/q60d.json").read_text())


def validate_action(args):
    allowed = {
        "inspect",
        "voice-audit",
        "apps",
        "sound-sensor",
        "guards-apply",
        "apply",
        "status",
        "restore",
        "startup",
    }
    if args.action not in allowed:
        raise ValueError(
            "Q60D supports assessed voice controls only; this action is unavailable"
        )
    if getattr(args, "group", None) is not None and not (
        args.action == "apps" and args.group == "voice-ui-refresh"
    ):
        raise ValueError("Optional groups are not supported by the Q60D policy")
    if args.action == "apply" and args.scope != "voice":
        raise ValueError("Q60D apply requires --scope voice")


def verify_model(host, expected):
    # Do not send a control message or depend on a caller-supplied model label.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{host}:8001/api/v2/", timeout=5) as response:
        device = json.load(response).get("device", {})
    if device.get("modelName") != expected:
        raise ValueError("Live TV model does not match the exact Q60D policy")


def registration_check(p):
    """Read the selected registrations in one bounded, consistent snapshot."""
    for app in p["app_files"]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", app):
            raise ValueError("Invalid policy app ID")
    names = ",".join("'" + app + "'" for app in sorted(p["app_files"]))
    query = (
        "SELECT app_id || '|' || app_exec FROM package_app_info WHERE app_id IN ("
        + names
        + ") ORDER BY app_id;"
    )
    expected = "\n".join(
        app + "|" + p["app_files"][app]["path"] for app in sorted(p["app_files"])
    )
    return (
        f"app_rows=$(sqlite3 -readonly -cmd '.timeout 5000' /opt/dbspace/.pkgmgr_parser.db {shlex.quote(query)}) || exit 1\n"
        f"[[ $app_rows == {shlex.quote(expected)} ]]\n"
    )


def preflight(p, *, recovery=False, native_apps=True):
    """Verify the reviewed build, registrations and files before any transaction."""
    lines = [
        "set -euo pipefail",
        "export PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "nsenter --mount=/proc/1/ns/mnt /bin/bash <<'Q60D_PREFLIGHT'",
        "set -euo pipefail",
        "[[ $(id -u) == 0 ]]",
        f"grep -Fxq {shlex.quote('BUILD_ID=' + p['build'])} /etc/os-release",
        f"[[ $(uname -m) == {shlex.quote(p['architecture'])} ]]",
        "[[ $(stat -c %u /opt/usr/home/owner) == 5001 ]]",
    ]
    if recovery:
        return "\n".join(lines + ["Q60D_PREFLIGHT"]) + "\n"
    if "startup" in p:
        import startup

        if (
            p["startup"]["original_sha256"] != startup.ORIGINAL_HASH
            or p["startup"]["unit_sha256"] != startup.UNIT_HASH
        ):
            raise ValueError(
                "Q60D boot files differ from the shared startup controller"
            )
        lines += [
            "if [[ -e /opt/usr/share/samshush-boot-v1 || -L /opt/usr/share/samshush-boot-v1 ]]; then",
            startup.substitute(startup.COMMON, p["build"]),
            "identity",
            "verify",
            "fi",
        ]
    else:
        lines.append("[[ ! -e /opt/usr/share/samshush-boot-v1 ]]")
    if native_apps:
        lines.append(registration_check(p))
    lines.append("sha256sum -c <<'Q60D_HASHES'")
    if native_apps:
        for item in p["app_files"].values():
            lines.append(f"{item['sha256']}  {item['path']}")
    for unit, digest in p["unit_sha256"].items():
        lines.append(f"{digest}  /usr/lib/systemd/system/{unit}")
    if "startup" in p:
        lines += [
            f"{p['startup']['unit_sha256']}  /usr/lib/systemd/system/AT-HUB.service",
            f"{p['startup']['gawk_sha256']}  /usr/bin/gawk",
            f"{p['startup']['bash_sha256']}  /bin/bash",
        ]
    lines.extend(["Q60D_HASHES", "echo 'Q60D POLICY PREFLIGHT PASS'", "Q60D_PREFLIGHT"])
    return "\n".join(lines) + "\n"


def render(args, frame):
    validate_action(args)
    p = policy()
    if args.action in ("apps", "sound-sensor"):
        script = frame.render_apps(
            args.operation,
            sound_sensor=args.action == "sound-sensor",
            profile=p,
            group=getattr(args, "group", None),
        )
    elif args.action == "guards-apply":
        script = frame.device_scripts.STARTUP_GUARDS
        start = script.index("\n", script.index("rows() { cat <<'ROWS'")) + 1
        end = script.index("\nROWS\n", start)
        rows = "\n".join(
            f"{unit}\t/opt/usr/share/systemd/system/{unit[:-8]}"
            for unit in p["startup_guards"]
        )
        script = script[:start] + rows + script[end:]
    elif args.action == "voice-audit":
        script = frame.device_scripts.VOICE_AUDIT
    elif args.action == "inspect":
        script = "id; cat /etc/os-release; uname -m; nsenter --mount=/proc/1/ns/mnt /bin/true"
    elif args.action == "startup":
        if args.operation in ("audit", "probe"):
            template = (
                frame.device_scripts.STARTUP_AUDIT
                if args.operation == "audit"
                else frame.device_scripts.STARTUP_PROBE
            )
            script = (
                "nsenter --mount=/proc/1/ns/mnt /bin/bash <<'BOOT_OPERATION'\n"
                + template.replace("@@BUILD@@", p["build"])
                + "\nBOOT_OPERATION\n"
            )
        else:
            import startup

            script = startup.control(
                args.operation,
                p["build"],
                getattr(args, "startup_archive_hash", "unused"),
            )
            script = (
                "nsenter --mount=/proc/1/ns/mnt /bin/bash <<'BOOT_OPERATION'\n"
                + script
                + "\nBOOT_OPERATION\n"
            )
    else:
        script = frame.render(
            args.action,
            "voice" if args.action == "apply" else "none",
            profile=p,
            runtime_state=RUNTIME_STATE,
        )
    # Keep Frame receipts untouched. The operation lock remains shared.
    script = script.replace("/opt/usr/home/owner/share/frame-voice-apps-v2", APP_STATE)
    script = script.replace(
        "/opt/usr/home/owner/share/frame-sound-sensor-v1", SOUND_STATE
    )
    script = script.replace(
        "/opt/usr/home/owner/share/frame-apps-voice-ui-refresh-v1", UI_STATE
    )
    if args.action not in ("apply", "status", "restore"):
        script = script.replace("/run/frame-runtime-v1", RUNTIME_STATE)
    return (
        preflight(p, recovery=args.action == "startup" and args.operation == "remove")
        + script
    )


def startup_bundle(frame):
    import startup

    p = policy()

    def runtime(action, scope, **options):
        return frame.render(
            action, scope, profile=p, runtime_state=RUNTIME_STATE, **options
        )

    # The immutable policy is checked once before masks. Reuse native readback
    # after masking without two more full hash/registration preflights.
    postflight = (
        "set -euo pipefail\n"
        + registration_check(p)
        + "\n".join(
            frame.render_apps("status", sound_sensor=sensor, profile=p)
            for sensor in (False, True)
        )
    )
    postflight = postflight.replace(
        "/opt/usr/home/owner/share/frame-voice-apps-v2", APP_STATE
    )
    postflight = postflight.replace(
        "/opt/usr/home/owner/share/frame-sound-sensor-v1", SOUND_STATE
    )
    return startup.bundle(
        p,
        runtime,
        frame.ASSETS,
        candidates=[("voice", RUNTIME_STATE, "voice", {})],
        # Mutable UI/package updates must not prevent stable, pinned service
        # masks from returning. Native registration/flag drift fails postflight
        # while leaving the correctly reapplied service masks in place.
        preflight=preflight(p, native_apps=False),
        postflight=postflight,
        include_packages=False,
    )


def run(args, frame):
    import tempfile
    from pathlib import PurePosixPath

    from samsung_tv_root.archive_root import probe
    from samsung_tv_root.sdb import SdbClient, find_sdb

    # Reject unsupported scopes before contacting any device.
    validate_action(args)
    package = (
        startup_bundle(frame)
        if args.action == "startup" and args.operation == "install"
        else None
    )
    if package is not None:
        args.startup_archive_hash = hashlib.sha256(package).hexdigest()
    script = render(args, frame)
    verify_model(str(args.tv), policy()["model"])
    args.logs.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = args.logs / (
        datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
        + "-q60d-"
        + args.action
        + "-"
        + secrets.token_hex(3)
        + ".json"
    )
    evidence = {
        "profile": "q60d",
        "action": args.action,
        "operation": getattr(args, "operation", None),
        "group": getattr(args, "group", None),
        "completed": False,
    }
    stage = PurePosixPath("/home/owner/share/tmp/sdk_tools") / (
        "q60d-startup-" + secrets.token_hex(8)
    )
    staged = False
    client = SdbClient(find_sdb(), str(args.tv))
    try:
        if package is not None:
            client.connect()
            client.require_device()
            result = client.capture(f"mkdir {stage}")
            if "\n[exit:0]" not in result.output:
                raise ValueError("Cannot create Q60D startup staging directory")
            staged = True
            with tempfile.TemporaryDirectory(prefix="q60d-startup-") as directory:
                path = Path(directory) / "startup.tar.gz"
                path.write_bytes(package)
                client.push(path, stage / "startup.tar.gz")
            script = f"export FRAME_STAGE={shlex.quote(str(stage))}\n" + script
        print("Acquiring temporary root for the exact Q60D voice policy.", flush=True)
        result = asyncio.run(
            probe(
                str(args.tv),
                model=policy()["model"],
                callback_host=str(args.callback_host) if args.callback_host else None,
                accept_timeout=180,
                command_timeout=180,
                commands=(frame.wrapped(script),),
                payloads=frame.ASSETS / "payloads",
            )
        )
        evidence["result"] = result
        for command in result.get("commands", []):
            print(command.get("stdout", ""), end="")
            print(command.get("stderr", ""), end="", file=frame.sys.stderr)
        frame.check_result(result)
        evidence["completed"] = True
    except Exception as error:
        evidence["error"] = str(error)
        print(f"FAILED: {error}", file=frame.sys.stderr)
    finally:
        if staged:
            try:
                result = client.capture(f"rm -rf {stage}; test ! -e {stage}")
                evidence["bundle_staging_cleaned"] = "\n[exit:0]" in result.output
            except Exception as error:
                evidence["bundle_staging_cleaned"] = False
                evidence["cleanup_error"] = str(error)
            if not evidence.get("bundle_staging_cleaned"):
                evidence["completed"] = False
        with report.open("x") as output:
            os.chmod(report, 0o600)
            json.dump(evidence, output, indent=2)
            output.write("\n")
        print(f"Report: {report}", file=frame.sys.stderr)
    return 0 if evidence["completed"] else 1
