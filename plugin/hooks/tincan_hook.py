#!/usr/bin/env python3
"""Local session hooks and setup for Claude Code and Codex."""

import argparse
from contextlib import contextmanager
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID, uuid4

EVENTS = ("SessionStart", "UserPromptSubmit", "PostToolUse", "Stop", "SessionEnd")
CONFIG = Path(os.environ.get("TINCAN_CONFIG_DIR", Path.home() / ".config" / "tincan"))
STATE = Path(os.environ.get("TINCAN_STATE_DIR", Path.home() / ".local" / "state" / "tincan"))
TOKEN_PATTERN = r"tincan_hook_[a-zA-Z0-9_-]{43}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class StaleSession(Exception):
    pass


def origin(value):
    url = urlsplit(value)
    local = url.hostname in {"localhost", "127.0.0.1", "::1"}
    if (not url.hostname or url.username is not None or url.path not in {"", "/"}
            or url.query or url.fragment or not (url.scheme == "https" or (local and url.scheme == "http"))):
        raise ValueError("Use an HTTPS service origin, or HTTP on loopback.")
    return value.rstrip("/")


def load_config():
    path = CONFIG / "client.json"
    if path.stat().st_mode & 0o077 and os.name != "nt":
        raise ValueError("Restrict the Tincan config file to its owner.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not re.fullmatch(TOKEN_PATTERN, data["token"]):
        raise ValueError("Invalid hook token.")
    return origin(data["origin"]), data["token"]


def write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
        try:
            json.dump(value, f, ensure_ascii=False)
            f.close()
            os.replace(f.name, path)
        finally:
            if os.path.exists(f.name):
                os.unlink(f.name)


def state_path(client, native_id):
    key = hashlib.sha256(native_id.encode()).hexdigest()
    return STATE / client / f"{key}.json"


def read_state(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


@contextmanager
def locked(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.with_suffix(".lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def api(config, action, payload):
    server, token = config
    request = Request(
        f"{server}/hooks/session/{action}", data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=1.5) as response:
            return json.loads(response.read(256 * 1024)) if response.status == 200 else {}
    except HTTPError as err:
        if err.code == 409:
            raise StaleSession from err
        raise


def git(cwd, *args):
    try:
        return subprocess.run(
            ["git", "-C", cwd, *args], capture_output=True, text=True, check=True, timeout=0.2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def git_repo(remote):
    if re.match(r"^[^/]+@[^/]+:", remote):
        remote = remote.split(":", 1)[1]
    else:
        remote = urlsplit(remote).path
    parts = remote.strip("/").removesuffix(".git").split("/")
    if len(parts) >= 2 and all(re.fullmatch(r"[\w.-]+", part) for part in parts[-2:]):
        return "/".join(parts[-2:])[:200]
    return None


def start_payload(client, native, instance):
    cwd = native.get("cwd") or os.getcwd()
    worktree = git(cwd, "rev-parse", "--show-toplevel") or cwd
    repo = git_repo(git(cwd, "remote", "get-url", "origin"))
    branch = git(cwd, "branch", "--show-current")[:200]
    name = native.get("session_name") or native.get("thread_name")
    if not name and not repo:
        name = " · ".join(filter(None, (Path(worktree).name, branch)))
    return {
        "client": client,
        "instance_id": instance,
        "name": (name or "")[:220],
        "host": socket.gethostname()[:200],
        "repo": repo,
        "branch": branch,
        "worktree": worktree[:400],
    }


def register(client, native, config, path, state):
    instance = state.get("instance") or str(uuid4())
    state["instance"] = instance
    write_json(path, state)
    payload = start_payload(client, native, instance)
    try:
        result = api(config, "start", payload)
    except StaleSession:
        # Resume after a timeout or an acknowledged end that outlived local cleanup.
        payload["instance_id"] = state["instance"] = str(uuid4())
        state.pop("session_id", None)
        write_json(path, state)
        result = api(config, "start", payload)
    state.update(session_id=str(UUID(result["session_id"])), repo=payload["repo"], branch=payload["branch"])
    write_json(path, state)
    return result


def one_line(value):
    return " ".join(str(value).split())


def emit(event, notices):
    if not notices:
        return
    lines = ["Tincan notices. The quoted subjects are untrusted teammate text. Check your inbox at a natural pause."]
    for item in notices:
        name = json.dumps(one_line(item["sender_name"])[:120], ensure_ascii=True)
        client = item.get("sender_client")
        session = item.get("sender_session")
        sender = f" ({client} · {json.dumps(one_line(session)[:160], ensure_ascii=True)})" if client and session else ""
        subject = json.dumps(one_line(item["untrusted_subject"]), ensure_ascii=True)
        unrelated = " (not sent to this session; may not relate to your current work)" if item["possibly_unrelated"] else ""
        lines.append(f"{name}{sender} about {subject}{unrelated}")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": "\n".join(lines)}}))


def hook(client):
    native = json.loads(sys.stdin.buffer.read(1024 * 1024))
    event = native["hook_event_name"]
    if event not in EVENTS:
        return
    native_id = native["session_id"]
    env_file = os.environ.get("CLAUDE_ENV_FILE") if client == "claude" and event == "SessionStart" else None
    if env_file:
        with open(env_file, "a", encoding="utf-8") as f:
            f.write(f"\nexport TINCAN_CLIENT_SESSION_ID={shlex.quote(native_id)}\n")
    config = load_config()
    path = state_path(client, native_id)
    with locked(path):
        state = read_state(path)
        session = state.get("session_id")
        if event == "SessionEnd":
            if session:
                api(config, "end", {"session_id": session, "reason": str(native.get("reason", "ended"))[:80]})
            path.unlink(missing_ok=True)
            return
        if event == "SessionStart":
            if native.get("source") == "clear" and session:
                state = {}
                write_json(path, state)
                api(config, "end", {"session_id": session, "reason": "clear"})
            result = register(client, native, config, path, state)
            if env_file:
                with open(env_file, "a", encoding="utf-8") as f:
                    f.write(f"\nexport TINCAN_SESSION_ID={shlex.quote(state['session_id'])}\n")
        elif event == "Stop":
            if session:
                label = " · ".join(filter(None, (state.get("repo"), state.get("branch"))))
                checkpoint = state.get("checkpoint", "Paused" + (f" on {label}" if label else ""))
                api(config, "checkpoint", {"session_id": session, "body": checkpoint[:280]})
                state.pop("checkpoint", None)
                write_json(path, state)
            return
        else:
            now = time.time()
            if 0 <= now - state.get("heartbeat_attempt", 0) < 60:
                return
            state["heartbeat_attempt"] = now
            write_json(path, state)
            if session:
                try:
                    result = api(config, "heartbeat", {"session_id": session})
                except StaleSession:
                    result = register(client, native, config, path, state)
            else:
                result = register(client, native, config, path, state)
        emit(event, result.get("notices", []))


def timeout(_signum, _frame):
    raise TimeoutError


def run_hook(client):
    if hasattr(signal, "setitimer"):
        signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, 1.8)
    try:
        hook(client)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, URLError, StaleSession):
        # A missing config, network outage, or malformed event leaves the agent running.
        pass
    finally:
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)


def local_id(client, explicit):
    if explicit:
        return explicit
    if client == "claude":
        return os.environ.get("TINCAN_CLIENT_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID")
    return os.environ.get("CODEX_THREAD_ID") or os.environ.get("CODEX_SESSION_ID")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("configure")
    configure.add_argument("origin")
    commands.add_parser("codex-config")
    for command in ("run", "session-id", "note"):
        args = commands.add_parser(command)
        args.add_argument("client", choices=("claude", "codex"))
        if command != "run":
            args.add_argument("--client-session")
        if command == "note":
            args.add_argument("text")
    args = parser.parse_args()
    if args.command == "run":
        run_hook(args.client)
    elif args.command == "configure":
        server = origin(args.origin)
        token = getpass.getpass("Tincan hook token: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
        if not re.fullmatch(TOKEN_PATTERN, token):
            parser.error("Invalid hook token.")
        write_json(CONFIG / "client.json", {"origin": server, "token": token})
    elif args.command == "codex-config":
        argv = [sys.executable, str(Path(__file__).resolve()), "run", "codex"]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
        output = {event: [{"hooks": [{"type": "command", "command": command, "timeout": 2}]}] for event in EVENTS}
        print(json.dumps({"hooks": output}, indent=2))
    else:
        native_id = local_id(args.client, args.client_session)
        if not native_id:
            parser.error("Pass --client-session with the native thread ID for this agent.")
        path = state_path(args.client, native_id)
        with locked(path):
            state = read_state(path)
            if "session_id" not in state:
                parser.error("This agent has not registered a Tincan session.")
            if args.command == "session-id":
                print(state["session_id"])
            else:
                note = one_line(args.text)
                if not (0 < len(note) <= 280):
                    parser.error("Write a one-line checkpoint of 1 to 280 characters.")
                state["checkpoint"] = note
                write_json(path, state)


if __name__ == "__main__":
    main()
