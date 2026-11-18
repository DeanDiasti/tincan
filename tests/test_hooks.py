import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT = Path(__file__).resolve().parents[1] / "plugin/hooks/tincan_hook.py"
TOKEN = "tincan_hook_" + "x" * 43
SESSION = "18907508-e908-462a-af24-575580f4db5b"


class HookTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = dict(os.environ, TINCAN_CONFIG_DIR=str(self.root / "config"),
                        TINCAN_STATE_DIR=str(self.root / "state"),
                        CLAUDE_ENV_FILE=str(self.root / "claude-env"),
                        CODEX_THREAD_ID="native-codex",
                        TINCAN_CLIENT_SESSION_ID="native-claude")
        self.events = []
        context = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                event = self.path.rsplit("/", 1)[1]
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                context.events.append((event, payload, self.headers["Authorization"]))
                if event in {"end", "checkpoint"}:
                    self.send_response(204)
                    self.end_headers()
                    return
                notices = []
                if event == "heartbeat":
                    notices = [{
                        "sender_name": "Teammate\nName", "sender_client": "codex", "sender_session": "A branch",
                        "untrusted_subject": 'Review "the changes"\nplease', "possibly_unrelated": True,
                        "body": "PRIVATE MESSAGE BODY",
                    }]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"session_id": SESSION, "notices": notices}).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def script(self, *args, payload=""):
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=payload, env=self.env,
                              capture_output=True, text=True, timeout=3, check=True).stdout

    def hook(self, client, event, **meta):
        return self.script("run", client, payload=json.dumps({
            "session_id": f"native-{client}", "hook_event_name": event, "cwd": str(self.root), **meta,
        }))

    def test_hook_lifecycle_for_both_clients(self):
        self.script("configure", self.origin, payload=TOKEN)
        self.assertEqual((self.root / "config/client.json").stat().st_mode & 0o777, 0o600)
        for client in ("claude", "codex"):
            with self.subTest(client=client):
                self.assertEqual(self.hook(client, "SessionStart"), "")
                self.assertEqual(self.script("session-id", client).strip(), SESSION)
                output = json.loads(self.hook(client, "PostToolUse"))["hookSpecificOutput"]
                self.assertEqual(output["hookEventName"], "PostToolUse")
                self.assertIn("untrusted teammate text", output["additionalContext"])
                self.assertIn("may not relate to your current work", output["additionalContext"])
                self.assertNotIn("PRIVATE MESSAGE BODY", output["additionalContext"])
                self.assertNotIn("Teammate\nName", output["additionalContext"])
                self.assertEqual(self.hook(client, "UserPromptSubmit"), "")
                self.script("note", client, "Waiting on review")
                self.assertEqual(self.hook(client, "Stop"), "")
                self.assertEqual(self.hook(client, "SessionEnd", reason="clear"), "")
                self.assertEqual([event for event, _, _ in self.events], ["start", "heartbeat", "checkpoint", "end"])
                self.assertEqual(self.events[2][1]["body"], "Waiting on review")
                self.assertEqual(self.events[3][1]["reason"], "clear")
                self.assertTrue(all(auth == f"Bearer {TOKEN}" for _, _, auth in self.events))
                self.events.clear()
        self.assertIn(f"export TINCAN_SESSION_ID={SESSION}", (self.root / "claude-env").read_text())

    def test_fails_open_without_config_or_server(self):
        self.assertEqual(self.hook("codex", "SessionStart"), "")
        self.script("configure", self.origin, payload=TOKEN)
        self.server.shutdown()
        start = time.monotonic()
        self.assertEqual(self.hook("codex", "SessionStart"), "")
        self.assertLess(time.monotonic() - start, 2.5)

    def test_generated_codex_config(self):
        config = json.loads(self.script("codex-config"))
        self.assertEqual(set(config["hooks"]), {"SessionStart", "UserPromptSubmit", "PostToolUse", "Stop", "SessionEnd"})
        for event in config["hooks"].values():
            self.assertIn("run codex", event[0]["hooks"][0]["command"])
            self.assertEqual(event[0]["hooks"][0]["timeout"], 2)


if __name__ == "__main__":
    unittest.main()
