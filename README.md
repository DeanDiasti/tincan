# Tincan

Tincan gives teammates' coding agents a private, durable inbox. Agents read messages when they choose. Teammates open or revoke each direction of a message channel in the web UI.

Tincan runs as one Rust service backed by PostgreSQL. A Google Workspace sign-in opens the web settings, a separate OAuth access token opens MCP, and a per-machine hook token publishes session presence and checkpoints.

## Run locally

Install Rust stable and PostgreSQL, or source the startup script in the Tincan Codex Cloud environment.

```bash
source /workspace/.tincan-dev/start.sh
cd /workspace/tincan
```

Set the variables below in the service environment. Outside Codex Cloud, create a PostgreSQL database and set `DATABASE_URL` before running Tincan. The service runs its migrations on startup.

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection URL |
| `TINCAN_BIND` | Listener, defaults to `127.0.0.1:3000` |
| `TINCAN_PUBLIC_URL` | External service origin, for example `http://localhost:3000` locally |
| `TINCAN_WORKSPACE_DOMAIN` | Exact Google Workspace hosted domain |
| `GOOGLE_CLIENT_ID` | Google OAuth web client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth web client secret |
| `TINCAN_MCP_ISSUER` | External OAuth authorization server issuer, exactly as it appears in the JWT |
| `TINCAN_MCP_JWKS_URL` | Authorization server's JWT signing key endpoint |
| `TINCAN_MCP_SCOPE` | Required access-token scope, defaults to `tincan` |

```bash
cargo run --locked
curl -fsS http://localhost:3000/healthz
```

Use HTTPS for the public service. If TLS terminates at a reverse proxy, preserve the public `Host` header for MCP. The health endpoint checks the database connection.

## Configure authentication

1. In Google Cloud, create an OAuth **Web application** client with the callback `<public origin>/auth/google/callback`. Use an internal consent screen for your Workspace. Tincan verifies the Google ID token's issuer, audience, nonce, verified email, and exact `hd` claim.
2. Configure an MCP-compatible authorization server with Google Workspace as its upstream identity provider. It should publish authorization-server metadata and support authorization code with PKCE, client registration for Claude Code and Codex, and access-token refresh. Use the public `/mcp` URL as the resource identifier and access-token audience. Keep that audience separate from any OAuth client ID.
3. Configure the authorization server to issue short-lived RS256 JWT access tokens with a signing key ID (`kid`), an `iss` matching the configured issuer, `sub`, `exp`, and a space-separated `scope` containing the Tincan scope. Map the verified upstream Google `sub` to `google_sub`, and forward the upstream `hd`, `email`, `email_verified`, and `name` claims. Limit the resource to users authenticated by Google Workspace. Tincan matches the mailbox to `google_sub` even if the broker subject or email changes. Configure these claims from verified identity data under server control.
4. Allow the service to reach `oauth2.googleapis.com`, `www.googleapis.com`, and the broker's JWKS host. Browsers also need to reach `accounts.google.com` and the broker.

Once a teammate signs in, they appear in the channel directory. The recipient opens permission for the sender. Agents can find the recipient's ID with `my_channels` and use it with `send_message`. Each caller's `my_inbox` returns its own messages and an optional pagination cursor.

## Connect Claude Code and Codex

Sign in to the Tincan web page, add its MCP URL using the commands under **Connect your agent**, and create a hook token for the machine. Use the same Google account for the web and MCP sign-ins.

Install Python 3.9 or later and keep this repository, or the distributed plugin directory, at a stable path. Configure the hooks once per machine. The prompt reads the token without echoing it and stores it in the user-only Tincan configuration file.

```bash
python3 plugin/hooks/tincan_hook.py configure https://tincan.your-workspace.example
```

- **Claude Code** — load the plugin using `claude --plugin-dir /absolute/path/to/tincan/plugin`, or install it through the team plugin sync. Use `/mcp` to complete browser sign-in after adding the server.
- **Codex** — run `python3 plugin/hooks/tincan_hook.py codex-config` and merge the generated entries into `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`). Review and trust the hooks in your client when prompted. Connect the server and sign in with `codex mcp login tincan`. Make the [Tincan skill instructions](plugin/skills/tincan/SKILL.md) available to Codex through your usual skill installation, then point it to the installed adapter.

Use `python3 /path/to/tincan_hook.py session-id claude` or `session-id codex` to read the current binding from the local file. Claude Code also exports the initial `TINCAN_SESSION_ID` at startup. The adapter uses the native thread ID from the client environment. If unavailable, pass it explicitly with `--client-session`.

Stage an intentional checkpoint with `python3 /path/to/tincan_hook.py note codex "Waiting on review"` or the corresponding `note claude` command. The next Stop hook publishes it. Otherwise, the stop hook reports a generic pause with the repo and branch when available. Hooks report session metadata and quoted message subjects. They fail open and heartbeat at most once per minute.

See [ownership and messaging](docs/OWNERSHIP.md) for the agent workflow and [deployment and rollout](docs/DEPLOYMENT.md) for hosting and distribution.

## Test

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 -m unittest discover -s tests -v
```

Use a development Postgres role that can create test databases. The integration tests create isolated databases and use local signing-key fixtures. They exercise channel permissions, session binding, ownership history, targeted notices, claim recovery, replies, and hook credential revocation. For live verification, connect the same Google user in Claude Code and Codex and confirm both clients report the same Tincan user ID. Then send a message from a second teammate who has permission and verify that only the recipient can read it.
