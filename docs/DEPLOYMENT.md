# Deployment and team rollout

## Service

Build the OCI image and run it behind the team's HTTPS reverse proxy.

```bash
docker build -t tincan:local .
docker run --rm --env-file /path/to/tincan.env -p 127.0.0.1:3000:3000 tincan:local
```

If the builder cannot reach the Rust registry, run Cargo on a host with trusted registry access and pass the verified sources to the build.

```bash
cargo_sources=$(mktemp -d)
cargo vendor --locked "$cargo_sources/vendor"
docker build --build-context "cargo-vendor=$cargo_sources" -t tincan:local .
```

Set the environment variables in the [README](../README.md). Store the Google OAuth client secret and database connection in the hosting platform's secret store. Preserve the public `Host` header at the proxy, including on `/mcp`. Allow the service's HTTPS requests to the broker's signing-key endpoint and to Google. Use `/healthz` as the readiness check.

Provision a dedicated managed PostgreSQL database and a login role for Tincan. Give it database access and ownership of the application schema so it can run migrations. Keep the role confined to the Tincan database and give it ordinary application privileges. The service applies migrations when it starts. Enable provider backups before rollout.

Choose the MCP authorization server and hosting platform with the team. Before onboarding teammates, use the provider's registered client or registration workflow and confirm that both clients acquire tokens for the Tincan resource. Test sign-in with both a Workspace account and an account outside the allowed domain.

## Client distribution

The [plugin directory](../plugin/) contains a Claude Code plugin and a shared hook adapter for both Claude Code and Codex. For the team plugin sync, distribute the directory as a unit so the manifest, hooks, and skill stay together. Generate the Codex hook entry after the adapter has a stable installed path. Keep each machine's token in its local Tincan configuration. The same person can issue and revoke separate tokens per machine in the web UI.

1. Install the hooks and connect MCP on two teammates' machines using the [README](../README.md).
2. Sign the same account into Claude Code and Codex. Verify both return the same user ID from `whoami`.
3. Have a second teammate open a one-way channel. Send a message, confirm its notice excludes the body, and verify the recipient can read it. Use a third account without a channel to verify session and ownership lookup stays private.
4. Claim a test PR, publish a checkpoint, send to that session, and close it before completing the mail. Start another session for the same recipient and verify the message can still be claimed. Test revoking both a channel and a hook token.

Keep mail delivery pull-only. The rollout requires the team's `alterion-hooks` sync destination, hosted OAuth configuration, and managed database.
