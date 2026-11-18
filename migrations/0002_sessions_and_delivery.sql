CREATE TABLE hook_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    token_hash bytea NOT NULL UNIQUE,
    scope text NOT NULL DEFAULT 'session:publish' CHECK (scope = 'session:publish'),
    label text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX hook_credentials_user_idx ON hook_credentials (user_id, created_at DESC);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    client text NOT NULL CHECK (client IN ('claude', 'codex')),
    instance_id uuid NOT NULL,
    name text NOT NULL,
    host text,
    repo text,
    branch text,
    worktree text,
    started_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at timestamptz,
    ended_at timestamptz,
    end_reason text,
    UNIQUE (user_id, client, instance_id),
    UNIQUE (id, user_id)
);
CREATE INDEX sessions_user_idx ON sessions (user_id, last_seen_at DESC);
CREATE INDEX sessions_stale_idx ON sessions (last_seen_at) WHERE ended_at IS NULL;

CREATE FUNCTION tincan_session_status(last_seen timestamptz, ended timestamptz)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN ended IS NOT NULL OR last_seen <= now() - interval '30 minutes' THEN 'closed'
        WHEN last_seen <= now() - interval '5 minutes' THEN 'idle'
        ELSE 'active'
    END
$$;

CREATE TABLE checkpoints (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES sessions(id),
    body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 280),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX checkpoints_session_idx ON checkpoints (session_id, id DESC);

CREATE TABLE ownership (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_kind text NOT NULL CHECK (subject_kind IN ('ticket', 'pr')),
    subject_ref text NOT NULL,
    session_id uuid NOT NULL,
    user_id uuid NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (session_id, user_id) REFERENCES sessions(id, user_id)
);
CREATE INDEX ownership_subject_idx ON ownership (subject_kind, subject_ref, id DESC);
CREATE INDEX ownership_session_idx ON ownership (session_id);

ALTER TABLE messages
    ADD COLUMN thread_id uuid,
    ADD COLUMN sender_session_id uuid,
    ADD COLUMN target_session_id uuid,
    ADD COLUMN subject_kind text CHECK (subject_kind IN ('ticket', 'pr')),
    ADD COLUMN subject_ref text,
    ADD COLUMN state text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'claimed', 'done', 'cleared', 'expired')),
    ADD COLUMN claimed_by_session_id uuid,
    ADD COLUMN claimed_at timestamptz,
    ADD COLUMN expires_at timestamptz,
    ADD FOREIGN KEY (sender_session_id, sender_user_id) REFERENCES sessions(id, user_id),
    ADD FOREIGN KEY (target_session_id, recipient_user_id) REFERENCES sessions(id, user_id),
    ADD FOREIGN KEY (claimed_by_session_id, recipient_user_id) REFERENCES sessions(id, user_id),
    ADD CHECK ((subject_kind IS NULL) = (subject_ref IS NULL)),
    ADD CHECK ((state IN ('claimed', 'done')) = (claimed_by_session_id IS NOT NULL)),
    ADD CHECK ((claimed_by_session_id IS NULL) = (claimed_at IS NULL));

UPDATE messages SET thread_id = id, expires_at = created_at + interval '14 days';
ALTER TABLE messages ALTER COLUMN thread_id SET NOT NULL,
    ALTER COLUMN thread_id SET DEFAULT gen_random_uuid(),
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN expires_at SET DEFAULT (now() + interval '14 days');

CREATE INDEX messages_expiry_idx ON messages (expires_at) WHERE state = 'queued';
CREATE INDEX messages_claim_idx ON messages (claimed_by_session_id) WHERE state = 'claimed';
CREATE INDEX messages_rate_idx ON messages (sender_session_id, created_at DESC);

CREATE TABLE notifications (
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES sessions(id),
    shown_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, session_id)
);
