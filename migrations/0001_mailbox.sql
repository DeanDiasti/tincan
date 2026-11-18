CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    google_sub text NOT NULL UNIQUE,
    email text NOT NULL,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE channels (
    recipient_user_id uuid NOT NULL REFERENCES users(id),
    sender_user_id uuid NOT NULL REFERENCES users(id),
    opened_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    PRIMARY KEY (recipient_user_id, sender_user_id),
    CHECK (recipient_user_id <> sender_user_id)
);

CREATE TABLE messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_user_id uuid NOT NULL REFERENCES users(id),
    recipient_user_id uuid NOT NULL REFERENCES users(id),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 80),
    body text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 16384),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX messages_inbox_idx ON messages (recipient_user_id, created_at DESC, id DESC);

CREATE TABLE web_login_attempts (
    state_hash bytea PRIMARY KEY,
    nonce text NOT NULL,
    verifier text NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE web_sessions (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    expires_at timestamptz NOT NULL
);
