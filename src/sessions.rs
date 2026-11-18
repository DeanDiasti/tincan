use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::subject::Subject;

pub type Tx<'a> = Transaction<'a, Postgres>;

#[derive(Serialize, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_name: String,
    pub client: String,
    pub name: String,
    pub host: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub worktree: Option<String>,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub end_reason: Option<String>,
    pub untrusted_checkpoint: Option<String>,
}

#[derive(Serialize, FromRow)]
pub struct Owner {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub user_name: String,
    pub client: String,
    pub session_name: String,
    pub status: String,
    pub closed_at: Option<DateTime<Utc>>,
    pub claimed_at: DateTime<Utc>,
    pub current: bool,
    pub untrusted_checkpoint: Option<String>,
}

#[derive(Serialize, FromRow)]
pub struct Notice {
    pub message_id: Uuid,
    pub sender_name: String,
    pub sender_client: Option<String>,
    pub sender_session: Option<String>,
    pub untrusted_subject: String,
    pub possibly_unrelated: bool,
}

pub async fn owned(db: &PgPool, user: Uuid, id: Uuid) -> sqlx::Result<Option<Session>> {
    let query = format!("{SESSION_DETAILS} WHERE s.id = $1 AND s.user_id = $2");
    sqlx::query_as(&query)
        .bind(id)
        .bind(user)
        .fetch_optional(db)
        .await
}

pub async fn own_sessions(db: &PgPool, user: Uuid) -> sqlx::Result<Vec<Session>> {
    let query = format!(
        "{SESSION_DETAILS} WHERE s.user_id = $1 ORDER BY s.last_seen_at DESC, s.id LIMIT 30"
    );
    sqlx::query_as(&query).bind(user).fetch_all(db).await
}

const SESSION_DETAILS: &str = "
    SELECT s.id, s.user_id, u.display_name AS user_name, s.client, s.name, s.host,
           s.repo, s.branch, s.worktree, s.started_at, s.last_seen_at,
           tincan_session_status(s.last_seen_at, s.ended_at) AS status,
           CASE WHEN tincan_session_status(s.last_seen_at, s.ended_at) = 'closed'
                THEN coalesce(s.ended_at, s.last_seen_at + interval '30 minutes') END AS closed_at,
           CASE WHEN tincan_session_status(s.last_seen_at, s.ended_at) = 'closed'
                THEN coalesce(s.end_reason, 'timeout') END AS end_reason,
           (SELECT body FROM checkpoints WHERE session_id = s.id ORDER BY id DESC LIMIT 1)
               AS untrusted_checkpoint
    FROM sessions s JOIN users u ON u.id = s.user_id";

pub async fn find(
    db: &PgPool,
    caller: Uuid,
    teammate_id: Option<Uuid>,
    teammate: Option<&str>,
    repo: Option<&str>,
    subject: Option<&Subject>,
) -> sqlx::Result<Vec<Session>> {
    let query = format!(
        "{SESSION_DETAILS}
        WHERE (s.user_id = $1 OR EXISTS (
            SELECT 1 FROM channels c WHERE c.recipient_user_id = s.user_id
              AND c.sender_user_id = $1 AND c.closed_at IS NULL
        ))
          AND ($2::uuid IS NULL OR s.user_id = $2)
          AND ($3::text IS NULL OR strpos(lower(u.display_name), lower($3)) > 0)
          AND ($4::text IS NULL OR lower(s.repo) = lower($4))
          AND ($5::text IS NULL OR EXISTS (
              SELECT 1 FROM ownership o
              WHERE o.session_id = s.id AND o.subject_kind = $5 AND o.subject_ref = $6
          ))
        ORDER BY s.last_seen_at DESC, s.id
        LIMIT 100"
    );
    sqlx::query_as(&query)
        .bind(caller)
        .bind(teammate_id)
        .bind(teammate)
        .bind(repo)
        .bind(subject.map(|s| s.kind.as_str()))
        .bind(subject.map(|s| &s.reference))
        .fetch_all(db)
        .await
}

pub async fn owners(db: &PgPool, caller: Uuid, subject: &Subject) -> sqlx::Result<Vec<Owner>> {
    sqlx::query_as(
        "SELECT o.session_id, o.user_id, u.display_name AS user_name, s.client,
                s.name AS session_name, o.claimed_at,
                tincan_session_status(s.last_seen_at, s.ended_at) AS status,
                CASE WHEN tincan_session_status(s.last_seen_at, s.ended_at) = 'closed'
                     THEN coalesce(s.ended_at, s.last_seen_at + interval '30 minutes') END AS closed_at,
                o.id = (SELECT id FROM ownership
                        WHERE subject_kind = $2 AND subject_ref = $3
                        ORDER BY id DESC LIMIT 1) AS current,
                (SELECT body FROM checkpoints WHERE session_id = s.id ORDER BY id DESC LIMIT 1)
                    AS untrusted_checkpoint
         FROM ownership o
         JOIN sessions s ON s.id = o.session_id
         JOIN users u ON u.id = o.user_id
         WHERE o.subject_kind = $2 AND o.subject_ref = $3
           AND (o.user_id = $1 OR EXISTS (
               SELECT 1 FROM channels c WHERE c.recipient_user_id = o.user_id
                 AND c.sender_user_id = $1 AND c.closed_at IS NULL
           ))
         ORDER BY o.id DESC LIMIT 100",
    )
    .bind(caller)
    .bind(subject.kind.as_str())
    .bind(&subject.reference)
    .fetch_all(db)
    .await
}

pub async fn claim_subject(
    tx: &mut Tx<'_>,
    user: Uuid,
    session: Uuid,
    subject: &Subject,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO ownership (subject_kind, subject_ref, user_id, session_id)
                 VALUES ($1, $2, $3, $4)",
    )
    .bind(subject.kind.as_str())
    .bind(&subject.reference)
    .bind(user)
    .bind(session)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn lock_live(tx: &mut Tx<'_>, user: Uuid, session: Uuid) -> sqlx::Result<bool> {
    // Serialize mutations in one session with its end and with the per-session send limit.
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM sessions WHERE id = $1 AND user_id = $2
           AND tincan_session_status(last_seen_at, ended_at) <> 'closed'
         FOR NO KEY UPDATE",
    )
    .bind(session)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

pub async fn release_claims(tx: &mut Tx<'_>, sessions: &[Uuid]) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE messages SET state = CASE WHEN expires_at <= now() THEN 'expired' ELSE 'queued' END,
                             claimed_by_session_id = NULL, claimed_at = NULL
         WHERE state = 'claimed' AND claimed_by_session_id = ANY($1)",
    )
    .bind(sessions).execute(&mut **tx).await?;
    Ok(())
}

pub async fn sweep(db: &PgPool) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    let ended: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE sessions SET ended_at = last_seen_at + interval '30 minutes', end_reason = 'timeout'
         WHERE ended_at IS NULL AND last_seen_at <= now() - interval '30 minutes' RETURNING id",
    ).fetch_all(&mut *tx).await?;
    if !ended.is_empty() {
        release_claims(&mut tx, &ended).await?;
    }
    sqlx::query(
        "UPDATE messages SET state = 'expired' WHERE state = 'queued' AND expires_at <= now()",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

pub async fn notices(tx: &mut Tx<'_>, user: Uuid, session: Uuid) -> sqlx::Result<Vec<Notice>> {
    sqlx::query_as(
        "WITH candidates AS (
            SELECT m.id FROM messages m
            LEFT JOIN sessions t ON t.id = m.target_session_id
            WHERE m.recipient_user_id = $1 AND m.state = 'queued' AND m.expires_at > now()
              AND (t.id IS NULL OR t.id = $2 OR tincan_session_status(t.last_seen_at, t.ended_at) = 'closed')
              AND NOT EXISTS (SELECT 1 FROM notifications n WHERE n.message_id = m.id AND n.session_id = $2)
            ORDER BY m.created_at DESC, m.id DESC LIMIT 50
        ), inserted AS (
            INSERT INTO notifications (message_id, session_id)
            SELECT id, $2 FROM candidates
            ON CONFLICT DO NOTHING RETURNING message_id
        )
        SELECT m.id AS message_id, u.display_name AS sender_name, s.client AS sender_client,
               s.name AS sender_session, m.subject AS untrusted_subject,
               m.target_session_id IS DISTINCT FROM $2 AS possibly_unrelated
        FROM inserted i JOIN messages m ON m.id = i.message_id
        JOIN users u ON u.id = m.sender_user_id
        LEFT JOIN sessions s ON s.id = m.sender_session_id
        ORDER BY m.created_at DESC, m.id DESC",
    )
    .bind(user).bind(session).fetch_all(&mut **tx).await
}
