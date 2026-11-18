use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{sessions::Tx, subject::Subject};

#[derive(FromRow, Serialize)]
pub struct Message {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub sender_user_id: Uuid,
    pub sender_name: String,
    pub sender_session_id: Option<Uuid>,
    pub sender_session_name: Option<String>,
    pub target_session_id: Option<Uuid>,
    pub targeted_to_this_session: bool,
    pub subject_kind: Option<String>,
    pub subject_ref: Option<String>,
    pub subject: String,
    pub body: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize)]
pub struct Sent {
    pub message_id: Uuid,
    pub thread_id: Uuid,
}

pub enum Delivery {
    Sent(Sent),
    NoChannel,
    BadTarget,
    RateLimited,
    NotClaimed,
}

pub struct Outgoing<'a> {
    pub recipient: Uuid,
    pub target: Option<Uuid>,
    pub thread: Option<Uuid>,
    pub subject_kind: Option<&'a str>,
    pub subject_ref: Option<&'a str>,
    pub subject: &'a str,
    pub body: &'a str,
}

impl<'a> Outgoing<'a> {
    pub fn new(
        recipient: Uuid,
        target: Option<Uuid>,
        tag: Option<&'a Subject>,
        subject: &'a str,
        body: &'a str,
    ) -> Self {
        Self {
            recipient,
            target,
            thread: None,
            subject,
            body,
            subject_kind: tag.map(|tag| tag.kind.as_str()),
            subject_ref: tag.map(|tag| tag.reference.as_str()),
        }
    }
}

// The caller holds the sender session row until commit.
pub async fn send(
    tx: &mut Tx<'_>,
    sender: Uuid,
    session: Uuid,
    msg: Outgoing<'_>,
) -> sqlx::Result<Delivery> {
    // Keep the permission open through insertion, even if a teammate revokes it concurrently.
    let channel = sqlx::query_scalar::<_, Uuid>(
        "SELECT recipient_user_id FROM channels
         WHERE recipient_user_id = $1 AND sender_user_id = $2 AND closed_at IS NULL FOR SHARE",
    )
    .bind(msg.recipient)
    .bind(sender)
    .fetch_optional(&mut **tx)
    .await?;
    if channel.is_none() {
        return Ok(Delivery::NoChannel);
    }
    if let Some(target) = msg.target {
        let valid = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2)",
        )
        .bind(target)
        .bind(msg.recipient)
        .fetch_one(&mut **tx)
        .await?;
        if !valid {
            return Ok(Delivery::BadTarget);
        }
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM messages
         WHERE sender_session_id = $1 AND created_at > now() - interval '1 minute'",
    )
    .bind(session)
    .fetch_one(&mut **tx)
    .await?;
    if count >= 20 {
        return Ok(Delivery::RateLimited);
    }
    let sent = sqlx::query_as(
        "INSERT INTO messages (sender_user_id, sender_session_id, recipient_user_id,
             target_session_id, thread_id, subject_kind, subject_ref, subject, body)
         VALUES ($1, $2, $3, $4, coalesce($5, gen_random_uuid()), $6, $7, $8, $9)
         RETURNING id AS message_id, thread_id",
    )
    .bind(sender)
    .bind(session)
    .bind(msg.recipient)
    .bind(msg.target)
    .bind(msg.thread)
    .bind(msg.subject_kind)
    .bind(msg.subject_ref)
    .bind(msg.subject)
    .bind(msg.body)
    .fetch_one(&mut **tx)
    .await?;
    Ok(Delivery::Sent(sent))
}

const MESSAGE_COLUMNS: &str = "
    m.id, m.thread_id, m.sender_user_id, u.display_name AS sender_name,
    m.sender_session_id, s.name AS sender_session_name, m.target_session_id,
    coalesce(m.target_session_id = $2, false) AS targeted_to_this_session,
    m.subject_kind, m.subject_ref, m.subject, m.body, m.state, m.created_at, m.expires_at";

pub async fn inbox(
    db: &PgPool,
    recipient: Uuid,
    session: Option<Uuid>,
    before: Option<Uuid>,
    limit: i64,
) -> sqlx::Result<Vec<Message>> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages m
        JOIN users u ON u.id = m.sender_user_id LEFT JOIN sessions s ON s.id = m.sender_session_id
        WHERE m.recipient_user_id = $1 AND m.state = 'queued' AND m.expires_at > now()
          AND ($3::uuid IS NULL OR (m.created_at, m.id) < (
              SELECT created_at, id FROM messages WHERE recipient_user_id = $1 AND id = $3
          ))
        ORDER BY m.created_at DESC, m.id DESC LIMIT $4"
    );
    sqlx::query_as(&sql)
        .bind(recipient)
        .bind(session)
        .bind(before)
        .bind(limit)
        .fetch_all(db)
        .await
}

pub async fn claim(
    tx: &mut Tx<'_>,
    recipient: Uuid,
    session: Uuid,
    id: Uuid,
) -> sqlx::Result<Option<Message>> {
    let sql = format!(
        "WITH claimed AS (
        UPDATE messages SET state = 'claimed', claimed_by_session_id = $2, claimed_at = now()
        WHERE recipient_user_id = $1 AND id = $3 AND state = 'queued' AND expires_at > now()
        RETURNING *
    )
    SELECT {MESSAGE_COLUMNS} FROM claimed m
    JOIN users u ON u.id = m.sender_user_id LEFT JOIN sessions s ON s.id = m.sender_session_id"
    );
    sqlx::query_as(&sql)
        .bind(recipient)
        .bind(session)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
}

pub async fn clear(db: &PgPool, recipient: Uuid, ids: Option<&[Uuid]>) -> sqlx::Result<u64> {
    let result = sqlx::query(
        "UPDATE messages SET state = 'cleared'
         WHERE recipient_user_id = $1 AND state = 'queued' AND expires_at > now()
           AND ($2::uuid[] IS NULL OR id = ANY($2))",
    )
    .bind(recipient)
    .bind(ids)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

pub async fn complete(
    tx: &mut Tx<'_>,
    recipient: Uuid,
    session: Uuid,
    id: Uuid,
) -> sqlx::Result<bool> {
    let result = sqlx::query(
        "UPDATE messages SET state = 'done'
         WHERE recipient_user_id = $1 AND claimed_by_session_id = $2 AND id = $3 AND state = 'claimed'",
    ).bind(recipient).bind(session).bind(id).execute(&mut **tx).await?;
    Ok(result.rows_affected() == 1)
}

#[derive(FromRow)]
struct Original {
    sender_user_id: Uuid,
    sender_session_id: Option<Uuid>,
    thread_id: Uuid,
    subject_kind: Option<String>,
    subject_ref: Option<String>,
    subject: String,
}

pub async fn reply(
    tx: &mut Tx<'_>,
    recipient: Uuid,
    session: Uuid,
    id: Uuid,
    subject: Option<&str>,
    body: &str,
) -> sqlx::Result<Delivery> {
    let original: Option<Original> = sqlx::query_as(
        "SELECT sender_user_id, sender_session_id, thread_id, subject_kind, subject_ref, subject
         FROM messages WHERE recipient_user_id = $1 AND claimed_by_session_id = $2
           AND id = $3 AND state = 'claimed' FOR UPDATE",
    )
    .bind(recipient)
    .bind(session)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(original) = original else {
        return Ok(Delivery::NotClaimed);
    };
    let outgoing = Outgoing {
        recipient: original.sender_user_id,
        target: original.sender_session_id,
        thread: Some(original.thread_id),
        subject_kind: original.subject_kind.as_deref(),
        subject_ref: original.subject_ref.as_deref(),
        subject: subject.unwrap_or(&original.subject),
        body,
    };
    let result = send(tx, recipient, session, outgoing).await?;
    if matches!(result, Delivery::Sent(_)) {
        complete(tx, recipient, session, id).await?;
    }
    Ok(result)
}
