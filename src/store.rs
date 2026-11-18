use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

pub struct Identity {
    pub google_sub: String,
    pub email: String,
    pub name: String,
}

#[derive(FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
}

#[derive(FromRow, Serialize)]
pub struct Teammate {
    pub id: Uuid,
    pub name: String,
    pub can_message_me: bool,
    pub i_can_message_them: bool,
}

pub async fn upsert_user(db: &PgPool, identity: &Identity) -> sqlx::Result<User> {
    sqlx::query_as(
        "INSERT INTO users (google_sub, email, display_name)
         VALUES ($1, $2, $3)
         ON CONFLICT (google_sub) DO UPDATE
         SET email = excluded.email, display_name = excluded.display_name
         RETURNING id, email, display_name AS name",
    )
    .bind(&identity.google_sub)
    .bind(&identity.email)
    .bind(&identity.name)
    .fetch_one(db)
    .await
}

pub async fn teammates(db: &PgPool, me: Uuid) -> sqlx::Result<Vec<Teammate>> {
    sqlx::query_as(
        "SELECT u.id, u.display_name AS name,
                inbound.sender_user_id IS NOT NULL AS can_message_me,
                outbound.sender_user_id IS NOT NULL AS i_can_message_them
         FROM users u
         LEFT JOIN channels inbound
           ON (inbound.recipient_user_id, inbound.sender_user_id) = ($1, u.id)
          AND inbound.closed_at IS NULL
         LEFT JOIN channels outbound
           ON (outbound.recipient_user_id, outbound.sender_user_id) = (u.id, $1)
          AND outbound.closed_at IS NULL
         WHERE u.id <> $1
         ORDER BY lower(u.display_name), u.id",
    )
    .bind(me)
    .fetch_all(db)
    .await
}

pub async fn set_channel(
    db: &PgPool,
    recipient: Uuid,
    sender: Uuid,
    open: bool,
) -> sqlx::Result<()> {
    if open {
        sqlx::query(
            "INSERT INTO channels (recipient_user_id, sender_user_id)
             SELECT $1, id FROM users WHERE id = $2 AND id <> $1
             ON CONFLICT (recipient_user_id, sender_user_id) DO UPDATE
             SET opened_at = now(), closed_at = NULL WHERE channels.closed_at IS NOT NULL",
        )
        .bind(recipient)
        .bind(sender)
        .execute(db)
        .await?;
    } else {
        sqlx::query(
            "UPDATE channels SET closed_at = now()
             WHERE recipient_user_id = $1 AND sender_user_id = $2 AND closed_at IS NULL",
        )
        .bind(recipient)
        .bind(sender)
        .execute(db)
        .await?;
    }
    Ok(())
}
