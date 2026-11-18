use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    App,
    auth::token_hash,
    sessions::{self, Notice, Tx},
    subject::one_line,
};

pub const TOKEN_PREFIX: &str = "tincan_hook_";

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/hooks/session/start", post(start))
        .route("/hooks/session/heartbeat", post(heartbeat))
        .route("/hooks/session/checkpoint", post(checkpoint))
        .route("/hooks/session/end", post(end))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(deadline))
}

async fn deadline(request: Request, next: Next) -> Response {
    match tokio::time::timeout(Duration::from_secs(2), next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Client {
    Claude,
    Codex,
}

impl Client {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

#[derive(Deserialize)]
struct Start {
    client: Client,
    instance_id: Uuid,
    name: Option<String>,
    host: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    worktree: Option<String>,
}

#[derive(Serialize)]
struct Updates {
    session_id: Uuid,
    notices: Vec<Notice>,
}

async fn start(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Start>,
) -> Result<Json<Updates>, HookError> {
    let (user, mut tx) = authorize(&app, &headers).await?;
    let host = field(input.host, 200)?;
    let repo = field(input.repo, 200)?;
    let branch = field(input.branch, 200)?;
    let worktree = field(input.worktree, 400)?;
    let name = field(input.name, 220)?.unwrap_or_else(|| match (&repo, &branch) {
        (Some(repo), Some(branch)) => format!("{repo} · {branch}").chars().take(220).collect(),
        (Some(repo), None) => repo.clone(),
        _ => input.client.as_str().to_owned(),
    });
    let session: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO sessions (user_id, client, instance_id, name, host, repo, branch, worktree)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (user_id, client, instance_id) DO UPDATE SET last_seen_at = now()
           WHERE tincan_session_status(sessions.last_seen_at, sessions.ended_at) <> 'closed'
         RETURNING id",
    )
    .bind(user)
    .bind(input.client.as_str())
    .bind(input.instance_id)
    .bind(name)
    .bind(host)
    .bind(repo)
    .bind(branch)
    .bind(worktree)
    .fetch_optional(&mut *tx)
    .await?;
    let session_id = session.ok_or(HookError::Stale)?;
    let notices = sessions::notices(&mut tx, user, session_id).await?;
    tx.commit().await?;
    Ok(Json(Updates {
        session_id,
        notices,
    }))
}

#[derive(Deserialize)]
struct SessionId {
    session_id: Uuid,
}

async fn heartbeat(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<SessionId>,
) -> Result<Json<Updates>, HookError> {
    let (user, mut tx) = authorize(&app, &headers).await?;
    let session_id = input.session_id;
    if !sessions::lock_live(&mut tx, user, session_id).await? {
        return Err(HookError::Stale);
    }
    let updated = sqlx::query(
        "UPDATE sessions SET last_seen_at = now(), last_heartbeat_at = now() WHERE id = $1
           AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= now() - interval '1 minute')",
    )
    .bind(session_id)
    .execute(&mut *tx)
    .await?;
    let notices = if updated.rows_affected() == 1 {
        sessions::notices(&mut tx, user, session_id).await?
    } else {
        Vec::new()
    };
    tx.commit().await?;
    Ok(Json(Updates {
        session_id,
        notices,
    }))
}

#[derive(Deserialize)]
struct Checkpoint {
    session_id: Uuid,
    body: String,
}

async fn checkpoint(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Checkpoint>,
) -> Result<StatusCode, HookError> {
    let (user, mut tx) = authorize(&app, &headers).await?;
    let body = field(Some(input.body), 280)?.ok_or(HookError::Invalid)?;
    if !sessions::lock_live(&mut tx, user, input.session_id).await? {
        return Err(HookError::Stale);
    }
    sqlx::query("INSERT INTO checkpoints (session_id, body) VALUES ($1, $2)")
        .bind(input.session_id)
        .bind(body)
        .execute(&mut *tx)
        .await?;
    // A stop hook also indicates that the session is still present.
    sqlx::query("UPDATE sessions SET last_seen_at = now() WHERE id = $1")
        .bind(input.session_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct End {
    session_id: Uuid,
    reason: Option<String>,
}

async fn end(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<End>,
) -> Result<StatusCode, HookError> {
    let (user, mut tx) = authorize(&app, &headers).await?;
    let reason = field(input.reason, 80)?.unwrap_or_else(|| "ended".to_owned());
    let ended = sqlx::query(
        "UPDATE sessions SET ended_at = least(now(), last_seen_at + interval '30 minutes'),
             end_reason = CASE WHEN tincan_session_status(last_seen_at, ended_at) = 'closed'
                               THEN 'timeout' ELSE $3 END
         WHERE id = $1 AND user_id = $2 AND ended_at IS NULL",
    )
    .bind(input.session_id)
    .bind(user)
    .bind(reason)
    .execute(&mut *tx)
    .await?;
    if ended.rows_affected() > 0 {
        sessions::release_claims(&mut tx, &[input.session_id]).await?;
    }
    tx.commit().await?;
    // Repeating end is safe and cannot reveal whether another user's session exists.
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize<'a>(app: &'a App, headers: &HeaderMap) -> Result<(Uuid, Tx<'a>), HookError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("bearer") && token.starts_with(TOKEN_PREFIX)
        })
        .map(|(_, token)| token)
        .ok_or(HookError::Unauthorized)?;
    let mut tx = app.db.begin().await?;
    let user = sqlx::query_scalar(
        "SELECT user_id FROM hook_credentials
         WHERE token_hash = $1 AND scope = 'session:publish' AND revoked_at IS NULL FOR SHARE",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(HookError::Unauthorized)?;
    Ok((user, tx))
}

fn field(input: Option<String>, limit: usize) -> Result<Option<String>, HookError> {
    let value = input
        .as_deref()
        .map(one_line)
        .filter(|value| !value.is_empty());
    if value
        .as_ref()
        .is_some_and(|value| value.chars().count() > limit)
    {
        return Err(HookError::Invalid);
    }
    Ok(value)
}

enum HookError {
    Invalid,
    Unauthorized,
    Stale,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for HookError {
    fn from(error: sqlx::Error) -> Self {
        Self::Db(error)
    }
}

impl IntoResponse for HookError {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "Invalid hook input").into_response(),
            Self::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            Self::Stale => (StatusCode::CONFLICT, "Register a live session first").into_response(),
            Self::Db(err) => {
                tracing::warn!(%err, "Session hook failed");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    }
}
