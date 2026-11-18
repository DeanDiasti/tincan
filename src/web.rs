use std::{sync::Arc, time::Duration};

use anyhow::Error;
use askama::Template;
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use sqlx::FromRow;
use url::Url;
use uuid::Uuid;

use crate::{
    App,
    auth::{
        GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL, VerifyError, pkce_challenge, random_token, token_hash,
    },
    hooks::TOKEN_PREFIX,
    sessions::{self, Session},
    store::{self, Teammate},
    subject::one_line,
};

const CALLBACK: &str = "/auth/google/callback";

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/", get(home))
        .route("/style.css", get(styles))
        .route("/auth/google", get(login))
        .route(CALLBACK, get(callback))
        .route("/channels", post(change_channel))
        .route("/logout", post(logout))
        .route("/credentials", post(issue_token))
        .route("/credentials/revoke", post(revoke_token))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::map_response(web_headers))
}

async fn web_headers(mut response: Response) -> Response {
    for (key, value) in [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ] {
        response.headers_mut().insert(key, value.parse().unwrap());
    }
    response
}

async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../templates/style.css"),
    )
}

#[derive(Template)]
#[template(path = "home.html")]
struct Home {
    session: Option<WebSession>,
    teammates: Vec<Teammate>,
    mcp_url: Url,
    credentials: Vec<Credential>,
    clients: Vec<Session>,
    issued: Option<String>,
}

#[derive(FromRow)]
struct WebSession {
    user_id: Uuid,
    name: String,
    csrf_token: String,
}

async fn home(State(app): State<Arc<App>>, jar: CookieJar) -> Result<Html<String>, WebError> {
    let session = web_session(&app, &jar).await?;
    render_home(&app, session, None).await
}

#[derive(FromRow)]
struct Credential {
    id: Uuid,
    label: String,
    revoked: bool,
}

async fn render_home(
    app: &App,
    session: Option<WebSession>,
    issued: Option<String>,
) -> Result<Html<String>, WebError> {
    let (teammates, credentials, clients) = if let Some(account) = &session {
        tokio::try_join!(
            store::teammates(&app.db, account.user_id),
            sqlx::query_as(
                "SELECT id, label, revoked_at IS NOT NULL AS revoked
                            FROM hook_credentials WHERE user_id = $1 ORDER BY created_at DESC"
            )
            .bind(account.user_id)
            .fetch_all(&app.db),
            sessions::own_sessions(&app.db, account.user_id),
        )?
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    Ok(Html(
        Home {
            session,
            teammates,
            credentials,
            clients,
            issued,
            mcp_url: app.config.url("/mcp"),
        }
        .render()
        .map_err(Error::from)?,
    ))
}

#[derive(Deserialize)]
struct IssueToken {
    csrf: String,
    label: String,
}

async fn issue_token(
    State(app): State<Arc<App>>,
    jar: CookieJar,
    Form(form): Form<IssueToken>,
) -> Result<Html<String>, WebError> {
    let session = authorize_form(&app, &jar, &form.csrf).await?;
    let label = one_line(&form.label);
    if !(1..=80).contains(&label.chars().count()) {
        return Err(WebError::InvalidLabel);
    }
    let token = format!("{TOKEN_PREFIX}{}", random_token()?);
    sqlx::query("INSERT INTO hook_credentials (user_id, token_hash, label) VALUES ($1, $2, $3)")
        .bind(session.user_id)
        .bind(token_hash(&token))
        .bind(label)
        .execute(&app.db)
        .await?;
    render_home(&app, Some(session), Some(token)).await
}

#[derive(Deserialize)]
struct RevokeToken {
    csrf: String,
    id: Uuid,
}

async fn revoke_token(
    State(app): State<Arc<App>>,
    jar: CookieJar,
    Form(form): Form<RevokeToken>,
) -> Result<Redirect, WebError> {
    let session = authorize_form(&app, &jar, &form.csrf).await?;
    sqlx::query(
        "UPDATE hook_credentials SET revoked_at = now()
                 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(form.id)
    .bind(session.user_id)
    .execute(&app.db)
    .await?;
    Ok(Redirect::to("/#hook-tokens"))
}

async fn login(State(app): State<Arc<App>>, jar: CookieJar) -> Result<impl IntoResponse, WebError> {
    let state = random_token()?;
    let nonce = random_token()?;
    let verifier = random_token()?;
    sqlx::query("DELETE FROM web_login_attempts WHERE expires_at <= now()")
        .execute(&app.db)
        .await?;
    sqlx::query(
        "INSERT INTO web_login_attempts (state_hash, nonce, verifier, expires_at)
         VALUES ($1, $2, $3, now() + interval '10 minutes')",
    )
    .bind(token_hash(&state))
    .bind(&nonce)
    .bind(&verifier)
    .execute(&app.db)
    .await?;
    let mut url = Url::parse(GOOGLE_AUTH_URL).expect("static provider URL");
    url.query_pairs_mut().extend_pairs([
        ("client_id", app.config.google_client_id.as_str()),
        ("redirect_uri", app.config.url(CALLBACK).as_str()),
        ("response_type", "code"),
        ("scope", "openid email profile"),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge", &pkce_challenge(&verifier)),
        ("code_challenge_method", "S256"),
        ("hd", &app.config.workspace_domain),
    ]);
    let jar = jar.add(cookie(
        &app,
        "tincan_login",
        state,
        Duration::from_secs(600),
    ));
    Ok((jar, Redirect::to(url.as_str())))
}

#[derive(Deserialize)]
struct Callback {
    state: Option<String>,
    code: Option<String>,
}

#[derive(FromRow)]
struct LoginAttempt {
    nonce: String,
    verifier: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

async fn callback(
    State(app): State<Arc<App>>,
    jar: CookieJar,
    Query(params): Query<Callback>,
) -> Result<impl IntoResponse, WebError> {
    let state = params
        .state
        .as_deref()
        .filter(|state| {
            jar.get(&cookie_name(&app, "tincan_login"))
                .is_some_and(|c| c.value() == *state)
        })
        .ok_or(WebError::InvalidLogin)?;
    let attempt: LoginAttempt = sqlx::query_as(
        "DELETE FROM web_login_attempts WHERE state_hash = $1 AND expires_at > now()
         RETURNING nonce, verifier",
    )
    .bind(token_hash(state))
    .fetch_optional(&app.db)
    .await?
    .ok_or(WebError::InvalidLogin)?;

    let code = params.code.ok_or(WebError::InvalidLogin)?;
    let token = app
        .http
        .post(GOOGLE_TOKEN_URL)
        .form(&[
            ("client_id", app.config.google_client_id.as_str()),
            ("client_secret", &app.config.google_client_secret),
            ("grant_type", "authorization_code"),
            ("redirect_uri", app.config.url(CALLBACK).as_str()),
            ("code_verifier", &attempt.verifier),
            ("code", &code),
        ])
        .send()
        .await
        .map_err(Error::from)?
        .error_for_status()
        .map_err(Error::from)?
        .json::<TokenResponse>()
        .await
        .map_err(Error::from)?;
    let identity = app
        .google
        .google_identity(
            &app.http,
            &token.id_token,
            &app.config.workspace_domain,
            &attempt.nonce,
        )
        .await
        .map_err(|err| match err {
            VerifyError::Invalid | VerifyError::InsufficientScope => WebError::InvalidLogin,
            VerifyError::Unavailable(err) => WebError::Internal(err),
        })?;
    let user = store::upsert_user(&app.db, &identity).await?;

    let session = random_token()?;
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM web_sessions WHERE expires_at <= now() OR token_hash = $1")
        .bind(session_hash(&app, &jar))
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO web_sessions (token_hash, user_id, csrf_token, expires_at)
         VALUES ($1, $2, $3, now() + interval '8 hours')",
    )
    .bind(token_hash(&session))
    .bind(user.id)
    .bind(random_token()?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let jar = jar
        .remove(cookie(&app, "tincan_login", String::new(), Duration::ZERO))
        .add(cookie(
            &app,
            "tincan_session",
            session,
            Duration::from_secs(8 * 3600),
        ));
    Ok((jar, Redirect::to("/")))
}

#[derive(Deserialize)]
struct ChannelForm {
    teammate: Uuid,
    allow: bool,
    csrf: String,
}

async fn change_channel(
    State(app): State<Arc<App>>,
    jar: CookieJar,
    Form(form): Form<ChannelForm>,
) -> Result<Redirect, WebError> {
    let session = authorize_form(&app, &jar, &form.csrf).await?;
    store::set_channel(&app.db, session.user_id, form.teammate, form.allow).await?;
    Ok(Redirect::to("/"))
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf: String,
}

async fn logout(
    State(app): State<Arc<App>>,
    jar: CookieJar,
    Form(form): Form<LogoutForm>,
) -> Result<impl IntoResponse, WebError> {
    authorize_form(&app, &jar, &form.csrf).await?;
    sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1")
        .bind(session_hash(&app, &jar))
        .execute(&app.db)
        .await?;
    Ok((
        jar.remove(cookie(
            &app,
            "tincan_session",
            String::new(),
            Duration::ZERO,
        )),
        Redirect::to("/"),
    ))
}

async fn authorize_form(app: &App, jar: &CookieJar, csrf: &str) -> Result<WebSession, WebError> {
    let session = web_session(app, jar).await?.ok_or(WebError::Forbidden)?;
    if csrf != session.csrf_token {
        return Err(WebError::Forbidden);
    }
    Ok(session)
}

async fn web_session(app: &App, jar: &CookieJar) -> sqlx::Result<Option<WebSession>> {
    let Some(hash) = session_hash(app, jar) else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT s.user_id, u.display_name AS name, s.csrf_token
         FROM web_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(hash)
    .fetch_optional(&app.db)
    .await
}

fn session_hash(app: &App, jar: &CookieJar) -> Option<Vec<u8>> {
    jar.get(&cookie_name(app, "tincan_session"))
        .map(|c| token_hash(c.value()))
}

fn cookie_name(app: &App, name: &str) -> String {
    if app.config.public_url.scheme() == "https" {
        format!("__Host-{name}")
    } else {
        name.to_owned()
    }
}

fn cookie(app: &App, name: &str, value: String, ttl: Duration) -> Cookie<'static> {
    Cookie::build((cookie_name(app, name), value))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(app.config.public_url.scheme() == "https")
        .path("/")
        .max_age(ttl.try_into().expect("short cookie lifetime"))
        .build()
}

enum WebError {
    InvalidLogin,
    Forbidden,
    InvalidLabel,
    Internal(Error),
}

impl From<Error> for WebError {
    fn from(err: Error) -> Self {
        Self::Internal(err)
    }
}

impl From<sqlx::Error> for WebError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(err.into())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidLogin => (StatusCode::BAD_REQUEST, "Sign-in expired or your Google Workspace account could not be verified. Return to Tincan and try again.").into_response(),
            Self::InvalidLabel => (StatusCode::BAD_REQUEST, "Use a token label from 1 to 80 characters.").into_response(),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Refresh Tincan and try again.").into_response(),
            Self::Internal(err) => {
                tracing::error!(%err, "Web request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Tincan could not complete your request.").into_response()
            }
        }
    }
}
