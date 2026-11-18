use axum::{
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use super::*;

const ISSUER: &str = "https://broker.example.test";
const DOMAIN: &str = "team.example.test";
const RESOURCE: &str = "http://localhost:3000/mcp";

struct Issuer {
    key: EncodingKey,
    jwks_url: url::Url,
    server: tokio::task::JoinHandle<()>,
}

impl Issuer {
    async fn start() -> Self {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let jwks = json!({ "keys": [{
            "kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())
        }] });
        let key = EncodingKey::from_rsa_der(private.to_pkcs1_der().unwrap().as_bytes());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jwks_url = format!("http://{}/keys", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/keys", get(async move || Json(jwks))),
            )
            .await
            .unwrap();
        });
        Self {
            key,
            jwks_url,
            server,
        }
    }

    fn sign(&self, claims: Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test".into());
        encode(&header, &claims, &self.key).unwrap()
    }

    fn claims(&self, person: &str, client: &str) -> Value {
        json!({
            "iss": ISSUER, "sub": client, "google_sub": person,
            "aud": RESOURCE, "exp": chrono::Utc::now().timestamp() + 120,
            "hd": DOMAIN, "email": format!("{person}@{DOMAIN}"),
            "email_verified": true, "name": person, "scope": "tincan"
        })
    }
}

impl Drop for Issuer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn config(jwks_url: url::Url) -> Config {
    Config {
        database_url: String::new(),
        bind: "127.0.0.1:3000".parse().unwrap(),
        public_url: "http://localhost:3000".parse().unwrap(),
        workspace_domain: DOMAIN.into(),
        google_client_id: "web-client".into(),
        google_client_secret: "fixture".into(),
        mcp_issuer: ISSUER.into(),
        mcp_jwks_url: jwks_url,
        mcp_scope: "tincan".into(),
    }
}

async fn request(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.unwrap()
}

fn mcp_request(token: Option<&str>, method: &str, params: Value) -> Request<Body> {
    let mut builder = Request::post(RESOURCE)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::HOST, "localhost:3000")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .body(Body::from(
            json!({
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params
            })
            .to_string(),
        ))
        .unwrap()
}

async fn body(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn rpc(app: &Router, token: &str, method: &str, params: Value) -> Value {
    let response = request(app, mcp_request(Some(token), method, params)).await;
    let status = response.status();
    let body = body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let payload: Value = serde_json::from_str(&body).unwrap();
    assert!(payload.get("error").is_none(), "{payload}");
    payload["result"].clone()
}

async fn tool(app: &Router, token: &str, name: &str, arguments: Value) -> Value {
    rpc(
        app,
        token,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
    .await
}

fn form(path: &str, fields: String) -> Request<Body> {
    Request::post(path)
        .header(header::COOKIE, "tincan_session=alice-session")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(fields))
        .unwrap()
}

async fn hook_token(db: &PgPool, user: &Value) -> String {
    let token = format!("{}{}", hooks::TOKEN_PREFIX, auth::random_token().unwrap());
    sqlx::query(
        "INSERT INTO hook_credentials (user_id, token_hash, label) VALUES ($1, $2, 'Workstation')",
    )
    .bind(uuid::Uuid::parse_str(user.as_str().unwrap()).unwrap())
    .bind(auth::token_hash(&token))
    .execute(db)
    .await
    .unwrap();
    token
}

async fn hook(app: &Router, token: &str, event: &str, data: Value) -> Response<Body> {
    request(
        app,
        Request::post(format!("/hooks/session/{event}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(data.to_string()))
            .unwrap(),
    )
    .await
}

async fn updates(app: &Router, token: &str, event: &str, data: Value) -> Value {
    let response = hook(app, token, event, data).await;
    let status = response.status();
    let text = body(response).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str(&text).unwrap()
}

async fn start_hook(app: &Router, token: &str, client: &str, name: &str) -> Value {
    let payload = json!({"client": client, "name": name,
        "instance_id": uuid::Uuid::new_v4(), "repo": "dev/project"});
    updates(app, token, "start", payload).await
}

#[sqlx::test]
async fn channel_consent_and_mailbox_privacy(db: PgPool) {
    let issuer = Issuer::start().await;
    let app_state = Arc::new(App::new(config(issuer.jwks_url.clone()), db.clone()).unwrap());
    let app = router(app_state.clone());
    let alice_first = issuer.sign(issuer.claims("Alice", "first-client"));
    let alice_second = issuer.sign(issuer.claims("Alice", "second-client"));
    let bob = issuer.sign(issuer.claims("Bob", "second-client"));

    let response = request(&app, mcp_request(None, "tools/list", json!({}))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("/.well-known/oauth-protected-resource/mcp")
    );
    for (claim, value) in [
        ("hd", json!("another.example.test")),
        ("aud", json!("web-client")),
        ("iss", json!("https://another.example.test")),
        ("exp", json!(1)),
        ("google_sub", Value::Null),
        ("email_verified", json!(false)),
    ] {
        let mut invalid = issuer.claims("Alice", "first-client");
        invalid[claim] = value;
        let response = request(
            &app,
            mcp_request(Some(&issuer.sign(invalid)), "tools/list", json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{claim}");
    }

    let mut unscoped = issuer.claims("Alice", "first-client");
    unscoped["scope"] = json!("unrelated");
    let response = request(
        &app,
        mcp_request(Some(&issuer.sign(unscoped)), "tools/list", json!({})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("insufficient_scope")
    );

    let mut wrong_origin = mcp_request(Some(&alice_first), "tools/list", json!({}));
    wrong_origin.headers_mut().insert(
        header::ORIGIN,
        "https://unrelated.example.test".parse().unwrap(),
    );
    assert_eq!(
        request(&app, wrong_origin).await.status(),
        StatusCode::FORBIDDEN
    );

    let init = rpc(
        &app,
        &alice_first,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "integration-test", "version": "1"}
        }),
    )
    .await;
    assert_eq!(init["serverInfo"]["name"], "tincan");
    let tools = rpc(&app, &alice_first, "tools/list", json!({})).await;
    assert_eq!(tools["tools"].as_array().unwrap().len(), 11);

    let alice =
        tool(&app, &alice_first, "whoami", json!({})).await["structuredContent"]["id"].clone();
    let same = tool(&app, &alice_second, "whoami", json!({})).await;
    assert_eq!(alice, same["structuredContent"]["id"]);
    let bob_id = tool(&app, &bob, "whoami", json!({})).await["structuredContent"]["id"].clone();

    let google = JwtVerifier::new(
        &["https://accounts.google.com"],
        "web-client".into(),
        issuer.jwks_url.clone(),
    );
    let mut google_claims = issuer.claims("Alice", "Alice");
    google_claims["iss"] = json!("https://accounts.google.com");
    google_claims["aud"] = json!("web-client");
    google_claims["nonce"] = json!("login-nonce");
    let id_token = issuer.sign(google_claims);
    assert!(matches!(
        google
            .google_identity(&app_state.http, &id_token, DOMAIN, "wrong-nonce")
            .await,
        Err(auth::VerifyError::Invalid)
    ));
    let identity = google
        .google_identity(&app_state.http, &id_token, DOMAIN, "login-nonce")
        .await
        .ok()
        .unwrap();
    let web_user = store::upsert_user(&db, &identity).await.unwrap();
    assert_eq!(json!(web_user.id), alice);

    let alice_hook_token = hook_token(&db, &alice).await;
    let bob_hook_token = hook_token(&db, &bob_id).await;
    let alice_session = start_hook(&app, &alice_hook_token, "claude", "Alice worktree").await;
    let bob_session = start_hook(&app, &bob_hook_token, "codex", "Bob worktree").await;
    let message = json!({"session_id": bob_session["session_id"], "recipient_user_id": alice, "subject": "Hi\nAlice\u{0007}", "body": "For Alice only"});
    let blocked = tool(&app, &bob, "send_message", message.clone()).await;
    assert_eq!(blocked["isError"], true);
    sqlx::query(
        "INSERT INTO web_sessions VALUES ($1, $2, 'form-token', now() + interval '1 hour')",
    )
    .bind(auth::token_hash("alice-session"))
    .bind(web_user.id)
    .execute(&db)
    .await
    .unwrap();
    let bob_id = bob_id.as_str().unwrap();
    let open = |csrf| format!("teammate={bob_id}&allow=true&csrf={csrf}");
    let rejected = request(&app, form("/channels", open("incorrect"))).await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let opened = request(&app, form("/channels", open("form-token"))).await;
    assert_eq!(opened.status(), StatusCode::SEE_OTHER);
    let page = request(
        &app,
        Request::get("/")
            .header(header::COOKIE, "tincan_session=alice-session")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(body(page).await.contains("Can message you"));
    let reverse = tool(
        &app,
        &alice_first,
        "send_message",
        json!({
            "session_id": alice_session["session_id"], "recipient_user_id": bob_id, "subject": "Reverse", "body": "Should be blocked"
        }),
    )
    .await;
    assert_eq!(reverse["isError"], true);
    for _ in 0..2 {
        let sent = tool(&app, &bob, "send_message", message.clone()).await;
        assert!(
            sent["structuredContent"]["message_id"].is_string(),
            "{sent}"
        );
    }
    let page = tool(&app, &alice_second, "my_inbox", json!({"limit": 1})).await;
    let inbox = &page["structuredContent"];
    assert_eq!(inbox["untrusted_messages"][0]["subject"], "Hi Alice");
    assert_eq!(inbox["untrusted_messages"][0]["body"], "For Alice only");
    let cursor = &inbox["next_before"];
    assert!(cursor.is_string());
    for before in [Value::Null, cursor.clone()] {
        let bobs_inbox = tool(&app, &bob, "my_inbox", json!({"before": before})).await;
        assert_eq!(
            bobs_inbox["structuredContent"]["untrusted_messages"],
            json!([])
        );
    }
    let next = tool(&app, &alice_first, "my_inbox", json!({"before": cursor})).await;
    assert_eq!(
        next["structuredContent"]["untrusted_messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(next["structuredContent"]["next_before"].is_null());

    let close = request(
        &app,
        form(
            "/channels",
            format!("teammate={bob_id}&allow=false&csrf=form-token"),
        ),
    )
    .await;
    assert_eq!(close.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        tool(&app, &bob, "send_message", message).await["isError"],
        true
    );
    let kept = tool(&app, &alice_first, "my_inbox", json!({})).await;
    assert_eq!(
        kept["structuredContent"]["untrusted_messages"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[sqlx::test]
async fn oauth_entrypoints(db: PgPool) {
    let app = router(Arc::new(
        App::new(
            config("https://broker.example.test/keys".parse().unwrap()),
            db,
        )
        .unwrap(),
    ));
    let metadata = request(
        &app,
        Request::get("/.well-known/oauth-protected-resource/mcp")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let metadata: Value = serde_json::from_str(&body(metadata).await).unwrap();
    assert_eq!(metadata["resource"], RESOURCE);
    assert_eq!(metadata["authorization_servers"], json!([ISSUER]));

    let start = request(
        &app,
        Request::get("/auth/google").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let location = url::Url::parse(start.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(location.host_str(), Some("accounts.google.com"));
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(!query["nonce"].is_empty());
    let login_cookie = start.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(login_cookie.contains(&format!("tincan_login={}", query["state"])));
    assert!(login_cookie.contains("HttpOnly"));
    let callback = request(
        &app,
        Request::get("/auth/google/callback?state=unbound&code=ignored")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn targeted_delivery_and_ownership_lifecycle(db: PgPool) {
    let issuer = Issuer::start().await;
    let app = router(Arc::new(
        App::new(config(issuer.jwks_url.clone()), db.clone()).unwrap(),
    ));
    let sender = issuer.sign(issuer.claims("Sender", "codex"));
    let owner = issuer.sign(issuer.claims("Owner", "claude"));
    let outsider = issuer.sign(issuer.claims("Outsider", "codex"));
    let mut actors = Vec::new();
    for token in [&sender, &owner] {
        let id = tool(&app, token, "whoami", json!({})).await["structuredContent"]["id"].clone();
        actors.push((
            uuid::Uuid::parse_str(id.as_str().unwrap()).unwrap(),
            hook_token(&db, &id).await,
        ));
    }
    let (sender_id, sender_hook) = &actors[0];
    let (owner_id, owner_hook) = &actors[1];
    let send_session = &start_hook(&app, sender_hook, "codex", "Fix retry").await["session_id"];
    let old_session = &start_hook(&app, owner_hook, "claude", "Review PR").await["session_id"];
    let other_session = &start_hook(&app, owner_hook, "codex", "Side quest").await["session_id"];

    assert_eq!(
        hook(
            &app,
            owner_hook,
            "checkpoint",
            json!({"session_id":send_session, "body":"forged"})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, mcp_request(Some(owner_hook), "tools/list", json!({})))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(&app, &owner, "heartbeat", json!({"session_id":old_session}))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let spoof = request(
        &app,
        mcp_request(
            Some(&sender),
            "tools/call",
            json!({
                "name":"whoami", "arguments":{"session_id":old_session}
            }),
        ),
    )
    .await;
    assert!(serde_json::from_str::<Value>(&body(spoof).await).unwrap()["error"].is_object());

    store::set_channel(&db, *owner_id, *sender_id, true)
        .await
        .unwrap();
    let claim = tool(
        &app,
        &owner,
        "claim",
        json!({
            "session_id": old_session, "subject_kind":"pr","subject_ref":"DEV/Project#0645"
        }),
    )
    .await;
    assert_eq!(claim["structuredContent"]["subject_ref"], "dev/project#645");
    assert_eq!(
        hook(
            &app,
            owner_hook,
            "checkpoint",
            json!({"session_id":old_session, "body":"Waiting on review"})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );

    let pr = json!({"subject_kind":"pr","subject_ref":"dev/project#645"});
    let current = tool(&app, &sender, "who_owns", pr.clone()).await;
    assert_eq!(current["structuredContent"]["current"]["status"], "active");
    assert_eq!(
        current["structuredContent"]["current"]["untrusted_checkpoint"],
        "Waiting on review"
    );
    let hidden = tool(&app, &outsider, "who_owns", pr.clone()).await;
    assert!(hidden["structuredContent"]["current"].is_null());
    let hidden = tool(
        &app,
        &outsider,
        "find_sessions",
        json!({"repo":"dev/project"}),
    )
    .await;
    assert_eq!(hidden["structuredContent"]["sessions"], json!([]));

    let message = json!({"session_id":send_session, "recipient_user_id": owner_id,
        "target_session_id": old_session, "subject_kind":"pr","subject_ref":"dev/project#645",
        "subject":"Retry loop", "body":"Full private body"});
    let sent = tool(&app, &sender, "send_message", message.clone()).await;
    let message_id = &sent["structuredContent"]["message_id"];
    let thread = &sent["structuredContent"]["thread_id"];
    assert!(message_id.is_string(), "{sent}");

    let other = updates(
        &app,
        owner_hook,
        "heartbeat",
        json!({"session_id":other_session}),
    )
    .await;
    assert_eq!(other["notices"], json!([]));
    let notice = updates(
        &app,
        owner_hook,
        "heartbeat",
        json!({"session_id":old_session}),
    )
    .await;
    assert_eq!(notice["notices"][0]["message_id"], *message_id);
    assert_eq!(notice["notices"][0]["sender_session"], "Fix retry");
    assert_eq!(notice["notices"][0]["possibly_unrelated"], false);
    assert!(!notice.to_string().contains("Full private body"));
    sqlx::query("UPDATE sessions SET last_heartbeat_at = NULL WHERE user_id = $1")
        .bind(owner_id)
        .execute(&db)
        .await
        .unwrap();
    let repeat = updates(
        &app,
        owner_hook,
        "heartbeat",
        json!({"session_id":old_session}),
    )
    .await;
    assert_eq!(repeat["notices"], json!([]));

    let selected = tool(
        &app,
        &owner,
        "claim_message",
        json!({"session_id":old_session,"message_id":message_id}),
    )
    .await;
    assert_eq!(
        selected["structuredContent"]["untrusted_message"]["body"],
        "Full private body"
    );
    assert_eq!(
        hook(
            &app,
            owner_hook,
            "end",
            json!({"session_id":old_session,"reason":"clear"})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let closed = tool(&app, &sender, "who_owns", pr.clone()).await;
    assert_eq!(closed["structuredContent"]["current"]["status"], "closed");
    let found = tool(
        &app,
        &sender,
        "find_sessions",
        json!({"teammate":"owner","repo":"DEV/PROJECT",
        "subject_kind":"pr","subject_ref":"dev/project#645"}),
    )
    .await;
    assert_eq!(
        found["structuredContent"]["sessions"][0]["end_reason"],
        "clear"
    );
    let incoming = start_hook(&app, owner_hook, "claude", "Continuation").await;
    assert_eq!(incoming["notices"][0]["possibly_unrelated"], true);
    let continuation = &incoming["session_id"];

    let stolen = tool(
        &app,
        &sender,
        "claim_message",
        json!({"session_id":send_session,"message_id":message_id}),
    )
    .await;
    assert_eq!(stolen["isError"], true);
    let (left, right) = tokio::join!(
        tool(
            &app,
            &owner,
            "claim_message",
            json!({"session_id":continuation,"message_id":message_id})
        ),
        tool(
            &app,
            &owner,
            "claim_message",
            json!({"session_id":other_session,"message_id":message_id})
        ),
    );
    let claimant = match (left["isError"] == true, right["isError"] == true) {
        (false, true) => continuation,
        (true, false) => other_session,
        _ => panic!("only one session can claim: {left}, {right}"),
    };

    let reply = json!({"session_id":claimant, "message_id":message_id, "body":"Fixed"});
    assert_eq!(
        tool(&app, &owner, "reply", reply.clone()).await["isError"],
        true
    );
    store::set_channel(&db, *sender_id, *owner_id, true)
        .await
        .unwrap();
    let replied = tool(&app, &owner, "reply", reply).await;
    assert_eq!(replied["structuredContent"]["thread_id"], *thread);
    let inbox = tool(
        &app,
        &sender,
        "my_inbox",
        json!({"session_id":send_session}),
    )
    .await;
    assert_eq!(
        inbox["structuredContent"]["untrusted_messages"][0]["targeted_to_this_session"],
        true
    );
    let reply_id = &replied["structuredContent"]["message_id"];
    let clear = tool(
        &app,
        &owner,
        "clear_messages",
        json!({"message_id":reply_id}),
    )
    .await;
    assert_eq!(clear["structuredContent"]["cleared"], 0);
    let reply_args = json!({"session_id":send_session, "message_id":reply_id});
    assert!(tool(&app, &sender, "claim_message", reply_args.clone()).await["structuredContent"]["untrusted_message"].is_object());
    assert_eq!(
        tool(&app, &sender, "complete", reply_args).await["structuredContent"]["state"],
        "done"
    );

    tool(
        &app,
        &owner,
        "claim",
        json!({"session_id": continuation,"subject_kind":"pr","subject_ref":"dev/project#645"}),
    )
    .await;
    let ownership = tool(&app, &sender, "who_owns", pr.clone()).await;
    assert_eq!(
        ownership["structuredContent"]["current"]["session_id"],
        *continuation
    );
    assert_eq!(
        ownership["structuredContent"]["history"][0]["session_id"],
        *old_session
    );
    store::set_channel(&db, *owner_id, *sender_id, false)
        .await
        .unwrap();
    let hidden_again = tool(&app, &sender, "who_owns", pr).await;
    assert!(hidden_again["structuredContent"]["current"].is_null());
    assert_eq!(hidden_again["structuredContent"]["history"], json!([]));
}

#[sqlx::test]
async fn key_issuance_revocation_and_stale_claims(db: PgPool) {
    let app = router(Arc::new(
        App::new(
            config("https://broker.example.test/keys".parse().unwrap()),
            db.clone(),
        )
        .unwrap(),
    ));
    let user = store::upsert_user(
        &db,
        &store::Identity {
            google_sub: "alice".into(),
            name: "Alice".into(),
            email: "alice@example.test".into(),
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO web_sessions VALUES ($1, $2, 'form-token', now() + interval '1 hour')",
    )
    .bind(auth::token_hash("alice-session"))
    .bind(user.id)
    .execute(&db)
    .await
    .unwrap();

    let issued = request(
        &app,
        form("/credentials", "label=Test+machine&csrf=form-token".into()),
    )
    .await;
    assert_eq!(issued.headers()[header::CACHE_CONTROL], "no-store");
    let html = body(issued).await;
    let value = html
        .split_once(hooks::TOKEN_PREFIX)
        .unwrap()
        .1
        .split('<')
        .next()
        .unwrap();
    let token = format!("{}{value}", hooks::TOKEN_PREFIX);
    let token_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM hook_credentials WHERE token_hash = $1")
            .bind(auth::token_hash(&token))
            .fetch_one(&db)
            .await
            .unwrap();
    let session = start_hook(&app, &token, "codex", "Topic").await;
    let session_id = uuid::Uuid::parse_str(session["session_id"].as_str().unwrap()).unwrap();
    let page = body(
        request(
            &app,
            Request::get("/")
                .header(header::COOKIE, "tincan_session=alice-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await,
    )
    .await;
    assert!(page.contains("Test machine") && page.contains("Topic") && !page.contains(&token));

    let revoked = request(
        &app,
        form(
            "/credentials/revoke",
            format!("id={token_id}&csrf=form-token"),
        ),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        hook(&app, &token, "heartbeat", json!({"session_id":session_id}))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let sender = store::upsert_user(
        &db,
        &store::Identity {
            google_sub: "sender".into(),
            name: "Sender".into(),
            email: "sender@example.test".into(),
        },
    )
    .await
    .unwrap();
    // Existing mailbox entries can have no sender session.
    for expires in ["now() + interval '1 hour'", "now() - interval '1 hour'"] {
        let query = format!("INSERT INTO messages (sender_user_id,recipient_user_id,subject,body,state,claimed_by_session_id,claimed_at,expires_at)
                           VALUES ($1,$2,'Subject','Body','claimed',$3,now(),{expires})");
        sqlx::query(&query)
            .bind(sender.id)
            .bind(user.id)
            .bind(session_id)
            .execute(&db)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '7 minutes' WHERE id = $1")
        .bind(session_id)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        sessions::owned(&db, user.id, session_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "idle"
    );
    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '31 minutes' WHERE id = $1")
        .bind(session_id)
        .execute(&db)
        .await
        .unwrap();
    sessions::sweep(&db).await.unwrap();
    assert_eq!(
        sessions::owned(&db, user.id, session_id)
            .await
            .unwrap()
            .unwrap()
            .end_reason
            .as_deref(),
        Some("timeout")
    );
    let states: Vec<String> = sqlx::query_scalar("SELECT state FROM messages ORDER BY state")
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(states, ["expired", "queued"]);
}
