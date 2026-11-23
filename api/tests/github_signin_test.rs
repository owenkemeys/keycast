#![cfg(feature = "integration-tests")]

// ABOUTME: content-web: Sign in with GitHub against a mock GitHub (token exchange and GET /user).
// ABOUTME: Covers PKCE and state, mapping github:<id> to the held key, claiming it, and refusals.

mod common;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    Extension, Form, Json, Router,
};
use chrono::Utc;
use keycast_api::api::{
    http::{
        auth::get_pubkey,
        github_auth::{
            exchange_code_for_user_id, github_callback, github_start, pkce_challenge,
            GithubAuthConfig, GithubAuthError, GithubCallbackQuery,
        },
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::{BcryptAdmission, PrefixedRedis};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::repositories::held_key::HeldKeyRepository;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::Keys;
use serial_test::serial;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const TENANT_ID: i64 = 1;
// TEST HARNESS ONLY: values the mock GitHub expects. None of them is real.
const CLIENT_ID: &str = "Iv1.mockclientid";
const CLIENT_SECRET: &str = "mock-client-secret-not-real";
const GOOD_CODE: &str = "good-code";
const ACCESS_TOKEN: &str = "ghu_mock_user_token_not_real";

#[derive(Clone, Default)]
struct MockGithub {
    user_id: Arc<Mutex<u64>>,
    verifiers: Arc<Mutex<Vec<String>>>,
}

async fn mock_token(
    State(mock): State<MockGithub>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    assert_eq!(
        headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let ok = form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
        && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET)
        && form.get("code").map(String::as_str) == Some(GOOD_CODE)
        && form.get("redirect_uri").map(String::as_str)
            == Some("https://keys.example.test/api/auth/github/callback");
    if let Some(verifier) = form.get("code_verifier") {
        mock.verifiers.lock().unwrap().push(verifier.clone());
    }
    if ok {
        Json(serde_json::json!({ "access_token": ACCESS_TOKEN, "token_type": "bearer" }))
    } else {
        // GitHub's real behaviour for a bad code: 200 with an error body.
        Json(serde_json::json!({ "error": "bad_verification_code" }))
    }
}

async fn mock_user(
    State(mock): State<MockGithub>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if auth != Some(&format!("Bearer {ACCESS_TOKEN}")) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "message": "Bad credentials" })),
        );
    }
    let id = *mock.user_id.lock().unwrap();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "id": id, "login": "mock-user" })),
    )
}

async fn start_mock_github() -> (String, MockGithub) {
    let mock = MockGithub::default();
    let app = Router::new()
        .route("/login/oauth/access_token", axum::routing::post(mock_token))
        .route("/user", axum::routing::get(mock_user))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), mock)
}

fn config(github: &str) -> GithubAuthConfig {
    GithubAuthConfig {
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
        redirect_uri: "https://keys.example.test/api/auth/github/callback".to_string(),
        authorize_url: format!("{github}/login/oauth/authorize"),
        token_url: format!("{github}/login/oauth/access_token"),
        api_url: github.to_string(),
        post_login_redirect: "https://keys.example.test/".to_string(),
    }
}

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("connect");
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("migrations");
    pool
}

async fn auth_state(pool: PgPool) -> AuthState {
    let client = redis::Client::open(std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL"))
        .expect("valid Redis URL");
    let connection = redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect to Redis");
    let key_manager: Arc<Box<dyn KeyManager>> =
        Arc::new(Box::new(FileKeyManager::new().expect("file key manager")));
    AuthState {
        state: Arc::new(KeycastState {
            db: pool,
            key_manager,
            signer_handlers: None,
            http_handler_cache: new_http_handler_cache(),
            account_status_cache: keycast_api::state::new_account_status_cache(),
            server_keys: Keys::generate(),
            tenant_cache: Cache::builder().max_capacity(10).build(),
            bcrypt: BcryptAdmission::new(1, Duration::from_secs(5)),
            redis: Some(PrefixedRedis::new(
                connection,
                Some(format!("keycast-github-test:{}", Uuid::new_v4())),
            )),
            secret_pool: SecretPool::new(1).receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

fn tenant() -> TenantExtractor {
    TenantExtractor(Arc::new(Tenant {
        id: TENANT_ID,
        domain: "keys.example.test".to_string(),
        name: "GitHub Sign-in Test".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

fn unique_github_id() -> u64 {
    (Uuid::new_v4().as_u128() % 9_000_000_000) as u64 + 1_000_000_000
}

fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn cookie_value(cookies: &[String], name: &str) -> Option<String> {
    cookies.iter().find_map(|c| {
        c.strip_prefix(&format!("{name}="))
            .map(|rest| rest.split(';').next().unwrap_or_default().to_string())
    })
}

/// Run /start, returning (state, code_challenge).
async fn start(state: &AuthState, config: &GithubAuthConfig) -> (String, String) {
    let response = github_start(State(state.clone()), Extension(Arc::new(config.clone())))
        .await
        .expect("start");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(&config.authorize_url), "{location}");
    let url = reqwest::Url::parse(&location).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["redirect_uri"], config.redirect_uri);
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(!query.contains_key("client_secret"));
    let cookie_state =
        cookie_value(&set_cookies(&response), "keycast_github_state").expect("state cookie");
    assert_eq!(cookie_state, query["state"]);
    (query["state"].clone(), query["code_challenge"].clone())
}

async fn callback(
    state: &AuthState,
    config: &GithubAuthConfig,
    cookie_state: &str,
    code: &str,
    query_state: &str,
) -> Result<axum::response::Response, GithubAuthError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("other=1; keycast_github_state={cookie_state}")
            .parse()
            .unwrap(),
    );
    github_callback(
        tenant(),
        State(state.clone()),
        Extension(Arc::new(config.clone())),
        headers,
        Query(GithubCallbackQuery {
            code: Some(code.to_string()),
            state: Some(query_state.to_string()),
        }),
    )
    .await
}

async fn session_pubkey(pool: &PgPool, session: &str) -> String {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("keycast_session={session}").parse().unwrap(),
    );
    get_pubkey(tenant(), State(pool.clone()), headers)
        .await
        .expect("session is valid")
        .0
        .pubkey
}

#[tokio::test]
#[serial]
async fn signin_claims_the_existing_held_key() {
    let pool = setup_pool().await;
    let state = auth_state(pool.clone()).await;
    let (github, mock) = start_mock_github().await;
    let config = config(&github);
    let github_id = unique_github_id();
    *mock.user_id.lock().unwrap() = github_id;

    // Our server provisioned the held key before the person arrived.
    let held = HeldKeyRepository::new(pool.clone())
        .find_or_create(
            state.state.key_manager.as_ref().as_ref(),
            &format!("github:{github_id}"),
            TENANT_ID,
        )
        .await
        .expect("held key");
    assert!(!held.row.claimed);

    let (oauth_state, challenge) = start(&state, &config).await;
    let response = callback(&state, &config, &oauth_state, GOOD_CODE, &oauth_state)
        .await
        .expect("callback");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://keys.example.test/"
    );

    // PKCE: the verifier sent to GitHub matches the challenge from /start.
    let verifiers = mock.verifiers.lock().unwrap().clone();
    assert_eq!(verifiers.len(), 1);
    assert_eq!(pkce_challenge(&verifiers[0]), challenge);

    // The session is for the held key, which is now claimed.
    let cookies = set_cookies(&response);
    let session = cookie_value(&cookies, "keycast_session").expect("session cookie");
    assert_eq!(session_pubkey(&pool, &session).await, held.row.pubkey);
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("keycast_github_state=;")));
    let after = HeldKeyRepository::new(pool.clone())
        .find_by_external_id(&format!("github:{github_id}"), TENANT_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.pubkey, held.row.pubkey);
    assert!(after.claimed);

    // A state is single-use.
    let replay = callback(&state, &config, &oauth_state, GOOD_CODE, &oauth_state).await;
    assert_eq!(replay.err(), Some(GithubAuthError::InvalidState));
}

#[tokio::test]
#[serial]
async fn signin_for_a_new_github_user_creates_a_claimed_held_key() {
    let pool = setup_pool().await;
    let state = auth_state(pool.clone()).await;
    let (github, mock) = start_mock_github().await;
    let config = config(&github);
    let github_id = unique_github_id();
    *mock.user_id.lock().unwrap() = github_id;

    let (oauth_state, _) = start(&state, &config).await;
    let response = callback(&state, &config, &oauth_state, GOOD_CODE, &oauth_state)
        .await
        .expect("callback");
    let session = cookie_value(&set_cookies(&response), "keycast_session").expect("session");
    let row = HeldKeyRepository::new(pool.clone())
        .find_by_external_id(&format!("github:{github_id}"), TENANT_ID)
        .await
        .unwrap()
        .expect("held key created");
    assert!(row.claimed);
    assert_eq!(session_pubkey(&pool, &session).await, row.pubkey);

    // Signing in again maps to the same key.
    let (oauth_state, _) = start(&state, &config).await;
    let again = callback(&state, &config, &oauth_state, GOOD_CODE, &oauth_state)
        .await
        .expect("second sign-in");
    let session = cookie_value(&set_cookies(&again), "keycast_session").expect("session");
    assert_eq!(session_pubkey(&pool, &session).await, row.pubkey);
}

#[tokio::test]
#[serial]
async fn signin_refuses_wrong_state_and_bad_codes() {
    let pool = setup_pool().await;
    let state = auth_state(pool.clone()).await;
    let (github, mock) = start_mock_github().await;
    let config = config(&github);
    let github_id = unique_github_id();
    *mock.user_id.lock().unwrap() = github_id;

    let (oauth_state, _) = start(&state, &config).await;
    // A different browser (cookie) or a forged state is refused before GitHub is called.
    let other = callback(
        &state,
        &config,
        "someone-elses-state",
        GOOD_CODE,
        &oauth_state,
    )
    .await;
    assert_eq!(other.err(), Some(GithubAuthError::InvalidState));
    let forged = callback(&state, &config, "forged", GOOD_CODE, "forged").await;
    assert_eq!(forged.err(), Some(GithubAuthError::InvalidState));
    assert!(mock.verifiers.lock().unwrap().is_empty());

    // GitHub refuses the code: no session and no key.
    let bad = callback(&state, &config, &oauth_state, "bad-code", &oauth_state).await;
    assert_eq!(bad.err(), Some(GithubAuthError::GithubRejected));
    assert!(HeldKeyRepository::new(pool)
        .find_by_external_id(&format!("github:{github_id}"), TENANT_ID)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
#[serial]
async fn unreachable_github_is_reported_as_unavailable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let result = exchange_code_for_user_id(&config(&dead), GOOD_CODE, "verifier").await;
    assert_eq!(result, Err(GithubAuthError::GithubUnavailable));
}

#[test]
#[serial]
fn config_comes_from_the_environment() {
    for name in [
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GITHUB_REDIRECT_URI",
        "GITHUB_AUTHORIZE_URL",
        "GITHUB_TOKEN_URL",
        "GITHUB_API_URL",
        "GITHUB_POST_LOGIN_REDIRECT",
    ] {
        std::env::remove_var(name);
    }
    assert!(
        GithubAuthConfig::from_env().unwrap().is_none(),
        "off without a client id"
    );
    std::env::set_var("GITHUB_CLIENT_ID", CLIENT_ID);
    assert!(GithubAuthConfig::from_env().is_err(), "secret required");
    std::env::set_var("GITHUB_CLIENT_SECRET", CLIENT_SECRET);
    std::env::set_var(
        "GITHUB_REDIRECT_URI",
        "http://127.0.0.1:4300/api/auth/github/callback",
    );
    std::env::set_var("GITHUB_POST_LOGIN_REDIRECT", "http://127.0.0.1:4300/");
    std::env::set_var("GITHUB_API_URL", "http://127.0.0.1:4318");
    let config = GithubAuthConfig::from_env().unwrap().expect("on");
    assert_eq!(config.api_url, "http://127.0.0.1:4318");
    assert_eq!(
        config.token_url,
        "https://github.com/login/oauth/access_token"
    );
    assert_eq!(
        config.authorize_url,
        "https://github.com/login/oauth/authorize"
    );
    std::env::set_var("GITHUB_TOKEN_URL", "not a url");
    assert!(GithubAuthConfig::from_env().is_err());
    for name in [
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GITHUB_REDIRECT_URI",
        "GITHUB_TOKEN_URL",
        "GITHUB_API_URL",
        "GITHUB_POST_LOGIN_REDIRECT",
    ] {
        std::env::remove_var(name);
    }
}
