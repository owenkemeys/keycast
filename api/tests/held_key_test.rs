#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for POST /api/service/held-keys (content-web held keys):
// ABOUTME: service token, account id validation, idempotency, unclaimed profile, rate limits.

mod common;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use keycast_api::api::http::held_keys::{
    create_held_key_with_config, CreateHeldKeyRequest, HeldKeyConfig, HeldKeyError,
    HELD_KEY_SERVICE_TOKEN_ENV,
};
use keycast_api::api::http::routes::AuthState;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::{BcryptAdmission, PrefixedRedis};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::repositories::held_key::HeldKeyRepository;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_relay_builder::prelude::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::*;
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const TENANT_ID: i64 = 1;
// TEST HARNESS ONLY: a throwaway credential for this process.
const SERVICE_TOKEN: &str = "held-key-test-service-token-0123456789abcdef";

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.expect("connect");
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("migrations");
    pool
}

async fn auth_state(pool: PgPool) -> AuthState {
    let redis_url =
        std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL must name dedicated Redis");
    let client = redis::Client::open(redis_url).expect("valid Redis URL");
    let connection = redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect to Redis");
    let prefix = format!("keycast-held-key-test:{}", Uuid::new_v4());
    let bcrypt = BcryptAdmission::new(1, Duration::from_secs(1));
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
            bcrypt,
            redis: Some(PrefixedRedis::new(connection, Some(prefix))),
            secret_pool: SecretPool::new(1).receiver(),
            activity_logger: keycast_api::activity_log::ActivityLogger::disabled(),
        }),
        auth_tx: None,
    }
}

fn headers(token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        headers.insert(
            "Authorization",
            format!("Bearer {token}").parse().expect("header"),
        );
    }
    headers
}

fn unique_account() -> String {
    // Numeric, no leading zero, unique per run.
    let n = (Uuid::new_v4().as_u128() % 9_000_000_000_000) + 1_000_000_000_000;
    format!("github:{n}")
}

fn config(relays: Vec<String>) -> HeldKeyConfig {
    HeldKeyConfig {
        profile_relays: relays,
        per_hour: 50,
        per_day: 2_000,
    }
}

fn request(account_id: &str) -> CreateHeldKeyRequest {
    CreateHeldKeyRequest {
        account_id: account_id.to_string(),
    }
}

fn set_token() {
    std::env::set_var(HELD_KEY_SERVICE_TOKEN_ENV, SERVICE_TOKEN);
}

#[tokio::test]
#[serial]
async fn refuses_missing_or_wrong_service_token() {
    set_token();
    let state = auth_state(setup_pool().await).await;
    for token in [None, Some("wrong-token"), Some("")] {
        let err = create_held_key_with_config(
            TENANT_ID,
            &state,
            &headers(token),
            &request(&unique_account()),
            &config(vec![]),
        )
        .await
        .expect_err("must be refused");
        assert!(matches!(err, HeldKeyError::Unauthorized(_)), "{err:?}");
        assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
#[serial]
async fn refuses_when_token_not_configured() {
    std::env::remove_var(HELD_KEY_SERVICE_TOKEN_ENV);
    let state = auth_state(setup_pool().await).await;
    let err = create_held_key_with_config(
        TENANT_ID,
        &state,
        &headers(Some(SERVICE_TOKEN)),
        &request(&unique_account()),
        &config(vec![]),
    )
    .await
    .expect_err("must be refused");
    assert!(matches!(err, HeldKeyError::Unavailable(_)), "{err:?}");
    assert_eq!(
        err.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
#[serial]
async fn rejects_bad_account_ids() {
    set_token();
    let state = auth_state(setup_pool().await).await;
    for bad in [
        "owenkemeys",
        "github:owenkemeys",
        "github:",
        "gitlab:12",
        "github:012",
    ] {
        let err = create_held_key_with_config(
            TENANT_ID,
            &state,
            &headers(Some(SERVICE_TOKEN)),
            &request(bad),
            &config(vec![]),
        )
        .await
        .expect_err("bad id");
        assert!(matches!(err, HeldKeyError::BadRequest(_)), "{bad}: {err:?}");
    }
}

#[tokio::test]
#[serial]
async fn creates_once_and_publishes_unclaimed_profile() {
    set_token();
    let pool = setup_pool().await;
    let state = auth_state(pool.clone()).await;
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay");
    let relay_url = relay.url().await.to_string();
    let account = unique_account();

    let first = create_held_key_with_config(
        TENANT_ID,
        &state,
        &headers(Some(SERVICE_TOKEN)),
        &request(&account),
        &config(vec![relay_url.clone()]),
    )
    .await
    .expect("create");
    assert!(first.created);
    assert!(!first.claimed);
    assert!(first.profile_published);
    assert_eq!(first.account_id, account);
    PublicKey::from_hex(&first.pubkey).expect("valid pubkey");

    // Idempotent: same pubkey, nothing new created, no second key row.
    let second = create_held_key_with_config(
        TENANT_ID,
        &state,
        &headers(Some(SERVICE_TOKEN)),
        &request(&account),
        &config(vec![relay_url.clone()]),
    )
    .await
    .expect("repeat");
    assert_eq!(second.pubkey, first.pubkey);
    assert!(!second.created);
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users u JOIN personal_keys k ON k.user_pubkey = u.pubkey
         WHERE u.tenant_id = $1 AND u.external_id = $2 AND u.held_key",
    )
    .bind(TENANT_ID)
    .bind(&account)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(rows, 1);

    // The stored key is encrypted, not the raw 32 bytes.
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(&first.pubkey)
            .fetch_one(&pool)
            .await
            .expect("stored key");
    assert_ne!(stored.len(), 32);

    // The relay holds exactly one kind 0 from the held key, saying it is unclaimed.
    let reader = Client::default();
    reader
        .add_relay(relay_url.as_str())
        .await
        .expect("add relay");
    reader.connect().await;
    let author = PublicKey::from_hex(&first.pubkey).expect("pubkey");
    let events = reader
        .fetch_events(
            Filter::new().author(author).kind(Kind::Metadata),
            Duration::from_secs(5),
        )
        .await
        .expect("fetch");
    assert_eq!(events.len(), 1);
    let event = events.first().expect("event");
    let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
    assert_eq!(content["about"], format!("held for {account}, unclaimed"));
    reader.shutdown().await;
}

#[tokio::test]
#[serial]
async fn concurrent_requests_for_one_account_yield_one_key() {
    set_token();
    let pool = setup_pool().await;
    let state = auth_state(pool.clone()).await;
    let account = unique_account();
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let state = state.clone();
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            create_held_key_with_config(
                TENANT_ID,
                &state,
                &headers(Some(SERVICE_TOKEN)),
                &request(&account),
                &config(vec![]),
            )
            .await
            .expect("create")
        }));
    }
    let mut pubkeys = Vec::new();
    for task in tasks {
        pubkeys.push(task.await.expect("join").pubkey);
    }
    pubkeys.dedup();
    assert_eq!(pubkeys.len(), 1);
    let found = HeldKeyRepository::new(pool)
        .find_by_external_id(&account, TENANT_ID)
        .await
        .expect("lookup")
        .expect("row");
    assert_eq!(found.pubkey, pubkeys[0]);
}

#[tokio::test]
#[serial]
async fn rate_limits_new_keys_but_not_repeats() {
    set_token();
    let state = auth_state(setup_pool().await).await;
    let limited = HeldKeyConfig {
        profile_relays: vec![],
        per_hour: 2,
        per_day: 2_000,
    };
    let call = |account: String| {
        let state = state.clone();
        let limited = limited.clone();
        async move {
            create_held_key_with_config(
                TENANT_ID,
                &state,
                &headers(Some(SERVICE_TOKEN)),
                &request(&account),
                &limited,
            )
            .await
        }
    };
    let a = unique_account();
    call(a.clone()).await.expect("first");
    call(unique_account()).await.expect("second");
    let err = call(unique_account())
        .await
        .expect_err("third is over the limit");
    assert!(matches!(err, HeldKeyError::RateLimited(s) if s > 0 && s <= 3600));
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));
    // An existing account still resolves: repeats cost nothing.
    let again = call(a).await.expect("repeat is not limited");
    assert!(!again.created);
}

#[test]
#[serial]
fn config_refuses_public_relays_outside_production() {
    std::env::remove_var("NODE_ENV");
    std::env::remove_var("RUST_ENV");
    std::env::set_var("HELD_KEY_PROFILE_RELAYS", "wss://relay.damus.io");
    assert!(HeldKeyConfig::from_env().is_err());
    std::env::set_var("HELD_KEY_PROFILE_RELAYS", "ws://127.0.0.1:7777");
    let config = HeldKeyConfig::from_env().expect("loopback is fine in dev");
    assert_eq!(
        config.profile_relays,
        vec!["ws://127.0.0.1:7777".to_string()]
    );
    assert_eq!((config.per_hour, config.per_day), (50, 2_000));
    std::env::set_var("HELD_KEY_RATE_LIMIT_PER_HOUR", "0");
    assert!(HeldKeyConfig::from_env().is_err());
    std::env::remove_var("HELD_KEY_RATE_LIMIT_PER_HOUR");
    std::env::remove_var("HELD_KEY_PROFILE_RELAYS");
}
