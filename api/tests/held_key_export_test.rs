#![cfg(feature = "integration-tests")]

// ABOUTME: content-web: POST /user/export-key is refused for held keys (and for all keys
// ABOUTME: when KEY_EXPORT_DISABLED=true); an ordinary account can still export.

mod common;

use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use keycast_api::api::{
    http::{
        auth::{export_key, AuthError},
        routes::AuthState,
    },
    tenant::{Tenant, TenantExtractor},
};
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::KeycastState;
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_api::{BcryptAdmission, PrefixedRedis};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::repositories::held_key::HeldKeyRepository;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::prelude::*;
use serde_json::json;
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use ucan::builder::UcanBuilder;
use uuid::Uuid;

const TENANT_ID: i64 = 1;
// TEST HARNESS ONLY: throwaway password for throwaway accounts.
const PASSWORD: &str = "correct-horse-battery";

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

fn km() -> Arc<Box<dyn KeyManager>> {
    Arc::new(Box::new(FileKeyManager::new().expect("file key manager")))
}

async fn auth_state(pool: PgPool, key_manager: Arc<Box<dyn KeyManager>>) -> AuthState {
    let client = redis::Client::open(std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL"))
        .expect("valid Redis URL");
    let connection = redis::aio::ConnectionManager::new(client)
        .await
        .expect("connect to Redis");
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
                Some(format!("keycast-held-export-test:{}", Uuid::new_v4())),
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
        domain: "login.divine.video".to_string(),
        name: "Held Key Export Test".to_string(),
        settings: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }))
}

async fn headers_for(keys: &Keys) -> HeaderMap {
    let ucan = UcanBuilder::default()
        .issued_by(&NostrKeyMaterial::from_keys(keys.clone()))
        .for_audience(&nostr_pubkey_to_did(&keys.public_key()))
        .with_lifetime(3600)
        .with_fact(json!({
            "tenant_id": TENANT_ID,
            "email": "",
            "redirect_origin": "https://login.divine.video",
        }))
        .build()
        .expect("build UCAN")
        .sign()
        .await
        .expect("sign UCAN");
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", ucan.encode().expect("encode"))
            .parse()
            .expect("header"),
    );
    headers.insert("host", "login.divine.video".parse().expect("host"));
    headers.insert("x-forwarded-proto", "https".parse().expect("proto"));
    headers
}

/// Give an account a verified email and password, so the only thing that can
/// stop an export is the held-key policy.
async fn add_password_login(pool: &PgPool, pubkey: &str) {
    sqlx::query(
        "UPDATE users SET email = $1, password_hash = $2, email_verified = true,
             verified_minor = false
         WHERE pubkey = $3 AND tenant_id = $4",
    )
    .bind(format!("export-{}@example.test", Uuid::new_v4()))
    .bind(bcrypt::hash(PASSWORD, 4).expect("hash"))
    .bind(pubkey)
    .bind(TENANT_ID)
    .execute(pool)
    .await
    .expect("add password login");
}

async fn keys_for(pool: &PgPool, key_manager: &dyn KeyManager, pubkey: &str) -> Keys {
    let encrypted: Vec<u8> =
        sqlx::query_scalar("SELECT encrypted_secret_key FROM personal_keys WHERE user_pubkey = $1")
            .bind(pubkey)
            .fetch_one(pool)
            .await
            .expect("stored key");
    let secret = key_manager.decrypt(&encrypted).await.expect("decrypt");
    Keys::new(SecretKey::from_slice(&secret).expect("secret key"))
}

async fn ordinary_account(pool: &PgPool, key_manager: &dyn KeyManager) -> Keys {
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    sqlx::query("INSERT INTO users (pubkey, tenant_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW())")
        .bind(&pubkey)
        .bind(TENANT_ID)
        .execute(pool)
        .await
        .expect("insert user");
    let encrypted = key_manager
        .encrypt(&keys.secret_key().to_secret_bytes())
        .await
        .expect("encrypt");
    sqlx::query("INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id) VALUES ($1, $2, $3)")
        .bind(&pubkey)
        .bind(&encrypted)
        .bind(TENANT_ID)
        .execute(pool)
        .await
        .expect("insert key");
    add_password_login(pool, &pubkey).await;
    keys
}

async fn export(state: AuthState, keys: &Keys) -> Result<(), AuthError> {
    export_key(
        tenant(),
        State(state),
        headers_for(keys).await,
        Json(json!({ "password": PASSWORD, "format": "nsec" })),
    )
    .await
    // The exported key is dropped unread.
    .map(|_| ())
}

#[tokio::test]
#[serial]
async fn held_key_export_is_refused_even_with_correct_password() {
    std::env::remove_var("KEY_EXPORT_DISABLED");
    let pool = setup_pool().await;
    let key_manager = km();
    let account = format!(
        "github:{}",
        1_000_000 + (Uuid::new_v4().as_u128() % 1_000_000_000)
    );
    let lookup = HeldKeyRepository::new(pool.clone())
        .find_or_create(key_manager.as_ref().as_ref(), &account, TENANT_ID)
        .await
        .expect("held key");
    // Even after it is claimed and has a password login, it stays held.
    HeldKeyRepository::new(pool.clone())
        .mark_claimed(&lookup.row.pubkey, TENANT_ID)
        .await
        .expect("claim");
    add_password_login(&pool, &lookup.row.pubkey).await;
    let keys = keys_for(&pool, key_manager.as_ref().as_ref(), &lookup.row.pubkey).await;

    let err = export(auth_state(pool, key_manager).await, &keys)
        .await
        .expect_err("held key export must be refused");
    assert!(matches!(err, AuthError::KeyEgressDenied), "{err:?}");
    let response = axum::response::IntoResponse::into_response(err);
    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn ordinary_account_can_still_export() {
    std::env::remove_var("KEY_EXPORT_DISABLED");
    let pool = setup_pool().await;
    let key_manager = km();
    let keys = ordinary_account(&pool, key_manager.as_ref().as_ref()).await;
    export(auth_state(pool, key_manager).await, &keys)
        .await
        .expect("ordinary export still works");
}

#[tokio::test]
#[serial]
async fn key_export_disabled_refuses_every_account() {
    let pool = setup_pool().await;
    let key_manager = km();
    let keys = ordinary_account(&pool, key_manager.as_ref().as_ref()).await;
    std::env::set_var("KEY_EXPORT_DISABLED", "true");
    let result = export(auth_state(pool, key_manager).await, &keys).await;
    std::env::remove_var("KEY_EXPORT_DISABLED");
    assert!(
        matches!(result, Err(AuthError::KeyEgressDenied)),
        "{result:?}"
    );
}
