#![cfg(feature = "integration-tests")]

// ABOUTME: content-web: account emails encrypted under the master key with an HMAC fingerprint.
// ABOUTME: Wrapped data key persistence, backfill, change invalidation and lookup by fingerprint.

use async_trait::async_trait;
use keycast_core::email_protection::{self, EmailProtector};
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::UserRepository;
use serial_test::serial;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    assert!(url.contains("_test"), "refusing a non-test database");
    let pool = PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("migrations");
    pool
}

struct FailingKeyManager;

#[async_trait]
impl KeyManager for FailingKeyManager {
    async fn encrypt(&self, _: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Err(KeyManagerError::Encrypt("test".into()))
    }
    async fn decrypt(&self, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Err(KeyManagerError::Decrypt("test".into()))
    }
}

async fn insert_user(pool: &PgPool, email: &str) -> String {
    let pubkey = format!(
        "{:032x}{:032x}",
        Uuid::new_v4().as_u128(),
        Uuid::new_v4().as_u128()
    );
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, password_hash, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, 'not-a-real-hash', true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(TENANT_ID)
    .bind(email)
    .execute(pool)
    .await
    .expect("insert user");
    pubkey
}

async fn protected(pool: &PgPool, pubkey: &str) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    sqlx::query_as("SELECT email_ciphertext, email_fingerprint FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(pool)
        .await
        .expect("row")
}

#[tokio::test]
#[serial]
async fn data_key_is_stored_wrapped_and_reloads() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("file key manager");
    let first = EmailProtector::load_or_create(&pool, &km)
        .await
        .expect("create");
    let second = EmailProtector::load_or_create(&pool, &km)
        .await
        .expect("reload");
    assert_eq!(
        first.fingerprint("a@example.test"),
        second.fingerprint("a@example.test")
    );
    let wrapped: Vec<u8> =
        sqlx::query_scalar("SELECT wrapped_key FROM email_protection_keys WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("wrapped key");
    assert_ne!(wrapped.len(), 32, "the data key is stored wrapped, not raw");
    // Without the master key the stored data key is useless.
    assert!(EmailProtector::load_or_create(&pool, &FailingKeyManager)
        .await
        .is_err());
}

#[tokio::test]
#[serial]
async fn backfill_encrypts_and_change_invalidates() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("file key manager");
    let protector = EmailProtector::load_or_create(&pool, &km)
        .await
        .expect("protector");
    let email = format!("protect-{}@example.test", Uuid::new_v4());
    let pubkey = insert_user(&pool, &email).await;

    assert!(
        protector
            .protect_pending(&pool, 100)
            .await
            .expect("protect")
            >= 1
    );
    let (ciphertext, fingerprint) = protected(&pool, &pubkey).await;
    let ciphertext = ciphertext.expect("encrypted copy");
    assert!(!ciphertext
        .windows(email.len())
        .any(|w| w == email.as_bytes()));
    assert_eq!(fingerprint, Some(protector.fingerprint(&email)));
    assert_eq!(
        protector
            .decrypt_account_email(&pool, &pubkey, TENANT_ID)
            .await
            .expect("decrypt"),
        Some(email.clone())
    );

    // A changed address drops the stale copy; the next pass protects the new one.
    let changed = format!("changed-{}@example.test", Uuid::new_v4());
    sqlx::query("UPDATE users SET email = $1 WHERE pubkey = $2")
        .bind(&changed)
        .bind(&pubkey)
        .execute(&pool)
        .await
        .expect("change email");
    assert_eq!(protected(&pool, &pubkey).await, (None, None));
    protector
        .protect_pending(&pool, 100)
        .await
        .expect("protect");
    assert_eq!(
        protector
            .decrypt_account_email(&pool, &pubkey, TENANT_ID)
            .await
            .expect("decrypt"),
        Some(changed.clone())
    );
    assert_eq!(
        protected(&pool, &pubkey).await.1,
        Some(protector.fingerprint(&changed))
    );
}

#[tokio::test]
#[serial]
async fn login_lookup_uses_the_fingerprint() {
    let pool = setup_pool().await;
    let km = FileKeyManager::new().expect("file key manager");
    email_protection::install(
        EmailProtector::load_or_create(&pool, &km)
            .await
            .expect("protector"),
    );
    let protector = email_protection::installed().expect("installed");
    let email = format!("lookup-{}@example.test", Uuid::new_v4());
    let pubkey = insert_user(&pool, &email).await;
    let repo = UserRepository::new(pool.clone());

    // Not yet protected: the plaintext fallback finds it.
    assert_eq!(
        repo.find_pubkey_by_email(&email, TENANT_ID).await.unwrap(),
        Some(pubkey.clone())
    );

    protector
        .protect_pending(&pool, 100)
        .await
        .expect("protect");
    // Protected: found by fingerprint, which normalizes, so a differently
    // cased address (never matched by the plaintext column) also finds it.
    let shouted = email.to_uppercase();
    assert_eq!(
        repo.find_pubkey_by_email(&shouted, TENANT_ID)
            .await
            .unwrap(),
        Some(pubkey.clone())
    );
    let login = repo
        .find_with_password(&shouted, TENANT_ID)
        .await
        .unwrap()
        .expect("login lookup");
    assert_eq!(login.0, pubkey);
    assert!(repo
        .find_pubkey_by_email("nobody@example.test", TENANT_ID)
        .await
        .unwrap()
        .is_none());
}
