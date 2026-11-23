// ABOUTME: Held keys: Keycast-generated keys for outside accounts (e.g. github:123456)
// ABOUTME: One key per external account per tenant, created idempotently, claimed on sign-in

use crate::encryption::KeyManager;
use crate::repositories::RepositoryError;
use nostr_sdk::{EventBuilder, Keys, Metadata};
use sqlx::{FromRow, PgPool};

/// Host prefixes we accept for external account ids.
const EXTERNAL_ID_HOSTS: &[&str] = &["github"];

/// Validate an external account id: `<host>:<numeric id>`, e.g. `github:57272246`.
///
/// Only stable numeric ids are accepted: GitHub logins can be renamed and
/// reused, so a held key must never be keyed by a login.
#[must_use]
pub fn is_valid_external_id(external_id: &str) -> bool {
    let Some((host, id)) = external_id.split_once(':') else {
        return false;
    };
    EXTERNAL_ID_HOSTS.contains(&host)
        && !id.is_empty()
        && id.len() <= 20
        && !id.starts_with('0')
        && id.bytes().all(|b| b.is_ascii_digit())
}

/// The profile a held key publishes before anyone has claimed it.
#[must_use]
pub fn unclaimed_profile_metadata(external_id: &str) -> Metadata {
    Metadata::new()
        .name(external_id)
        .display_name(format!("{external_id} (unclaimed)"))
        .about(format!("held for {external_id}, unclaimed"))
}

/// Build the signed kind 0 profile event for an unclaimed held key.
///
/// # Errors
///
/// Returns an error when signing fails.
pub fn unclaimed_profile_event(keys: &Keys, external_id: &str) -> Result<nostr_sdk::Event, String> {
    EventBuilder::metadata(&unclaimed_profile_metadata(external_id))
        .sign_with_keys(keys)
        .map_err(|e| e.to_string())
}

/// A held key's row, without any key material.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct HeldKeyRow {
    pub pubkey: String,
    pub external_id: String,
    pub claimed: bool,
    pub profile_published: bool,
}

/// Result of [`HeldKeyRepository::find_or_create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldKeyLookup {
    pub row: HeldKeyRow,
    /// True when this call generated the key.
    pub created: bool,
}

const HELD_KEY_COLUMNS: &str =
    "pubkey, external_id, (external_claimed_at IS NOT NULL) AS claimed, \
     (held_profile_published_at IS NOT NULL) AS profile_published";

pub struct HeldKeyRepository {
    pool: PgPool,
}

impl HeldKeyRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find the held key for an external account id.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the query fails.
    pub async fn find_by_external_id(
        &self,
        external_id: &str,
        tenant_id: i64,
    ) -> Result<Option<HeldKeyRow>, RepositoryError> {
        let sql = format!(
            "SELECT {HELD_KEY_COLUMNS} FROM users WHERE tenant_id = $1 AND external_id = $2"
        );
        sqlx::query_as::<_, HeldKeyRow>(&sql)
            .bind(tenant_id)
            .bind(external_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Return the held key for `external_id`, generating and storing one if
    /// there is none. Safe under concurrent calls: the unique index on
    /// `(tenant_id, external_id)` decides the winner and the loser reads it.
    ///
    /// The secret key is encrypted with the key manager before it is stored and
    /// is never returned. No transaction is held across the KMS call.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the database or key manager fails.
    pub async fn find_or_create(
        &self,
        key_manager: &dyn KeyManager,
        external_id: &str,
        tenant_id: i64,
    ) -> Result<HeldKeyLookup, RepositoryError> {
        if let Some(row) = self.find_by_external_id(external_id, tenant_id).await? {
            return Ok(HeldKeyLookup {
                row,
                created: false,
            });
        }

        let keys = Keys::generate();
        let pubkey = keys.public_key().to_hex();
        let encrypted_secret = key_manager
            .encrypt(&keys.secret_key().to_secret_bytes())
            .await
            .map_err(|e| RepositoryError::Database(format!("key encryption failed: {e}")))?;

        let mut tx = self.pool.begin().await?;
        let inserted: Option<(String,)> = sqlx::query_as(
            "INSERT INTO users (pubkey, tenant_id, external_id, held_key, created_at, updated_at)
             VALUES ($1, $2, $3, TRUE, NOW(), NOW())
             ON CONFLICT (tenant_id, external_id) WHERE external_id IS NOT NULL DO NOTHING
             RETURNING pubkey",
        )
        .bind(&pubkey)
        .bind(tenant_id)
        .bind(external_id)
        .fetch_optional(&mut *tx)
        .await?;

        if inserted.is_none() {
            tx.rollback().await?;
            let row = self
                .find_by_external_id(external_id, tenant_id)
                .await?
                .ok_or_else(|| RepositoryError::NotFound("held key vanished".into()))?;
            return Ok(HeldKeyLookup {
                row,
                created: false,
            });
        }

        sqlx::query(
            "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())",
        )
        .bind(&pubkey)
        .bind(&encrypted_secret)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(HeldKeyLookup {
            row: HeldKeyRow {
                pubkey,
                external_id: external_id.to_string(),
                claimed: false,
                profile_published: false,
            },
            created: true,
        })
    }

    /// Record that the unclaimed profile reached at least one relay.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the update fails.
    pub async fn mark_profile_published(
        &self,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET held_profile_published_at = NOW(), updated_at = NOW()
             WHERE pubkey = $1 AND tenant_id = $2 AND held_profile_published_at IS NULL",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a held key as claimed by the person who signed in with its account.
    /// Idempotent: the first claim time is kept.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the update fails.
    pub async fn mark_claimed(&self, pubkey: &str, tenant_id: i64) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET external_claimed_at = COALESCE(external_claimed_at, NOW()), updated_at = NOW()
             WHERE pubkey = $1 AND tenant_id = $2 AND held_key = TRUE",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whether `pubkey` is a held key (generated by us for an outside account).
    /// Held keys stay held after they are claimed: leaving means replacing the
    /// key, never exporting it.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the query fails.
    pub async fn is_held_key(&self, pubkey: &str, tenant_id: i64) -> Result<bool, RepositoryError> {
        let held: Option<bool> =
            sqlx::query_scalar("SELECT held_key FROM users WHERE pubkey = $1 AND tenant_id = $2")
                .bind(pubkey)
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(held.unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_id_accepts_numeric_github_ids_only() {
        assert!(is_valid_external_id("github:57272246"));
        assert!(is_valid_external_id("github:1"));
        assert!(!is_valid_external_id("github:"));
        assert!(!is_valid_external_id("github:owenkemeys"));
        assert!(!is_valid_external_id("github:0123"));
        assert!(!is_valid_external_id("github:12 3"));
        assert!(!is_valid_external_id("github:123456789012345678901"));
        assert!(!is_valid_external_id("gitlab:123"));
        assert!(!is_valid_external_id("123456"));
    }

    #[test]
    fn unclaimed_profile_is_kind_0_and_says_held() {
        let keys = Keys::generate();
        let event = unclaimed_profile_event(&keys, "github:123456").expect("sign");
        assert_eq!(event.kind, nostr_sdk::Kind::Metadata);
        assert_eq!(event.pubkey, keys.public_key());
        let content: serde_json::Value = serde_json::from_str(&event.content).expect("json");
        assert_eq!(content["about"], "held for github:123456, unclaimed");
        assert_eq!(content["name"], "github:123456");
        event.verify().expect("valid signature");
    }
}
