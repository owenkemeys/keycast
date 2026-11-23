// ABOUTME: content-web: email addresses encrypted under the master key, plus an HMAC fingerprint
// ABOUTME: Envelope scheme: one email data key, wrapped by the KeyManager, unwrapped once at startup

use std::sync::OnceLock;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use sqlx::PgPool;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::encryption::KeyManager;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 12;
const ENCRYPTION_LABEL: &[u8] = b"keycast-email-encryption-v1";
const FINGERPRINT_LABEL: &[u8] = b"keycast-email-fingerprint-v1";

#[derive(Debug, Error)]
pub enum EmailProtectionError {
    #[error("email key could not be wrapped or unwrapped")]
    KeyManager,
    #[error("stored email key is malformed")]
    MalformedKey,
    #[error("email ciphertext is malformed or was not made with this key")]
    Decrypt,
    #[error("email encryption failed")]
    Encrypt,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Encrypts email addresses and computes their lookup fingerprints.
///
/// The data key is random, stored only wrapped by the master key (file, GCP
/// or AWS KMS) in `email_protection_keys`, so a database dump reveals no
/// address and no fingerprint can be recomputed without the master key.
pub struct EmailProtector {
    cipher: Aes256Gcm,
    hmac_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for EmailProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmailProtector(..)")
    }
}

fn derive(data_key: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(data_key).expect("HMAC accepts any key");
    mac.update(label);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The form an address is compared in: trimmed and lower-cased, as Keycast
/// already stores it.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

impl EmailProtector {
    /// Build a protector from an unwrapped 32-byte data key. Separate keys for
    /// encryption and fingerprints are derived from it.
    #[must_use]
    pub fn from_data_key(data_key: &[u8; 32]) -> Self {
        let encryption_key = derive(data_key, ENCRYPTION_LABEL);
        Self {
            cipher: Aes256Gcm::new(&(*encryption_key).into()),
            hmac_key: derive(data_key, FINGERPRINT_LABEL),
        }
    }

    /// HMAC-SHA256 of the normalized address: equal for equal addresses,
    /// useless without the key.
    #[must_use]
    pub fn fingerprint(&self, email: &str) -> Vec<u8> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&*self.hmac_key).expect("HMAC accepts any key");
        mac.update(normalize_email(email).as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// AES-256-GCM encryption of the normalized address: nonce, then ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`EmailProtectionError::Encrypt`] if encryption fails.
    pub fn encrypt(&self, email: &str) -> Result<Vec<u8>, EmailProtectionError> {
        let nonce = rand::thread_rng().gen::<[u8; NONCE_LEN]>();
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), normalize_email(email).as_bytes())
            .map_err(|_| EmailProtectionError::Encrypt)?;
        let mut out = nonce.to_vec();
        out.extend(ciphertext);
        Ok(out)
    }

    /// Decrypt an address made by [`Self::encrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`EmailProtectionError::Decrypt`] for anything not made with this key.
    pub fn decrypt(&self, bytes: &[u8]) -> Result<String, EmailProtectionError> {
        if bytes.len() <= NONCE_LEN {
            return Err(EmailProtectionError::Decrypt);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| EmailProtectionError::Decrypt)?;
        String::from_utf8(plaintext).map_err(|_| EmailProtectionError::Decrypt)
    }

    /// Load the wrapped data key, creating it on first use, and unwrap it with
    /// the key manager. Safe when several instances start together.
    ///
    /// # Errors
    ///
    /// Returns an error when the database or key manager fails.
    pub async fn load_or_create(
        pool: &PgPool,
        key_manager: &dyn KeyManager,
    ) -> Result<Self, EmailProtectionError> {
        let existing: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT wrapped_key FROM email_protection_keys WHERE id = 1")
                .fetch_optional(pool)
                .await?;
        let wrapped = match existing {
            Some(wrapped) => wrapped,
            None => {
                let data_key = Zeroizing::new(rand::thread_rng().gen::<[u8; 32]>());
                let wrapped = key_manager
                    .encrypt(&*data_key)
                    .await
                    .map_err(|_| EmailProtectionError::KeyManager)?;
                sqlx::query(
                    "INSERT INTO email_protection_keys (id, wrapped_key) VALUES (1, $1)
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(&wrapped)
                .execute(pool)
                .await?;
                // Another instance may have won the race; use whatever is stored.
                sqlx::query_scalar("SELECT wrapped_key FROM email_protection_keys WHERE id = 1")
                    .fetch_one(pool)
                    .await?
            }
        };
        let data_key = key_manager
            .decrypt(&wrapped)
            .await
            .map_err(|_| EmailProtectionError::KeyManager)?;
        let data_key: [u8; 32] = data_key
            .as_slice()
            .try_into()
            .map_err(|_| EmailProtectionError::MalformedKey)?;
        let data_key = Zeroizing::new(data_key);
        Ok(Self::from_data_key(&data_key))
    }

    /// Encrypt and fingerprint every account address that has no protected
    /// copy yet (new accounts, changed addresses, rows from before the
    /// migration). Returns how many rows were protected.
    ///
    /// # Errors
    ///
    /// Returns an error when the database fails or an address can't be encrypted.
    pub async fn protect_pending(
        &self,
        pool: &PgPool,
        batch_size: i64,
    ) -> Result<u64, EmailProtectionError> {
        let mut total = 0;
        loop {
            let rows: Vec<(String, i64, String)> = sqlx::query_as(
                "SELECT pubkey, tenant_id, email FROM users
                 WHERE email IS NOT NULL AND email_ciphertext IS NULL
                 ORDER BY pubkey LIMIT $1",
            )
            .bind(batch_size)
            .fetch_all(pool)
            .await?;
            if rows.is_empty() {
                return Ok(total);
            }
            let mut progressed = 0;
            for (pubkey, tenant_id, email) in rows {
                // The email guard skips a row whose address changed meanwhile;
                // the next pass picks it up.
                let updated = sqlx::query(
                    "UPDATE users SET email_ciphertext = $1, email_fingerprint = $2
                     WHERE pubkey = $3 AND tenant_id = $4 AND email = $5
                       AND email_ciphertext IS NULL",
                )
                .bind(self.encrypt(&email)?)
                .bind(self.fingerprint(&email))
                .bind(&pubkey)
                .bind(tenant_id)
                .bind(&email)
                .execute(pool)
                .await?
                .rows_affected();
                progressed += updated;
            }
            total += progressed;
            if progressed == 0 {
                return Ok(total);
            }
        }
    }

    /// Read an account's address back from its encrypted copy.
    ///
    /// # Errors
    ///
    /// Returns an error when the database fails or the ciphertext doesn't decrypt.
    pub async fn decrypt_account_email(
        &self,
        pool: &PgPool,
        pubkey: &str,
        tenant_id: i64,
    ) -> Result<Option<String>, EmailProtectionError> {
        let ciphertext: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT email_ciphertext FROM users WHERE pubkey = $1 AND tenant_id = $2",
        )
        .bind(pubkey)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;
        ciphertext
            .flatten()
            .map(|bytes| self.decrypt(&bytes))
            .transpose()
    }
}

static EMAIL_PROTECTOR: OnceLock<EmailProtector> = OnceLock::new();

/// Install the process-wide protector once at startup. Later calls are ignored.
pub fn install(protector: EmailProtector) {
    let _ = EMAIL_PROTECTOR.set(protector);
}

/// The installed protector, if startup has run.
#[must_use]
pub fn installed() -> Option<&'static EmailProtector> {
    EMAIL_PROTECTOR.get()
}

/// Fingerprint with the installed protector, for repository lookups.
#[must_use]
pub fn installed_fingerprint(email: &str) -> Option<Vec<u8>> {
    installed().map(|protector| protector.fingerprint(email))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protector(seed: u8) -> EmailProtector {
        EmailProtector::from_data_key(&[seed; 32])
    }

    #[test]
    fn encrypts_and_decrypts_normalized_address() {
        let p = protector(7);
        let ciphertext = p.encrypt("  Person@Example.TEST ").unwrap();
        assert!(!ciphertext.windows(b"person".len()).any(|w| w == b"person"));
        assert_eq!(p.decrypt(&ciphertext).unwrap(), "person@example.test");
    }

    #[test]
    fn encryption_is_randomized() {
        let p = protector(7);
        assert_ne!(
            p.encrypt("a@example.test").unwrap(),
            p.encrypt("a@example.test").unwrap()
        );
    }

    #[test]
    fn fingerprint_is_stable_normalized_and_keyed() {
        let p = protector(7);
        assert_eq!(
            p.fingerprint("A@Example.test"),
            p.fingerprint(" a@example.test")
        );
        assert_ne!(
            p.fingerprint("a@example.test"),
            p.fingerprint("b@example.test")
        );
        assert_ne!(
            p.fingerprint("a@example.test"),
            protector(8).fingerprint("a@example.test")
        );
        assert_eq!(p.fingerprint("a@example.test").len(), 32);
    }

    #[test]
    fn other_key_or_tampering_cannot_decrypt() {
        let mut ciphertext = protector(7).encrypt("a@example.test").unwrap();
        assert!(protector(8).decrypt(&ciphertext).is_err());
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert!(protector(7).decrypt(&ciphertext).is_err());
        assert!(protector(7).decrypt(&[0u8; 5]).is_err());
    }
}
