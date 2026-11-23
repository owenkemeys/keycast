// ABOUTME: POST /api/service/held-keys: our server asks for a held key for an outside account
// ABOUTME: Narrow service token, idempotent per account, rate-limited, publishes an unclaimed profile

use std::time::Duration;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::repositories::{
    held_key::{is_valid_external_id, unclaimed_profile_event, HeldKeyRepository},
    PersonalKeysRepository, RepositoryError,
};
use nostr_sdk::{Client, Keys};
use serde::{Deserialize, Serialize};

use super::admin::authorize_configured_service_token;
use super::routes::AuthState;
use crate::api::error::ApiError;

pub const HELD_KEY_SERVICE_TOKEN_ENV: &str = "KEYCAST_HELD_KEY_SERVICE_TOKEN";
const DEFAULT_PER_HOUR: u64 = 50;
const DEFAULT_PER_DAY: u64 = 2_000;
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for held-key provisioning, read from the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldKeyConfig {
    /// Relays the unclaimed profile goes to (`HELD_KEY_PROFILE_RELAYS`, comma-separated).
    pub profile_relays: Vec<String>,
    /// New held keys allowed per publisher per hour (`HELD_KEY_RATE_LIMIT_PER_HOUR`).
    pub per_hour: u64,
    /// New held keys allowed per tenant per day (`HELD_KEY_RATE_LIMIT_PER_DAY`).
    pub per_day: u64,
}

fn is_production() -> bool {
    std::env::var("NODE_ENV").as_deref() == Ok("production")
        || std::env::var("RUST_ENV").as_deref() == Ok("production")
}

fn is_loopback_ws(url: &str) -> bool {
    ["ws://127.0.0.1:", "ws://localhost:", "ws://[::1]:"]
        .iter()
        .any(|prefix| url.starts_with(prefix))
}

impl HeldKeyConfig {
    /// Read and validate the configuration.
    ///
    /// Outside production every profile relay must be a loopback `ws://` URL,
    /// so a development stack can never publish to a public relay. In
    /// production every relay must be `wss://`.
    ///
    /// # Errors
    ///
    /// Returns a description of the first invalid setting.
    pub fn from_env() -> Result<Self, String> {
        let profile_relays: Vec<String> = std::env::var("HELD_KEY_PROFILE_RELAYS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|relay| !relay.is_empty())
            .map(str::to_string)
            .collect();
        let production = is_production();
        for relay in &profile_relays {
            if production && !relay.starts_with("wss://") {
                return Err("HELD_KEY_PROFILE_RELAYS must use wss:// in production".to_string());
            }
            if !production && !is_loopback_ws(relay) {
                return Err(
                    "HELD_KEY_PROFILE_RELAYS must be loopback ws:// relays outside production"
                        .to_string(),
                );
            }
        }
        let limit = |name: &str, default: u64| -> Result<u64, String> {
            match std::env::var(name) {
                Ok(value) => value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|v| *v > 0)
                    .ok_or_else(|| format!("{name} must be a positive integer")),
                Err(_) => Ok(default),
            }
        };
        Ok(Self {
            profile_relays,
            per_hour: limit("HELD_KEY_RATE_LIMIT_PER_HOUR", DEFAULT_PER_HOUR)?,
            per_day: limit("HELD_KEY_RATE_LIMIT_PER_DAY", DEFAULT_PER_DAY)?,
        })
    }
}

/// Startup check, called beside the other configuration checks in `main`.
///
/// # Errors
///
/// Returns a description of the invalid setting.
pub fn validate_held_key_configuration() -> Result<(), String> {
    HeldKeyConfig::from_env().map(|_| ())
}

#[derive(Debug, Deserialize)]
pub struct CreateHeldKeyRequest {
    /// Host account id, e.g. `github:123456`.
    pub account_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateHeldKeyResponse {
    pub pubkey: String,
    pub account_id: String,
    pub created: bool,
    pub claimed: bool,
    pub profile_published: bool,
}

#[derive(Debug)]
pub enum HeldKeyError {
    Unauthorized(String),
    BadRequest(String),
    RateLimited(u64),
    Unavailable(String),
    Internal,
}

impl IntoResponse for HeldKeyError {
    fn into_response(self) -> Response {
        let (status, code, message, retry_after) = match self {
            Self::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", message, None)
            }
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message, None),
            Self::RateLimited(seconds) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many new held keys; try again later".to_string(),
                Some(seconds),
            ),
            Self::Unavailable(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                message,
                None,
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Something went wrong. Please try again.".to_string(),
                None,
            ),
        };
        let mut response = (
            status,
            Json(serde_json::json!({ "error": message, "code": code })),
        )
            .into_response();
        if let Some(seconds) = retry_after {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

fn repo_error(error: RepositoryError) -> HeldKeyError {
    match error {
        RepositoryError::Unavailable(_) => {
            HeldKeyError::Unavailable("Service temporarily unavailable".to_string())
        }
        other => {
            tracing::error!(error = %other, "Held key repository error");
            HeldKeyError::Internal
        }
    }
}

// Fixed-window counters: one per publisher per hour, one per tenant per day.
// Both are checked and incremented atomically; a refused request is not counted.
const ADMIT_SCRIPT: &str = r#"
local hour = redis.call('INCR', KEYS[1])
if hour == 1 then redis.call('EXPIRE', KEYS[1], 3600) end
local day = redis.call('INCR', KEYS[2])
if day == 1 then redis.call('EXPIRE', KEYS[2], 86400) end
if hour > tonumber(ARGV[1]) or day > tonumber(ARGV[2]) then
    redis.call('DECR', KEYS[1])
    redis.call('DECR', KEYS[2])
    local ttl = redis.call('TTL', KEYS[1])
    if day > tonumber(ARGV[2]) then ttl = redis.call('TTL', KEYS[2]) end
    return {0, math.max(1, ttl)}
end
return {1, 0}
"#;

async fn admit_new_held_key(
    auth_state: &AuthState,
    config: &HeldKeyConfig,
    tenant_id: i64,
) -> Result<(), HeldKeyError> {
    let redis = auth_state
        .state
        .redis
        .as_ref()
        .ok_or_else(|| HeldKeyError::Unavailable("Rate limiter unavailable".to_string()))?;
    let keys = [
        format!("held_keys:rate:{tenant_id}:publisher:service:hour"),
        format!("held_keys:rate:{tenant_id}:global:day"),
    ];
    let args = [config.per_hour.to_string(), config.per_day.to_string()];
    let (admitted, retry_after): (i64, i64) = redis
        .invoke_script(ADMIT_SCRIPT, &keys, &args)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "Held key rate limiter unavailable");
            HeldKeyError::Unavailable("Rate limiter unavailable".to_string())
        })?;
    if admitted == 1 {
        Ok(())
    } else {
        Err(HeldKeyError::RateLimited(retry_after.max(1) as u64))
    }
}

/// Publish the unclaimed kind 0 profile. Returns true if at least one relay
/// accepted it. Never fails the request: a later identical request retries.
pub async fn publish_unclaimed_profile(keys: &Keys, account_id: &str, relays: &[String]) -> bool {
    if relays.is_empty() {
        return false;
    }
    let event = match unclaimed_profile_event(keys, account_id) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(error = %error, "Failed to sign held key profile");
            return false;
        }
    };
    let client = Client::default();
    for relay in relays {
        if let Err(error) = client.add_relay(relay.as_str()).await {
            tracing::warn!(relay = %relay, error = %error, "Invalid held key profile relay");
        }
    }
    let _ = client.try_connect(PUBLISH_TIMEOUT).await;
    let published = match tokio::time::timeout(PUBLISH_TIMEOUT, client.send_event(&event)).await {
        Ok(Ok(output)) => !output.success.is_empty(),
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "Held key profile publish failed");
            false
        }
        Err(_) => {
            tracing::warn!("Held key profile publish timed out");
            false
        }
    };
    client.shutdown().await;
    published
}

async fn load_keys(
    auth_state: &AuthState,
    pubkey: &str,
    tenant_id: i64,
) -> Result<Keys, HeldKeyError> {
    let encrypted = PersonalKeysRepository::new(auth_state.state.db.clone())
        .find_encrypted_key_for_tenant(pubkey, tenant_id)
        .await
        .map_err(repo_error)?
        .ok_or(HeldKeyError::Internal)?;
    let secret = auth_state
        .state
        .key_manager
        .decrypt(&encrypted)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "Held key decryption failed");
            HeldKeyError::Internal
        })?;
    let secret_key =
        nostr_sdk::SecretKey::from_slice(&secret).map_err(|_| HeldKeyError::Internal)?;
    Ok(Keys::new(secret_key))
}

/// POST /api/service/held-keys
pub async fn create_held_key(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(request): Json<CreateHeldKeyRequest>,
) -> Response {
    let config = match HeldKeyConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error, "Held key configuration invalid");
            return HeldKeyError::Unavailable("Held keys are not configured".to_string())
                .into_response();
        }
    };
    match create_held_key_with_config(tenant.0.id, &auth_state, &headers, &request, &config).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

/// The handler body, with configuration passed in so tests can supply relays and limits.
///
/// # Errors
///
/// Returns a [`HeldKeyError`] describing the refusal.
pub async fn create_held_key_with_config(
    tenant_id: i64,
    auth_state: &AuthState,
    headers: &HeaderMap,
    request: &CreateHeldKeyRequest,
    config: &HeldKeyConfig,
) -> Result<CreateHeldKeyResponse, HeldKeyError> {
    authorize_configured_service_token(
        headers,
        HELD_KEY_SERVICE_TOKEN_ENV,
        "Held key service credential not configured",
    )
    .map_err(|error| match error {
        ApiError::Auth(message) => HeldKeyError::Unauthorized(message),
        _ => HeldKeyError::Unavailable("Held key service credential not configured".to_string()),
    })?;

    let account_id = request.account_id.trim();
    if !is_valid_external_id(account_id) {
        return Err(HeldKeyError::BadRequest(
            "account_id must look like github:<numeric id>".to_string(),
        ));
    }

    let repo = HeldKeyRepository::new(auth_state.state.db.clone());
    let existing = repo
        .find_by_external_id(account_id, tenant_id)
        .await
        .map_err(repo_error)?;
    let (mut row, created) = match existing {
        Some(row) => (row, false),
        None => {
            admit_new_held_key(auth_state, config, tenant_id).await?;
            let lookup = repo
                .find_or_create(
                    auth_state.state.key_manager.as_ref().as_ref(),
                    account_id,
                    tenant_id,
                )
                .await
                .map_err(repo_error)?;
            (lookup.row, lookup.created)
        }
    };

    if !row.claimed && !row.profile_published && !config.profile_relays.is_empty() {
        let keys = load_keys(auth_state, &row.pubkey, tenant_id).await?;
        if publish_unclaimed_profile(&keys, account_id, &config.profile_relays).await {
            repo.mark_profile_published(&row.pubkey, tenant_id)
                .await
                .map_err(repo_error)?;
            row.profile_published = true;
        }
    }

    tracing::info!(
        event = "held_key_provisioned",
        tenant_id,
        pubkey = %row.pubkey,
        created,
        profile_published = row.profile_published,
        "Held key provisioned"
    );

    Ok(CreateHeldKeyResponse {
        pubkey: row.pubkey,
        account_id: account_id.to_string(),
        created,
        claimed: row.claimed,
        profile_published: row.profile_published,
    })
}
