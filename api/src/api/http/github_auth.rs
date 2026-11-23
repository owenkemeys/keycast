// ABOUTME: Sign in with GitHub through the GitHub App user-authorization flow (code, token, user id)
// ABOUTME: Maps the numeric GitHub user id to its held key (github:<id>), creating one if needed

use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use base64::Engine;
use keycast_core::repositories::{
    held_key::HeldKeyRepository, PersonalKeysRepository, UserRepository,
};
use nostr_sdk::Keys;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::routes::AuthState;

const STATE_TTL_SECONDS: u64 = 600;
const STATE_COOKIE: &str = "keycast_github_state";
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// GitHub App sign-in settings. Everything comes from the environment so tests
/// and development can point the flow at a mock GitHub.
#[derive(Debug, Clone)]
pub struct GithubAuthConfig {
    /// `GITHUB_CLIENT_ID`: the GitHub App's client id.
    pub client_id: String,
    /// `GITHUB_CLIENT_SECRET`: the GitHub App's client secret. Never logged.
    pub client_secret: String,
    /// `GITHUB_REDIRECT_URI`: our callback, registered on the GitHub App.
    pub redirect_uri: String,
    /// `GITHUB_AUTHORIZE_URL`, default `https://github.com/login/oauth/authorize`.
    pub authorize_url: String,
    /// `GITHUB_TOKEN_URL`, default `https://github.com/login/oauth/access_token`.
    pub token_url: String,
    /// `GITHUB_API_URL`, default `https://api.github.com`.
    pub api_url: String,
    /// `GITHUB_POST_LOGIN_REDIRECT`, default `APP_URL`: where the browser lands after sign-in.
    pub post_login_redirect: String,
}

impl GithubAuthConfig {
    /// Read the configuration. Returns `Ok(None)` when `GITHUB_CLIENT_ID` is
    /// unset, which leaves GitHub sign-in switched off.
    ///
    /// # Errors
    ///
    /// Returns a description of a missing or invalid setting.
    pub fn from_env() -> Result<Option<Self>, String> {
        let var = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let Some(client_id) = var("GITHUB_CLIENT_ID") else {
            return Ok(None);
        };
        let client_secret = var("GITHUB_CLIENT_SECRET")
            .ok_or("GITHUB_CLIENT_SECRET is required when GITHUB_CLIENT_ID is set")?;
        let redirect_uri = var("GITHUB_REDIRECT_URI")
            .ok_or("GITHUB_REDIRECT_URI is required when GITHUB_CLIENT_ID is set")?;
        let post_login_redirect = var("GITHUB_POST_LOGIN_REDIRECT")
            .or_else(|| var("APP_URL"))
            .ok_or("GITHUB_POST_LOGIN_REDIRECT or APP_URL is required for GitHub sign-in")?;
        let config = Self {
            client_id,
            client_secret,
            redirect_uri,
            authorize_url: var("GITHUB_AUTHORIZE_URL")
                .unwrap_or_else(|| "https://github.com/login/oauth/authorize".to_string()),
            token_url: var("GITHUB_TOKEN_URL")
                .unwrap_or_else(|| "https://github.com/login/oauth/access_token".to_string()),
            api_url: var("GITHUB_API_URL").unwrap_or_else(|| "https://api.github.com".to_string()),
            post_login_redirect,
        };
        for (name, value) in [
            ("GITHUB_REDIRECT_URI", &config.redirect_uri),
            ("GITHUB_AUTHORIZE_URL", &config.authorize_url),
            ("GITHUB_TOKEN_URL", &config.token_url),
            ("GITHUB_API_URL", &config.api_url),
            ("GITHUB_POST_LOGIN_REDIRECT", &config.post_login_redirect),
        ] {
            reqwest::Url::parse(value).map_err(|_| format!("{name} must be an absolute URL"))?;
        }
        Ok(Some(config))
    }

    fn session_origin(&self) -> String {
        reqwest::Url::parse(&self.post_login_redirect)
            .map(|url| url.origin().ascii_serialization())
            .unwrap_or_default()
    }
}

/// Startup check, called beside the other configuration checks in `main`.
///
/// # Errors
///
/// Returns a description of the invalid setting.
pub fn validate_github_auth_configuration() -> Result<(), String> {
    GithubAuthConfig::from_env().map(|_| ())
}

#[derive(Debug, PartialEq, Eq)]
pub enum GithubAuthError {
    /// The browser came back without a valid, unexpired state of ours.
    InvalidState,
    /// GitHub refused the code or returned something we can't use.
    GithubRejected,
    /// GitHub could not be reached.
    GithubUnavailable,
    Unavailable,
    Internal,
}

impl IntoResponse for GithubAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidState => (
                StatusCode::BAD_REQUEST,
                "This sign-in link has expired. Please start again.",
            ),
            Self::GithubRejected => (
                StatusCode::BAD_REQUEST,
                "GitHub did not confirm the sign-in.",
            ),
            Self::GithubUnavailable => (StatusCode::BAD_GATEWAY, "GitHub could not be reached."),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign-in is temporarily unavailable.",
            ),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong."),
        };
        (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn http_client() -> Result<reqwest::Client, GithubAuthError> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| GithubAuthError::Internal)
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE S256 challenge for a verifier.
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn state_key(state: &str) -> String {
    format!("github_oauth_state:{state}")
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    id: u64,
}

/// Exchange an authorization code for a user access token, then read the
/// numeric user id with it. The token is dropped before returning.
///
/// # Errors
///
/// Returns [`GithubAuthError::GithubRejected`] when GitHub refuses the code or
/// token, and [`GithubAuthError::GithubUnavailable`] when it can't be reached.
pub async fn exchange_code_for_user_id(
    config: &GithubAuthConfig,
    code: &str,
    code_verifier: &str,
) -> Result<u64, GithubAuthError> {
    let client = http_client()?;
    let token_response = client
        .post(&config.token_url)
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|_| GithubAuthError::GithubUnavailable)?;
    if !token_response.status().is_success() {
        tracing::warn!(
            status = token_response.status().as_u16(),
            "GitHub token exchange refused"
        );
        return Err(GithubAuthError::GithubRejected);
    }
    // GitHub answers 200 with {"error": ...} for bad codes; no token means refused.
    let access_token = token_response
        .json::<TokenResponse>()
        .await
        .map_err(|_| GithubAuthError::GithubRejected)?
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or(GithubAuthError::GithubRejected)?;

    let user_url = format!("{}/user", config.api_url.trim_end_matches('/'));
    let user_response = client
        .get(user_url)
        .bearer_auth(&access_token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header(header::USER_AGENT, "keycast")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|_| GithubAuthError::GithubUnavailable)?;
    drop(access_token);
    if !user_response.status().is_success() {
        tracing::warn!(
            status = user_response.status().as_u16(),
            "GitHub user lookup refused"
        );
        return Err(GithubAuthError::GithubRejected);
    }
    let user = user_response
        .json::<GithubUser>()
        .await
        .map_err(|_| GithubAuthError::GithubRejected)?;
    if user.id == 0 {
        return Err(GithubAuthError::GithubRejected);
    }
    Ok(user.id)
}

/// GET /api/auth/github/start: send the browser to GitHub with a fresh state and PKCE challenge.
pub async fn github_start(
    State(auth_state): State<AuthState>,
    Extension(config): Extension<Arc<GithubAuthConfig>>,
) -> Result<Response, GithubAuthError> {
    let redis = auth_state
        .state
        .redis
        .as_ref()
        .ok_or(GithubAuthError::Unavailable)?;
    let state = random_token();
    let verifier = random_token();
    let stored = redis
        .set_nx_ex(&state_key(&state), STATE_TTL_SECONDS, &verifier)
        .await
        .map_err(|_| GithubAuthError::Unavailable)?;
    if !stored {
        return Err(GithubAuthError::Internal);
    }

    let mut location =
        reqwest::Url::parse(&config.authorize_url).map_err(|_| GithubAuthError::Internal)?;
    location
        .query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("state", &state)
        .append_pair("code_challenge", &pkce_challenge(&verifier))
        .append_pair("code_challenge_method", "S256");

    let cookie = format!(
        "{STATE_COOKIE}={state}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/github; Max-Age={STATE_TTL_SECONDS}"
    );
    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location.to_string()),
            (header::SET_COOKIE, cookie),
        ],
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct GithubCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
}

fn state_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| {
            pair.trim()
                .strip_prefix(&format!("{STATE_COOKIE}="))
                .map(str::to_string)
        })
        .next()
}

/// GET /api/auth/github/callback: finish sign-in, claim the held key, start a session.
pub async fn github_callback(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    Extension(config): Extension<Arc<GithubAuthConfig>>,
    headers: HeaderMap,
    Query(query): Query<GithubCallbackQuery>,
) -> Result<Response, GithubAuthError> {
    use subtle::ConstantTimeEq;

    let tenant_id = tenant.0.id;
    let (Some(code), Some(state)) = (query.code, query.state) else {
        return Err(GithubAuthError::InvalidState);
    };
    // The state must come back to the same browser that started the flow.
    let cookie_state = state_cookie(&headers).ok_or(GithubAuthError::InvalidState)?;
    if !bool::from(cookie_state.as_bytes().ct_eq(state.as_bytes())) {
        return Err(GithubAuthError::InvalidState);
    }
    let redis = auth_state
        .state
        .redis
        .as_ref()
        .ok_or(GithubAuthError::Unavailable)?;
    let key = state_key(&state);
    let verifier = redis
        .get(&key)
        .await
        .map_err(|_| GithubAuthError::Unavailable)?
        .ok_or(GithubAuthError::InvalidState)?;
    redis
        .del(&key)
        .await
        .map_err(|_| GithubAuthError::Unavailable)?;

    let github_id = exchange_code_for_user_id(&config, &code, &verifier).await?;
    let external_id = format!("github:{github_id}");

    let pool = &auth_state.state.db;
    let held = HeldKeyRepository::new(pool.clone());
    let lookup = held
        .find_or_create(
            auth_state.state.key_manager.as_ref().as_ref(),
            &external_id,
            tenant_id,
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "GitHub sign-in: held key lookup failed");
            GithubAuthError::Internal
        })?;
    let pubkey = lookup.row.pubkey;
    held.mark_claimed(&pubkey, tenant_id)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "GitHub sign-in: claim failed");
            GithubAuthError::Internal
        })?;

    let status = UserRepository::new(pool.clone())
        .get_user_status(&pubkey, tenant_id)
        .await
        .map_err(|_| GithubAuthError::Internal)?
        .map(|(status, _, _)| status);

    let encrypted = PersonalKeysRepository::new(pool.clone())
        .find_encrypted_key_for_tenant(&pubkey, tenant_id)
        .await
        .map_err(|_| GithubAuthError::Internal)?
        .ok_or(GithubAuthError::Internal)?;
    let secret = auth_state
        .state
        .key_manager
        .decrypt(&encrypted)
        .await
        .map_err(|_| GithubAuthError::Internal)?;
    let keys = Keys::new(
        nostr_sdk::SecretKey::from_slice(&secret).map_err(|_| GithubAuthError::Internal)?,
    );

    let status_ref = status.as_ref().filter(|status| !status.is_active());
    let ucan_token = super::auth::generate_ucan_token(
        &keys,
        tenant_id,
        "",
        &config.session_origin(),
        None,
        status_ref,
    )
    .await
    .map_err(|_| GithubAuthError::Internal)?;

    tracing::info!(
        event = "github_login",
        tenant_id,
        pubkey = %pubkey,
        new_key = lookup.created,
        "Signed in with GitHub"
    );

    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, config.post_login_redirect.clone())],
    )
        .into_response();
    let cookies = response.headers_mut();
    for cookie in [
        format!(
            "keycast_session={ucan_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400"
        ),
        format!(
            "{STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/github; Max-Age=0"
        ),
    ] {
        if let Ok(value) = header::HeaderValue::from_str(&cookie) {
            cookies.append(header::SET_COOKIE, value);
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn state_cookie_is_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "a=1; keycast_github_state=abc; b=2".parse().unwrap(),
        );
        assert_eq!(state_cookie(&headers).as_deref(), Some("abc"));
    }
}
