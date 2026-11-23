// ABOUTME: Email service abstraction for sending verification and password reset emails
// ABOUTME: Supports Resend for production and captured email in development/testing

use async_trait::async_trait;
use serde::Serialize;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

use crate::brand::BRAND_NAME;

/// Minimal HTML-escaping for interpolating untrusted text into email HTML bodies.
/// Defense-in-depth: callers already pass normalized emails (no `<`/`>`), but the
/// senders must not assume that.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Captured email for testing/inspection
#[derive(Debug, Clone, Serialize)]
pub struct CapturedEmail {
    pub to: String,
    pub subject: String,
    pub verification_url: Option<String>,
    pub reset_url: Option<String>,
    /// 6-digit in-app verification PIN, when one was issued alongside the link (keycast#262).
    pub pin: Option<String>,
}

/// Build the HTML body of a verification email.
///
/// When `pin` is present (headless registrations, keycast#262), the body shows a 6-digit code the
/// user can type in the app — a second transport for the same proof, for contexts where the link
/// can't open the app (sandboxed in-app browsers, a different device, a mangled link).
fn verification_email_html(verification_url: &str, pin: Option<&str>) -> String {
    let pin_block = match pin {
        Some(pin) => format!(
            r#"<p style="color: #666; font-size: 14px; margin-top: 30px;">
                    Or enter this verification code in the app:
                </p>
                <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #00B488; margin: 8px 0;">{pin}</p>"#,
            pin = html_escape(pin)
        ),
        None => String::new(),
    };
    format!(
        r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Verify your {brand} email</h1>
                <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>
                <div style="margin: 30px 0;">
                    <a href="{url}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Verify Email Address
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{url}" style="color: #00B488;">{url}</a>
                </p>
                {pin_block}
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    If you didn't sign up for {brand}, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
        url = verification_url,
        brand = BRAND_NAME,
        pin_block = pin_block,
    )
}

/// Build the plain-text body of a verification email (see [`verification_email_html`]).
fn verification_email_text(verification_url: &str, pin: Option<&str>) -> String {
    let pin_block = match pin {
        Some(pin) => format!("\n\nOr enter this verification code in the app: {pin}"),
        None => String::new(),
    };
    format!(
        "Thanks for signing up! Please verify your email address by clicking this link:\n\n{url}{pin_block}\n\nIf you didn't sign up for {brand}, you can safely ignore this email.",
        url = verification_url,
        pin_block = pin_block,
        brand = BRAND_NAME
    )
}

fn build_verification_url(base_url: &str, verification_token: &str) -> String {
    format!("{base_url}/verify-email?token={verification_token}")
}

fn build_claim_confirmation_url(base_url: &str, confirm_token: &str) -> String {
    format!("{base_url}/api/claim/confirm?token={confirm_token}")
}

/// Shared shell for action emails (a titled body with one primary button and a
/// copy-paste fallback link). New emails build on this; shipped bodies are left
/// as-is to preserve their exact rendered output.
fn action_email_html(
    title: &str,
    intro: &str,
    button_label: &str,
    url: &str,
    footer: &str,
) -> String {
    format!(
        r#"
        <html>
        <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #00B488;">{title}</h1>
            <p>{intro}</p>
            <div style="margin: 30px 0;">
                <a href="{url}" style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">{button_label}</a>
            </div>
            <p style="color: #666; font-size: 14px;">Or copy and paste this link into your browser:<br>
                <a href="{url}" style="color: #00B488;">{url}</a></p>
            <p style="color: #666; font-size: 14px; margin-top: 30px;">{footer}</p>
        </body>
        </html>
        "#,
    )
}

fn action_email_text(intro: &str, url: &str, footer: &str) -> String {
    format!("{intro}\n\n{url}\n\n{footer}")
}

/// Trait for email sending - allows swapping implementations for testing
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send the verification email. `pin`, when present, is the 6-digit in-app code emailed
    /// alongside the link (keycast#262).
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
        pin: Option<&str>,
    ) -> Result<(), EmailSendError>;
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), EmailSendError>;

    /// Send a claim link email for a preloaded Vine account.
    async fn send_claim_email(&self, to_email: &str, claim_url: &str)
        -> Result<(), EmailSendError>;

    /// Send a confirmation link that finishes a staged account claim.
    async fn send_claim_confirmation(
        &self,
        to_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError>;

    /// Send a confirmation link to the proposed NEW address during an email change.
    /// The implementation builds the URL from its configured base URL (mirrors
    /// `send_password_reset_email`), so handlers pass only the token.
    async fn send_email_change_confirmation(
        &self,
        to_new_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError>;

    /// Send a security notification to the user's CURRENT (old) address during an email change.
    /// Includes both a confirm link (approve the change) and a cancel link (reject it).
    async fn send_email_change_notification(
        &self,
        to_old_email: &str,
        new_email: &str,
        confirm_token: &str,
        cancel_token: &str,
    ) -> Result<(), EmailSendError>;

    /// Get captured emails (only available in dev/test mode)
    fn get_captured_emails(&self) -> Vec<CapturedEmail> {
        vec![]
    }

    /// Clear captured emails (only available in dev/test mode)
    fn clear_captured_emails(&self) {
        // No-op by default
    }
}

/// Stable terminal categories for email-provider calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailProviderOutcome {
    Accepted,
    Rejected,
    RateLimited,
    TimedOut,
    Unavailable,
}

impl EmailProviderOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::RateLimited => "rate_limited",
            Self::TimedOut => "timed_out",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Redacted email-provider error suitable for logs and audit reason codes.
#[derive(Debug, Error)]
pub enum EmailSendError {
    #[error("email provider rejected the request")]
    Rejected,
    #[error("email provider rate limited the request")]
    RateLimited,
    #[error("email provider request timed out")]
    TimedOut,
    #[error("email provider is unavailable")]
    Unavailable,
}

impl EmailSendError {
    #[must_use]
    pub const fn outcome(&self) -> EmailProviderOutcome {
        match self {
            Self::Rejected => EmailProviderOutcome::Rejected,
            Self::RateLimited => EmailProviderOutcome::RateLimited,
            Self::TimedOut => EmailProviderOutcome::TimedOut,
            Self::Unavailable => EmailProviderOutcome::Unavailable,
        }
    }
}

/// Development email sender that captures messages for testing.
pub struct DevEmailSender {
    base_url: String,
    captured: Arc<Mutex<Vec<CapturedEmail>>>,
}

impl DevEmailSender {
    pub fn new() -> Self {
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        tracing::info!("===========================================");
        tracing::info!("  EMAIL SERVICE: Development Mode");
        tracing::info!("  Emails will be captured in memory");
        tracing::info!("  Base URL: {}", base_url);
        tracing::info!("===========================================");

        Self {
            base_url,
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get a clone of the captured emails storage for sharing with tests
    pub fn captured_emails(&self) -> Arc<Mutex<Vec<CapturedEmail>>> {
        self.captured.clone()
    }
}

impl Default for DevEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailSender for DevEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
        pin: Option<&str>,
    ) -> Result<(), EmailSendError> {
        // This public path is claimed by the mobile apps and also verifies server-side when a
        // browser keeps the link instead of handing it to the app (keycast#360).
        let verification_url = build_verification_url(&self.base_url, verification_token);

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  VERIFICATION EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  Subject: Verify your {} email address", BRAND_NAME);
        tracing::info!("==================================================");
        tracing::info!("");

        // Capture for testing
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: format!("Verify your {} email address", BRAND_NAME),
                verification_url: Some(verification_url),
                reset_url: None,
                pin: pin.map(str::to_string),
            });
        }

        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), EmailSendError> {
        let reset_url = format!(
            "{}/reset-password?token={}&email={}",
            self.base_url,
            reset_token,
            urlencoding::encode(to_email),
        );

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  PASSWORD RESET EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  Subject: Reset your {} password", BRAND_NAME);
        tracing::info!("==================================================");
        tracing::info!("");

        // Capture for testing
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: format!("Reset your {} password", BRAND_NAME),
                verification_url: None,
                reset_url: Some(reset_url),
                pin: None,
            });
        }

        Ok(())
    }

    async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
    ) -> Result<(), EmailSendError> {
        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  VINE CLAIM EMAIL");
        tracing::info!("==================================================");
        tracing::info!(
            "  Subject: Your Vine account on {} is ready to claim",
            BRAND_NAME
        );
        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("");

        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: format!("Your Vine account on {} is ready to claim", BRAND_NAME),
                verification_url: Some(claim_url.to_string()),
                reset_url: None,
                pin: None,
            });
        }

        Ok(())
    }

    async fn send_claim_confirmation(
        &self,
        to_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError> {
        let confirm_url = build_claim_confirmation_url(&self.base_url, confirm_token);

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  CLAIM CONFIRMATION EMAIL");
        tracing::info!("==================================================");
        tracing::info!(
            "  Subject: Confirm your email to claim your {} account",
            BRAND_NAME
        );
        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("");

        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: format!("Confirm your email to claim your {} account", BRAND_NAME),
                verification_url: Some(confirm_url),
                reset_url: None,
                pin: None,
            });
        }

        Ok(())
    }

    async fn send_email_change_confirmation(
        &self,
        to_new_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError> {
        let confirm_url = format!(
            "{}/confirm-email-change?token={}",
            self.base_url, confirm_token
        );
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_new_email.to_string(),
                subject: format!("Confirm your new {} email address", BRAND_NAME),
                verification_url: Some(confirm_url),
                reset_url: None,
                pin: None,
            });
        }

        Ok(())
    }

    async fn send_email_change_notification(
        &self,
        to_old_email: &str,
        _new_email: &str,
        confirm_token: &str,
        cancel_token: &str,
    ) -> Result<(), EmailSendError> {
        let confirm_url = format!(
            "{}/confirm-email-change?token={}",
            self.base_url, confirm_token
        );
        let cancel_url = format!(
            "{}/cancel-email-change?token={}",
            self.base_url, cancel_token
        );
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_old_email.to_string(),
                subject: format!("Confirm the email change on your {} account", BRAND_NAME),
                // Store the confirm link for test inspection; cancel link goes in reset_url.
                verification_url: Some(confirm_url),
                reset_url: Some(cancel_url),
                pin: None,
            });
        }

        Ok(())
    }

    fn get_captured_emails(&self) -> Vec<CapturedEmail> {
        self.captured
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn clear_captured_emails(&self) {
        if let Ok(mut captured) = self.captured.lock() {
            captured.clear();
        }
    }
}

/// Request body for Resend's `POST /emails`
/// (https://resend.com/docs/api-reference/emails/send-email).
#[derive(Serialize)]
struct ResendEmail<'a> {
    from: String,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
    text: &'a str,
}

/// Settings for [`ResendEmailSender`]. Never logged: `api_key` is a secret.
#[derive(Clone)]
pub struct ResendConfig {
    /// `RESEND_API_KEY`
    pub api_key: String,
    /// `RESEND_API_URL`, default `https://api.resend.com` (tests point it at a mock).
    pub api_url: String,
    /// `FROM_EMAIL`, an address on the domain verified in Resend, e.g. `noreply@mail.creditedby.com`.
    pub from_email: String,
    /// `FROM_NAME`
    pub from_name: String,
    /// `BASE_URL` or `APP_URL`, used to build links in emails.
    pub base_url: String,
}

impl ResendConfig {
    /// Read the settings from the environment.
    #[must_use]
    pub fn from_env(api_key: String) -> Self {
        Self {
            api_key,
            api_url: env::var("RESEND_API_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "https://api.resend.com".to_string()),
            from_email: env::var("FROM_EMAIL")
                .unwrap_or_else(|_| "noreply@mail.creditedby.com".to_string()),
            from_name: env::var("FROM_NAME").unwrap_or_else(|_| BRAND_NAME.to_string()),
            base_url: env::var("BASE_URL")
                .or_else(|_| env::var("APP_URL"))
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
        }
    }
}

pub struct ResendEmailSender {
    api_key: String,
    api_url: String,
    from_email: String,
    from_name: String,
    base_url: String,
    client: reqwest::Client,
}

impl ResendEmailSender {
    pub fn new(api_key: String) -> Result<Self, String> {
        Self::with_config(ResendConfig::from_env(api_key))
    }

    pub fn with_config(config: ResendConfig) -> Result<Self, String> {
        let ResendConfig {
            api_key,
            api_url,
            from_email,
            from_name,
            base_url,
        } = config;

        tracing::info!("Email service initialized with Resend");

        let connect_timeout = duration_from_env("EMAIL_PROVIDER_CONNECT_TIMEOUT_MS", 3_000);
        let request_timeout = duration_from_env("EMAIL_PROVIDER_REQUEST_TIMEOUT_MS", 10_000);
        let client = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .build()
            .map_err(|error| format!("failed to build email HTTP client: {error}"))?;

        Ok(Self {
            api_key,
            api_url: api_url.trim_end_matches('/').to_string(),
            from_email,
            from_name,
            base_url,
            client,
        })
    }

    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_content: &str,
        text_content: &str,
    ) -> Result<(), EmailSendError> {
        // Check if emails are disabled (useful for load testing)
        if env::var("DISABLE_EMAILS").is_ok() {
            tracing::info!("Emails disabled via DISABLE_EMAILS env var, skipping provider call");
            return Ok(());
        }

        // Resend has no per-message tracking switch: click and open tracking
        // must stay off on the sending domain, so tokens in links never pass
        // through a redirect server.
        let from = format!("{} <{}>", self.from_name, self.from_email);
        let email = ResendEmail {
            from,
            to: [to_email],
            subject,
            html: html_content,
            text: text_content,
        };

        let response = self
            .client
            .post(format!("{}/emails", self.api_url))
            .bearer_auth(&self.api_key)
            .json(&email)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    EmailSendError::TimedOut
                } else {
                    EmailSendError::Unavailable
                }
            })?;

        if response.status().is_success() {
            tracing::info!("Email provider accepted request");
            Ok(())
        } else {
            let status = response.status();
            tracing::warn!(status = status.as_u16(), "Email provider rejected request");
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                Err(EmailSendError::RateLimited)
            } else if status.is_client_error() {
                Err(EmailSendError::Rejected)
            } else {
                Err(EmailSendError::Unavailable)
            }
        }
    }
}

fn duration_from_env(name: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default_ms),
    )
}

#[async_trait]
impl EmailSender for ResendEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
        pin: Option<&str>,
    ) -> Result<(), EmailSendError> {
        // This public path is claimed by the mobile apps and also verifies server-side when a
        // browser keeps the link instead of handing it to the app (keycast#360).
        let verification_url = build_verification_url(&self.base_url, verification_token);

        let subject = format!("Verify your {} email address", BRAND_NAME);
        let html_content = verification_email_html(&verification_url, pin);
        let text_content = verification_email_text(&verification_url, pin);

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), EmailSendError> {
        let reset_url = format!(
            "{}/reset-password?token={}&email={}",
            self.base_url,
            reset_token,
            urlencoding::encode(to_email),
        );

        let subject = format!("Reset your {} password", BRAND_NAME);
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Reset your {brand} password</h1>
                <p>We received a request to reset your password. Click the button below to set a new password:</p>
                <div style="margin: 30px 0;">
                    <a href="{url}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Reset Password
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{url}" style="color: #00B488;">{url}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            url = reset_url,
            brand = BRAND_NAME
        );

        let text_content = format!(
            "We received a request to reset your password. Click this link to set a new password:\n\n{url}\n\nThis link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.",
            url = reset_url
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
    ) -> Result<(), EmailSendError> {
        let subject = format!("Your Vine account on {} is ready to claim", BRAND_NAME);
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Your Vine account is ready!</h1>
                <p>Your Vine account has been migrated to {brand}. Click the button below to claim it and set up your login:</p>
                <div style="margin: 30px 0;">
                    <a href="{url}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Claim Your Account
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{url}" style="color: #00B488;">{url}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    This link will expire in 14 days. If you didn't request this, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            url = claim_url,
            brand = BRAND_NAME
        );

        let text_content = format!(
            "Your Vine account has been migrated to {brand}. Click this link to claim it:\n\n{url}\n\nThis link will expire in 14 days. If you didn't request this, you can safely ignore this email.",
            url = claim_url, brand = BRAND_NAME
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_claim_confirmation(
        &self,
        to_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError> {
        let confirm_url = build_claim_confirmation_url(&self.base_url, confirm_token);
        let subject = format!("Confirm your email to claim your {} account", BRAND_NAME);
        let intro = format!(
            "Confirm this email address to finish claiming your {} account.",
            BRAND_NAME
        );
        let footer = "This link will expire in 24 hours. If you didn't request this, you can safely ignore this email.";
        let html = action_email_html(
            "Confirm your email",
            &intro,
            "Confirm Email",
            &confirm_url,
            footer,
        );
        let text = action_email_text(&intro, &confirm_url, footer);
        self.send_email(to_email, &subject, &html, &text).await
    }

    async fn send_email_change_confirmation(
        &self,
        to_new_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError> {
        let confirm_url = format!(
            "{}/confirm-email-change?token={}",
            self.base_url, confirm_token
        );
        let subject = format!("Confirm your new {} email address", BRAND_NAME);
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Confirm your new email</h1>
                <p>You requested to use this address for your {brand} account. Click the button below to confirm it. The change only takes effect after both your old and new addresses confirm.</p>
                <div style="margin: 30px 0;">
                    <a href="{url}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Confirm New Email
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{url}" style="color: #00B488;">{url}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    This link will expire in 24 hours. If you didn't request this, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            url = confirm_url,
            brand = BRAND_NAME
        );

        let text_content = format!(
            "You requested to use this address for your {brand} account. Confirm it by clicking this link:\n\n{url}\n\nThe change only takes effect after both your old and new addresses confirm. This link will expire in 24 hours. If you didn't request this, you can safely ignore this email.",
            url = confirm_url, brand = BRAND_NAME
        );

        self.send_email(to_new_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_email_change_notification(
        &self,
        to_old_email: &str,
        new_email: &str,
        confirm_token: &str,
        cancel_token: &str,
    ) -> Result<(), EmailSendError> {
        let confirm_url = format!(
            "{}/confirm-email-change?token={}",
            self.base_url, confirm_token
        );
        let cancel_url = format!(
            "{}/cancel-email-change?token={}",
            self.base_url, cancel_token
        );
        // Escape the new address for the HTML context (defense-in-depth; callers normalize it).
        let new_email_html = html_escape(new_email);
        let subject = format!("Confirm the email change on your {} account", BRAND_NAME);
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Email change requested</h1>
                <p>Someone requested to change the email address on your {brand} account to <strong>{new_email}</strong>. The change only takes effect after you confirm here <em>and</em> the new address is verified.</p>
                <div style="margin: 30px 0;">
                    <a href="{confirm_url}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Confirm Change
                    </a>
                </div>
                <p style="margin: 20px 0;">
                    <strong>Didn't request this?</strong> Cancel it immediately and consider changing your password:
                </p>
                <div style="margin: 20px 0;">
                    <a href="{cancel_url}"
                       style="background: #b00020; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Cancel Change
                    </a>
                </div>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    These links will expire in 24 hours.
                </p>
            </body>
            </html>
            "#,
            new_email = new_email_html,
            confirm_url = confirm_url,
            cancel_url = cancel_url,
            brand = BRAND_NAME
        );

        let text_content = format!(
            "Someone requested to change the email address on your {brand} account to {new_email}.\n\nConfirm the change:\n{confirm_url}\n\nDidn't request this? Cancel it immediately and consider changing your password:\n{cancel_url}\n\nThese links will expire in 24 hours.",
            new_email = new_email, confirm_url = confirm_url, cancel_url = cancel_url, brand = BRAND_NAME
        );

        self.send_email(to_old_email, &subject, &html_content, &text_content)
            .await
    }
}

/// Create the appropriate email sender based on environment
/// - If RESEND_API_KEY is set and non-empty: use Resend (production)
/// - If running in production without RESEND_API_KEY and without DISABLE_EMAILS: fail with error
/// - Otherwise (development): use DevEmailSender as fallback
pub fn create_email_sender() -> Result<Arc<dyn EmailSender>, String> {
    if let Ok(api_key) = env::var("RESEND_API_KEY") {
        if !api_key.is_empty() {
            return Ok(Arc::new(ResendEmailSender::new(api_key)?));
        }
    }

    let env_mode = env::var("RUST_ENV")
        .or_else(|_| env::var("NODE_ENV"))
        .unwrap_or_else(|_| "development".to_string());
    if env_mode == "production"
        && env::var("DISABLE_EMAILS")
            .ok()
            .filter(|v| v == "true")
            .is_none()
    {
        return Err(
            "RESEND_API_KEY required in production (set DISABLE_EMAILS=true to override)"
                .to_string(),
        );
    }

    tracing::warn!("RESEND_API_KEY not set - using development email sender");
    Ok(Arc::new(DevEmailSender::new()))
}

/// Validate production email configuration without constructing a provider client.
pub fn validate_email_configuration() -> Result<(), String> {
    if env::var("RESEND_API_KEY")
        .ok()
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(());
    }
    let env_mode = env::var("RUST_ENV")
        .or_else(|_| env::var("NODE_ENV"))
        .unwrap_or_else(|_| "development".to_string());
    if env_mode == "production"
        && env::var("DISABLE_EMAILS")
            .ok()
            .filter(|value| value == "true")
            .is_none()
    {
        return Err(
            "RESEND_API_KEY required in production (set DISABLE_EMAILS=true to override)"
                .to_string(),
        );
    }
    Ok(())
}

/// Legacy EmailService for backward compatibility during migration
/// TODO: Remove once all usages are migrated to the trait
pub struct EmailService {
    inner: Arc<dyn EmailSender>,
}

impl EmailService {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            inner: create_email_sender()?,
        })
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
        pin: Option<&str>,
    ) -> Result<(), EmailSendError> {
        self.inner
            .send_verification_email(to_email, verification_token, pin)
            .await
    }

    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), EmailSendError> {
        self.inner
            .send_password_reset_email(to_email, reset_token)
            .await
    }

    pub async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
    ) -> Result<(), EmailSendError> {
        self.inner.send_claim_email(to_email, claim_url).await
    }

    pub async fn send_claim_confirmation(
        &self,
        to_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError> {
        self.inner
            .send_claim_confirmation(to_email, confirm_token)
            .await
    }

    pub async fn send_email_change_confirmation(
        &self,
        to_new_email: &str,
        confirm_token: &str,
    ) -> Result<(), EmailSendError> {
        self.inner
            .send_email_change_confirmation(to_new_email, confirm_token)
            .await
    }

    pub async fn send_email_change_notification(
        &self,
        to_old_email: &str,
        new_email: &str,
        confirm_token: &str,
        cancel_token: &str,
    ) -> Result<(), EmailSendError> {
        self.inner
            .send_email_change_notification(to_old_email, new_email, confirm_token, cancel_token)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn verification_links_use_the_public_app_link_path() {
        assert_eq!(
            build_verification_url("https://login.divine.video", "abc"),
            "https://login.divine.video/verify-email?token=abc"
        );
    }

    #[test]
    fn verification_email_bodies_include_pin_when_present() {
        let url = "https://login.example/verify-email?token=abc";
        let html = verification_email_html(url, Some("482913"));
        let text = verification_email_text(url, Some("482913"));
        assert!(html.contains("482913"), "HTML body must show the PIN");
        assert!(text.contains("482913"), "text body must show the PIN");
        // Link is still present alongside the PIN (two transports for the same proof).
        assert!(html.contains(url));
        assert!(text.contains(url));
    }

    #[test]
    fn verification_email_bodies_omit_pin_when_absent() {
        let url = "https://login.example/verify-email?token=abc";
        let html = verification_email_html(url, None);
        let text = verification_email_text(url, None);
        // No 6-digit code block when no PIN was issued (browser/OAuth flows).
        assert!(!html.to_lowercase().contains("verification code"));
        assert!(!text.to_lowercase().contains("verification code"));
        assert!(html.contains(url));
    }

    #[test]
    fn action_email_html_has_shell_button_and_fallback_link() {
        let url = "https://login.example/api/claim/confirm?token=abc";
        let html = action_email_html(
            "Confirm your email",
            "Click to finish.",
            "Confirm",
            url,
            "Expires in 24 hours.",
        );
        assert!(html.contains("Confirm your email")); // title
        assert!(html.contains(">Confirm<")); // button label
        assert!(html.contains(url)); // button href + fallback link
        assert!(html.contains("Expires in 24 hours.")); // footer
    }

    #[tokio::test]
    async fn dev_sender_captures_claim_confirmation() {
        let sender = DevEmailSender::new();
        sender
            .send_claim_confirmation("user@example.com", "conf-tok")
            .await
            .unwrap();
        let captured = sender.get_captured_emails();
        assert_eq!(captured.len(), 1);
        assert!(captured[0]
            .verification_url
            .as_deref()
            .is_some_and(|u| u.ends_with("/api/claim/confirm?token=conf-tok")));
    }

    #[tokio::test]
    async fn dev_sender_captures_pin() {
        let sender = DevEmailSender::new();
        sender
            .send_verification_email("user@example.com", "tok123", Some("482913"))
            .await
            .unwrap();
        let captured = sender.get_captured_emails();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].pin.as_deref(), Some("482913"));
        assert!(
            captured[0]
                .verification_url
                .as_deref()
                .is_some_and(|url| url.ends_with("/verify-email?token=tok123")),
            "verification emails must use the public app-link path"
        );
    }

    // Serial test lock to prevent env var races between tests
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper to run a closure with specific env vars set, restoring originals afterward
    fn with_env_vars<F, R>(vars: &[(&str, Option<&str>)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut originals = Vec::new();
        for (key, val) in vars {
            originals.push((*key, env::var(key).ok()));
            match val {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }
        let result = f();
        for (key, original) in originals {
            match original {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }
        result
    }

    #[test]
    fn test_production_without_resend_key_fails() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        let err = result.err().expect("expected an error");
        assert!(
            err.contains("RESEND_API_KEY required in production"),
            "unexpected error message: {}",
            err
        );
    }

    #[test]
    fn test_production_with_disable_emails_ok() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", Some("true")),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_production_with_resend_key_ok() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", Some("re_test_not_a_real_key")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_development_without_resend_key_ok() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", None),
                ("RUST_ENV", None),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_production_via_node_env_without_resend_key_fails() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", None),
                ("RUST_ENV", None),
                ("NODE_ENV", Some("production")),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_resend_key_treated_as_unset() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", Some("")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_disable_emails_still_requires_resend_in_production() {
        let result = with_env_vars(
            &[
                ("RESEND_API_KEY", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", Some("")),
            ],
            create_email_sender,
        );
        assert!(
            result.is_err(),
            "Empty DISABLE_EMAILS should not bypass production check"
        );
    }

    // ------------------------------------------------------------------
    // Resend sender against a mock Resend API
    // ------------------------------------------------------------------

    /// (Authorization header, JSON body) of each request the mock received.
    type RecordedRequests = Arc<Mutex<Vec<(Option<String>, serde_json::Value)>>>;

    #[derive(Clone, Default)]
    struct MockResend {
        requests: RecordedRequests,
        status: Arc<Mutex<u16>>,
    }

    async fn mock_resend_emails(
        axum::extract::State(mock): axum::extract::State<MockResend>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        mock.requests.lock().unwrap().push((auth, body));
        let status = *mock.status.lock().unwrap();
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            axum::Json(serde_json::json!({ "id": "mock-email-id" })),
        )
    }

    async fn start_mock_resend(status: u16) -> (String, MockResend) {
        let mock = MockResend::default();
        *mock.status.lock().unwrap() = status;
        let app = axum::Router::new()
            .route("/emails", axum::routing::post(mock_resend_emails))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), mock)
    }

    fn resend_sender(api_url: String) -> ResendEmailSender {
        ResendEmailSender::with_config(ResendConfig {
            // TEST HARNESS ONLY: not a real key.
            api_key: "re_test_not_a_real_key".to_string(),
            api_url,
            from_email: "noreply@mail.creditedby.com".to_string(),
            from_name: "Credited By".to_string(),
            base_url: "https://keys.example.test".to_string(),
        })
        .unwrap()
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn resend_sends_verification_email_with_expected_request() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("DISABLE_EMAILS");
        let (url, mock) = start_mock_resend(200).await;
        let sender = resend_sender(format!("{url}/"));

        sender
            .send_verification_email("person@example.test", "tok123", Some("123456"))
            .await
            .expect("accepted");

        let requests = mock.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let (auth, body) = &requests[0];
        assert_eq!(auth.as_deref(), Some("Bearer re_test_not_a_real_key"));
        assert_eq!(body["from"], "Credited By <noreply@mail.creditedby.com>");
        assert_eq!(body["to"], serde_json::json!(["person@example.test"]));
        assert!(body["subject"].as_str().unwrap().contains("Verify"));
        let verify_url = "https://keys.example.test/verify-email?token=tok123";
        assert!(body["html"].as_str().unwrap().contains(verify_url));
        assert!(body["text"].as_str().unwrap().contains(verify_url));
        assert!(body["text"].as_str().unwrap().contains("123456"));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn resend_maps_provider_failures() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("DISABLE_EMAILS");
        for (status, expected) in [
            (429, EmailSendError::RateLimited),
            (422, EmailSendError::Rejected),
            (401, EmailSendError::Rejected),
            (500, EmailSendError::Unavailable),
        ] {
            let (url, _mock) = start_mock_resend(status).await;
            let err = resend_sender(url)
                .send_password_reset_email("person@example.test", "reset-tok")
                .await
                .expect_err("provider refused");
            assert_eq!(
                std::mem::discriminant(&err),
                std::mem::discriminant(&expected),
                "status {status}"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn resend_unreachable_is_unavailable() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("DISABLE_EMAILS");
        // Bind then drop, so the port is closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let err = resend_sender(url)
            .send_claim_confirmation("person@example.test", "tok")
            .await
            .expect_err("unreachable");
        assert!(matches!(
            err,
            EmailSendError::Unavailable | EmailSendError::TimedOut
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn resend_disable_emails_skips_provider() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (url, mock) = start_mock_resend(200).await;
        env::set_var("DISABLE_EMAILS", "true");
        let result = resend_sender(url)
            .send_claim_email("person@example.test", "https://keys.example.test/claim")
            .await;
        env::remove_var("DISABLE_EMAILS");
        result.expect("skipped");
        assert!(mock.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn resend_config_reads_environment() {
        let config = with_env_vars(
            &[
                ("RESEND_API_URL", Some("http://127.0.0.1:4319")),
                ("FROM_EMAIL", Some("noreply@mail.creditedby.com")),
                ("FROM_NAME", Some("Credited By")),
                ("BASE_URL", Some("https://keys.example.test")),
            ],
            || ResendConfig::from_env("re_test_not_a_real_key".to_string()),
        );
        assert_eq!(config.api_url, "http://127.0.0.1:4319");
        assert_eq!(config.from_email, "noreply@mail.creditedby.com");
        assert_eq!(config.from_name, "Credited By");
        assert_eq!(config.base_url, "https://keys.example.test");
        let defaults = with_env_vars(&[("RESEND_API_URL", None), ("FROM_EMAIL", None)], || {
            ResendConfig::from_env("re_test_not_a_real_key".to_string())
        });
        assert_eq!(defaults.api_url, "https://api.resend.com");
        assert_eq!(defaults.from_email, "noreply@mail.creditedby.com");
    }
}
