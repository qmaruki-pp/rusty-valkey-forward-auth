use anyhow::{Context, Error};
use confique::Config;
use std::convert::Infallible;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

/// Default token salt (echo rusty-valkey-forward-auth | sha256sum).
pub(crate) const DEFAULT_TOKEN_SALT_HEX: &str =
    "3794447850d23a5db972dbe556437ec2edfe4294687843d7f0587bd9535beecf";

#[derive(Config)]
pub(crate) struct RVFAConfig {
    /// Port to listen on.
    #[config(env = "PORT", default = 8080)]
    pub port: u16,

    /// Bind address.
    #[config(env = "ADDRESS", default = "127.0.0.1")]
    pub address: IpAddr,

    /// Valkey server URL.
    #[config(env = "VALKEY_URL", default = "redis://127.0.0.1:6379")]
    pub valkey_url: String,

    /// Valkey username
    #[config(env = "VALKEY_USERNAME")]
    pub valkey_username: Option<String>,

    /// Valkey password
    #[config(env = "VALKEY_PASSWORD")]
    pub valkey_password: Option<String>,

    /// Valkey database
    #[config(env = "VALKEY_DATABASE_ID", default = 0)]
    pub valkey_database_id: u8,

    /// Token hashing salt (32 bytes hex-encoded, 64 characters). Used as the keyed blake3 salt.
    /// IMPORTANT: Keep this secret and consistent across deployments.
    #[config(env = "TOKEN_SALT")]
    pub token_salt: String,

    #[config(nested)]
    pub cors: CorsConfig,

    #[config(nested)]
    pub oauth: OAuthConfig,

    /// Static API key that grants admin access to `/api/users/*` routes.
    /// When set, a request bearing this value as a Bearer token is treated as an admin
    /// without requiring OAuth2 validation.  Keep this secret.
    #[config(env = "ADMIN_API_KEY")]
    pub admin_api_key: Option<String>,

    /// Directory containing pre-built frontend assets to serve at `/`.
    #[config(env = "STATIC_DIR")]
    pub static_dir: Option<PathBuf>,

    #[config(nested)]
    pub frontend: FrontendConfig,
}

impl RVFAConfig {
    pub fn load() -> Result<Self, Error> {
        let file = std::env::var("CONFIG_FILE").unwrap_or("settings.toml".to_string());
        let mut config = <Self as Config>::builder().env().file(file).load()?;

        if config
            .static_dir
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            config.static_dir = None;
        }

        if config.static_dir.is_none() {
            config.static_dir = Some(PathBuf::from("frontend/dist"));
        }

        config.frontend.materialize(&config.oauth)?;

        if config.token_salt.trim().is_empty() {
            config.token_salt = DEFAULT_TOKEN_SALT_HEX.to_string();
        }

        if let Some(key) = &config.admin_api_key
            && key.trim().is_empty()
        {
            config.admin_api_key = None;
        }

        if config
            .token_salt
            .eq_ignore_ascii_case(DEFAULT_TOKEN_SALT_HEX)
        {
            tracing::warn!(
                "TOKEN_SALT is using the built-in default; generate a unique salt for production."
            );
        }

        Ok(config)
    }

    pub fn token_salt_bytes(&self) -> Result<[u8; 32], Error> {
        let decoded = hex::decode(&self.token_salt)?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "TOKEN_SALT must be exactly 32 bytes (64 hex characters), got {} bytes",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}

#[derive(Clone, Config)]
pub(crate) struct FrontendConfig {
    /// Optional override for the API base URL consumed by the frontend.
    #[config(env = "FRONTEND_API_BASE_URL")]
    pub api_base_url: Option<String>,

    /// Human-friendly application name for the frontend.
    #[config(env = "FRONTEND_APP_NAME", default = "Rusty Valkey Forward Auth")]
    pub app_name: String,

    /// Authority URL for the frontend OIDC client.
    #[config(env = "FRONTEND_OIDC_AUTHORITY")]
    pub oidc_authority: Option<String>,

    /// Client identifier for the frontend OIDC client.
    #[config(env = "FRONTEND_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    /// Optional redirect URI override for the frontend OIDC client.
    #[config(env = "FRONTEND_OIDC_REDIRECT_URI")]
    pub oidc_redirect_uri: Option<String>,

    /// Path to an HTML snippet rendered within the frontend.
    #[config(env = "FRONTEND_DOCS_HTML_FILE")]
    pub docs_html_file: Option<PathBuf>,

    /// Inline HTML snippet rendered within the frontend.
    #[config(env = "FRONTEND_DOCS_HTML")]
    pub docs_html: Option<String>,

    /// Relative path (or absolute URL) to the API documentation.
    #[config(env = "FRONTEND_API_DOCS_PATH", default = "/docs")]
    pub api_docs_path: String,
}

#[derive(Clone)]
pub struct FrontendPublicConfig {
    pub api_base_url: Option<String>,
    pub app_name: String,
    pub oidc_authority: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub docs_html: Option<String>,
    pub api_docs_path: String,
}

impl FrontendConfig {
    fn materialize(&mut self, oauth: &OAuthConfig) -> Result<(), Error> {
        self.api_base_url = take_trimmed(self.api_base_url.take()).map(normalize_base_url);

        self.app_name = self.app_name.trim().to_string();
        if self.app_name.is_empty() {
            self.app_name = "Valkey Token Manager".to_string();
        }

        self.oidc_authority = take_trimmed(self.oidc_authority.take()).or_else(|| {
            oauth.issuer_url.as_ref().and_then(|issuer| {
                let trimmed = issuer.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
        });

        self.oidc_client_id = take_trimmed(self.oidc_client_id.take());

        if self.oidc_client_id.is_none() {
            self.oidc_client_id = Some("rusty-valkey-forward-auth-dev".to_string());
        }

        self.oidc_redirect_uri = take_trimmed(self.oidc_redirect_uri.take());

        if let Some(path) = self.docs_html_file.take()
            && !path.as_os_str().is_empty()
        {
            let html = fs::read_to_string(&path).with_context(|| {
                format!("failed to read FRONTEND_DOCS_HTML_FILE {}", path.display())
            })?;
            self.docs_html = Some(html);
        }

        self.docs_html = self.docs_html.take().and_then(|html| {
            if html.trim().is_empty() {
                None
            } else {
                Some(html)
            }
        });

        let docs_path_trimmed = self.api_docs_path.trim();
        if docs_path_trimmed.is_empty() {
            self.api_docs_path = "/docs".to_string();
        } else if docs_path_trimmed.starts_with("http://")
            || docs_path_trimmed.starts_with("https://")
        {
            self.api_docs_path = docs_path_trimmed.to_string();
        } else {
            let normalized = docs_path_trimmed.trim_start_matches('/');
            self.api_docs_path = format!("/{}", normalized);
        }

        Ok(())
    }

    pub fn public_view(&self) -> FrontendPublicConfig {
        FrontendPublicConfig {
            api_base_url: self.api_base_url.clone(),
            app_name: self.app_name.clone(),
            oidc_authority: self.oidc_authority.clone(),
            oidc_client_id: self.oidc_client_id.clone(),
            oidc_redirect_uri: self.oidc_redirect_uri.clone(),
            docs_html: self.docs_html.clone(),
            api_docs_path: self.api_docs_path.clone(),
        }
    }
}

fn take_trimmed(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_base_url(url: String) -> String {
    if url == "/" {
        return String::new();
    }

    let mut normalized = url;
    while normalized.ends_with('/') && !normalized.ends_with("://") {
        normalized.pop();
    }
    normalized
}

#[derive(Clone, Config)]
pub(crate) struct OAuthConfig {
    /// Issuer URL used for OIDC discovery and issuer validation.
    #[config(env = "OAUTH_ISSUER_URL")]
    pub issuer_url: Option<String>,

    /// Optional JWKS URL. When provided, discovery is skipped and the JWKS is polled directly.
    #[config(env = "OAUTH_JWKS_URL")]
    pub jwks_url: Option<String>,

    /// Optional tenant identifier to distinguish the configured authorization server.
    #[config(env = "OAUTH_TENANT_ID")]
    pub tenant_id: Option<String>,

    /// Audiences that incoming tokens must contain.
    #[config(default = [])]
    pub audiences: Vec<String>,

    /// Interval (in seconds) for JWKS refresh when jwks_url is set.
    #[config(env = "OAUTH_JWKS_REFRESH_SECS", default = 300)]
    pub jwks_refresh_interval_secs: u64,

    #[config(nested)]
    pub claims: OAuthClaimsConfig,

    #[config(nested)]
    pub admin: OAuthAdminConfig,
}

#[derive(Clone, Config)]
pub(crate) struct OAuthClaimsConfig {
    /// Claim name used as the subject identifier.
    #[config(env = "OAUTH_SUBJECT_CLAIM", default = "sub")]
    pub subject: String,

    /// Claim containing group or role memberships.
    #[config(env = "OAUTH_GROUPS_CLAIM", default = "groups")]
    pub groups: String,
}

#[derive(Clone, Config)]
pub(crate) struct OAuthAdminConfig {
    /// Group/role value required for admin access. Set to an empty string to disable enforcement.
    #[config(env = "OAUTH_ADMIN_GROUP", default = "admin")]
    pub group: String,

    /// Treat admin group comparisons as case-sensitive.
    #[config(env = "OAUTH_ADMIN_CASE_SENSITIVE", default = false)]
    pub group_case_sensitive: bool,
}

#[derive(Clone, Config, Default)]
pub(crate) struct CorsConfig {
    /// Enable CORS for the HTTP API.
    #[config(env = "CORS_ENABLED", default = false)]
    pub enabled: bool,

    /// Origins allowed to access the API when CORS is enabled. Use "*" to allow any origin.
    #[config(
        env = "CORS_ALLOW_ORIGINS",
        default = [],
        parse_env = parse_cors_allow_origins
    )]
    pub allow_origins: Vec<String>,
}

fn parse_cors_allow_origins(raw: &str) -> Result<Vec<String>, Infallible> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }

    Ok(raw
        .split(',')
        .map(|origin| origin.trim())
        .filter(|origin| !origin.is_empty())
        .map(|origin| origin.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::parse_cors_allow_origins;

    #[test]
    fn parse_empty_string_returns_empty_vec() {
        let parsed = parse_cors_allow_origins("").expect("parser should not fail");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_single_origin_trims_whitespace() {
        let parsed =
            parse_cors_allow_origins("  http://localhost:3000  ").expect("parser should not fail");
        assert_eq!(parsed, vec!["http://localhost:3000".to_string()]);
    }

    #[test]
    fn parse_multiple_origins_ignores_extra_commas() {
        let parsed = parse_cors_allow_origins("http://one.test, http://two.test , ,")
            .expect("parser should not fail");
        assert_eq!(
            parsed,
            vec!["http://one.test".to_string(), "http://two.test".to_string()]
        );
    }

    #[test]
    fn parse_allows_wildcard_origin() {
        let parsed =
            parse_cors_allow_origins("*,http://example.test").expect("parser should not fail");
        assert_eq!(
            parsed,
            vec!["*".to_string(), "http://example.test".to_string()]
        );
    }
}
