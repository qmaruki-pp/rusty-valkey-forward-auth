use crate::{
    auth,
    config::{CorsConfig, FrontendPublicConfig, RVFAConfig},
    storage,
};
use anyhow::Context;
use axum::body::Body;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fred::prelude::ClientLike;
use rand::TryRng;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower_helmet::HelmetLayer;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{Level, debug, info, warn};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_scalar::{Scalar, Servable as ScalarServable};

#[derive(Clone)]
pub struct AppState {
    pub client: fred::clients::Client,
    pub token_salt: [u8; 32],
    pub auth: Arc<auth::AuthState>,
    pub frontend: FrontendPublicConfig,
}

pub async fn serve(config: &RVFAConfig, client: fred::clients::Client) -> anyhow::Result<()> {
    let token_salt = config.token_salt_bytes()?;
    let auth_state = Arc::new(auth::AuthState::from_config(&config.oauth).await?);
    let cors_layer = cors_layer_from_config(&config.cors)?;
    let frontend_config = config.frontend.public_view();
    let state = AppState {
        client,
        token_salt,
        auth: auth_state,
        frontend: frontend_config,
    };

    let address = SocketAddr::from((config.address, config.port));
    info!("HTTP server binding on http://{}", address);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind HTTP listener on {}", address))?;

    let static_dir = config.static_dir.clone();

    let router = build_router(state, cors_layer, static_dir);

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server exited unexpectedly")
}

fn build_router(
    state: AppState,
    cors_layer: Option<CorsLayer>,
    static_dir: Option<PathBuf>,
) -> Router {
    let openapi = ApiDoc::openapi();
    let mut router = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/frontend/config", get(frontend_config))
        .route("/forward-auth", get(forward_auth))
        .merge(Scalar::with_url("/docs", openapi));

    let auth_state = state.auth.clone();
    let oauth_layer = auth_state
        .oauth_layer()
        .expect("OAuth2 resource server must be configured");

    let admin_router = Router::new()
        .route("/users/{sub}/tokens", get(list_tokens).post(create_token))
        .route("/users/{sub}/tokens/{id}", delete(delete_token))
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            require_admin,
        ))
        .layer(oauth_layer.clone())
        .layer(HelmetLayer::with_defaults());

    let user_router = Router::new()
        .route("/tokens", get(list_my_tokens).post(create_my_token))
        .route("/tokens/{id}", delete(delete_my_token))
        .layer(oauth_layer)
        .layer(HelmetLayer::with_defaults());

    router = router
        .nest("/api", admin_router)
        .nest("/api/me", user_router);

    if let Some(static_dir) = static_dir {
        if static_dir.is_dir() {
            info!(
                path = %static_dir.display(),
                "serving static frontend assets"
            );
            let index_file = static_dir.join("index.html");
            if !index_file.is_file() {
                warn!(
                    path = %index_file.display(),
                    "static frontend index file missing; SPA fallback may fail"
                );
            }
            router = router.fallback_service(
                ServeDir::new(static_dir).not_found_service(ServeFile::new(index_file)),
            );
        } else {
            warn!(
                path = %static_dir.display(),
                "static frontend directory not found; skipping static asset serving"
            );
        }
    }

    let router = router
        .layer(ConcurrencyLimitLayer::new(1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    match cors_layer {
        Some(layer) => router.layer(layer),
        None => router,
    }
}

fn cors_layer_from_config(config: &CorsConfig) -> anyhow::Result<Option<CorsLayer>> {
    if !config.enabled {
        return Ok(None);
    }

    let mut layer = CorsLayer::new()
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::list([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
        ]))
        .max_age(Duration::from_secs(60 * 60));

    if config.allow_origins.iter().any(|origin| origin == "*") {
        layer = layer.allow_origin(AllowOrigin::any());
    } else {
        let origins = config
            .allow_origins
            .iter()
            .map(|origin| {
                HeaderValue::from_str(origin)
                    .with_context(|| format!("invalid CORS origin {origin:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if origins.is_empty() {
            anyhow::bail!("CORS is enabled but no allowed origins were configured");
        }

        layer = layer.allow_origin(AllowOrigin::list(origins));
    }

    Ok(Some(layer))
}

async fn require_admin(
    State(auth_state): State<Arc<auth::AuthState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if !auth_state.is_enabled() {
        warn!("admin middleware invoked without oauth configuration");
        return Err(ApiError::internal("oauth not configured for admin routes"));
    }

    let claims_ref = match req.extensions().get::<auth::AuthClaims>() {
        Some(claims) => claims,
        None => {
            warn!("admin request missing oauth claims");
            return Err(ApiError::unauthorized("missing oauth claims"));
        }
    };

    let subject = claims_ref.sub.as_deref().unwrap_or("<unknown>");
    let is_admin = auth_state.user_has_admin_access(claims_ref);

    if !is_admin {
        warn!(subject = subject, "admin privileges required");
        return Err(ApiError::forbidden("admin privileges required"));
    }

    debug!(subject = subject, "admin access granted");
    Ok(next.run(req).await)
}

#[derive(OpenApi)]
#[openapi(
    paths(
        live,
        ready,
        frontend_config,
        list_tokens,
        create_token,
        delete_token,
        list_my_tokens,
        create_my_token,
        delete_my_token,
        forward_auth
    ),
    components(
        schemas(
            ApiErrorBody,
            HealthStatus,
            FrontendConfigResponse,
            TokenSummary,
            CreateTokenRequest,
            CreateTokenResponse
        )
    ),
    tags(
        (name = "health", description = "Health endpoints"),
        (name = "frontend", description = "Public metadata shared with the bundled frontend."),
        (name = "admin-token-management", description = "Administrator-only APIs for managing tokens on behalf of any subject. Requires OAuth2 bearer authentication with admin privileges."),
        (name = "self-token-management", description = "Self-service APIs for authenticated users to manage their own tokens via OAuth2 bearer authentication."),
        (name = "forward-auth", description = "Traefik forward auth compatibility")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "oauth2",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "OAuth2 / OpenID Connect access token validated against the configured issuer."
                                .to_owned(),
                        ))
                        .build(),
                ),
            );
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct ApiErrorBody {
    message: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: Cow<'static, str>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ApiErrorBody {
            message: self.message.to_string(),
        });
        (self.status, body).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("internal error: {:?}", err);
        ApiError::internal("internal server error")
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct HealthStatus {
    status: &'static str,
}

#[utoipa::path(
    get,
    path = "/health/live",
    tag = "health",
    responses((status = 200, body = HealthStatus))
)]
async fn live() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ok" })
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "health",
    responses(
        (status = 200, body = HealthStatus),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn ready(State(state): State<AppState>) -> Result<Json<HealthStatus>, ApiError> {
    state.client.ping::<String>(None).await.map_err(|err| {
        warn!("readiness ping failed: {:?}", err);
        ApiError::internal("valkey unavailable")
    })?;

    Ok(Json(HealthStatus { status: "ready" }))
}

#[derive(Debug, Serialize, ToSchema)]
struct FrontendConfigResponse {
    app_name: String,
    api_base_url: Option<String>,
    oidc_authority: Option<String>,
    oidc_client_id: Option<String>,
    oidc_redirect_uri: Option<String>,
    docs_html: Option<String>,
    api_docs_path: String,
}

#[utoipa::path(
    get,
    path = "/frontend/config",
    tag = "frontend",
    responses((status = 200, body = FrontendConfigResponse))
)]
async fn frontend_config(State(state): State<AppState>) -> Json<FrontendConfigResponse> {
    let cfg = &state.frontend;
    Json(FrontendConfigResponse {
        app_name: cfg.app_name.clone(),
        api_base_url: cfg.api_base_url.clone(),
        oidc_authority: cfg.oidc_authority.clone(),
        oidc_client_id: cfg.oidc_client_id.clone(),
        oidc_redirect_uri: cfg.oidc_redirect_uri.clone(),
        docs_html: cfg.docs_html.clone(),
        api_docs_path: cfg.api_docs_path.clone(),
    })
}

#[derive(Debug, Serialize, ToSchema)]
struct TokenSummary {
    id: String,
    description: Option<String>,
    created_at: String,
}

async fn list_tokens_for_subject(
    client: &fred::clients::Client,
    sub: &str,
) -> Result<Vec<TokenSummary>, ApiError> {
    let tokens = storage::list_user_tokens(client, sub)
        .await
        .map_err(ApiError::from)?;

    Ok(tokens
        .into_iter()
        .map(|token| TokenSummary {
            id: token.id,
            description: if token.description.is_empty() {
                None
            } else {
                Some(token.description)
            },
            created_at: token.created_at,
        })
        .collect())
}

fn subject_from_claims(state: &AppState, claims: &auth::AuthClaims) -> Result<String, ApiError> {
    match state.auth.subject_from_claims(claims) {
        Some(subject) => Ok(subject),
        None => {
            warn!("oauth claims missing subject");
            Err(ApiError::unauthorized("subject claim missing"))
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/users/{sub}/tokens",
    tag = "admin-token-management",
    security(
        ("oauth2" = [])
    ),
    params(
        ("sub" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, body = [TokenSummary]),
        (status = 401, body = ApiErrorBody),
        (status = 403, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn list_tokens(
    State(state): State<AppState>,
    Path(sub): Path<String>,
) -> Result<Json<Vec<TokenSummary>>, ApiError> {
    let subject = sub.trim().to_string();
    let summaries = list_tokens_for_subject(&state.client, &subject).await?;
    let token_count = summaries.len();
    info!(
        actor = "admin",
        subject = subject.as_str(),
        token_count = token_count,
        "listed tokens for subject"
    );
    Ok(Json(summaries))
}

#[utoipa::path(
    get,
    path = "/api/me/tokens",
    tag = "self-token-management",
    security(
        ("oauth2" = [])
    ),
    responses(
        (status = 200, body = [TokenSummary]),
        (status = 401, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn list_my_tokens(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::AuthClaims>,
) -> Result<Json<Vec<TokenSummary>>, ApiError> {
    let subject = subject_from_claims(&state, &claims)?;
    let summaries = list_tokens_for_subject(&state.client, &subject).await?;
    let token_count = summaries.len();
    info!(
        actor = "self",
        subject = subject.as_str(),
        token_count = token_count,
        "listed own tokens"
    );
    Ok(Json(summaries))
}

const MAX_DESCRIPTION_LENGTH: usize = 256;

async fn create_token_for_subject(
    state: &AppState,
    subject: &str,
    description: Option<String>,
) -> Result<CreateTokenResponse, ApiError> {
    let subject = subject.trim();
    if subject.is_empty() {
        warn!("attempted to create token with empty subject");
        return Err(ApiError::bad_request("subject must not be empty"));
    }

    const TOKEN_LENGTH: usize = 32; // 256 bits
    let raw_token = generate_token(TOKEN_LENGTH);
    let token_hash = hash_token(&raw_token, &state.token_salt);

    let description = description
        .map(|desc| desc.trim().to_string())
        .filter(|desc| !desc.is_empty())
        .unwrap_or_default();

    if description.len() > MAX_DESCRIPTION_LENGTH {
        warn!(
            subject = subject,
            description_length = description.len(),
            "token description exceeds limit"
        );
        return Err(ApiError::bad_request(format!(
            "description exceeds {} characters",
            MAX_DESCRIPTION_LENGTH
        )));
    }

    storage::create_api_token(&state.client, subject, &token_hash, &description)
        .await
        .map_err(ApiError::from)?;

    let created = storage::read_api_token(&state.client, &token_hash)
        .await
        .map_err(ApiError::from)?
        .context("stored token missing after creation")
        .map_err(ApiError::from)?;

    let storage::ApiToken {
        sub: stored_sub,
        description: stored_description,
        created_at,
    } = created;

    Ok(CreateTokenResponse {
        token: raw_token,
        id: token_hash,
        sub: stored_sub,
        description: if stored_description.is_empty() {
            None
        } else {
            Some(stored_description)
        },
        created_at,
    })
}

async fn delete_token_for_subject(
    client: &fred::clients::Client,
    subject: &str,
    token_id: &str,
) -> Result<StatusCode, ApiError> {
    let owner = storage::read_api_token_sub(client, token_id)
        .await
        .map_err(ApiError::from)?;

    match owner {
        Some(owner_sub) if owner_sub == subject => {
            let deleted = storage::delete_api_token(client, token_id)
                .await
                .map_err(ApiError::from)?;
            if deleted {
                Ok(StatusCode::NO_CONTENT)
            } else {
                debug!(
                    subject = subject,
                    token_id = token_id,
                    "token was missing during delete despite matching ownership"
                );
                Err(ApiError::not_found("token not found"))
            }
        }
        Some(owner_sub) => {
            debug!(
                requested_subject = subject,
                owner = owner_sub.as_str(),
                token_id = token_id,
                "token delete rejected for mismatched owner"
            );
            Err(ApiError::not_found("token not found"))
        }
        None => {
            debug!(
                subject = subject,
                token_id = token_id,
                "token delete rejected because token does not exist"
            );
            Err(ApiError::not_found("token not found"))
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateTokenRequest {
    /// Optional description to help identify the token (max 256 characters).
    #[schema(max_length = 256)]
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct CreateTokenResponse {
    token: String,
    id: String,
    sub: String,
    description: Option<String>,
    created_at: String,
}

#[utoipa::path(
    post,
    path = "/api/users/{sub}/tokens",
    tag = "admin-token-management",
    security(
        ("oauth2" = [])
    ),
    params(
        ("sub" = String, Path, description = "Subject identifier")
    ),
    request_body(
        content = CreateTokenRequest,
        description = "Optional description"
    ),
    responses(
        (status = 201, body = CreateTokenResponse),
        (status = 401, body = ApiErrorBody),
        (status = 403, body = ApiErrorBody),
        (status = 400, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn create_token(
    State(state): State<AppState>,
    Path(raw_sub): Path<String>,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    let response = create_token_for_subject(&state, &raw_sub, payload.description).await?;
    let subject_ref = response.sub.as_str();
    let token_id_ref = response.id.as_str();
    info!(
        actor = "admin",
        subject = subject_ref,
        token_id = token_id_ref,
        "created API token"
    );
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    post,
    path = "/api/me/tokens",
    tag = "self-token-management",
    security(
        ("oauth2" = [])
    ),
    request_body(
        content = CreateTokenRequest,
        description = "Optional description"
    ),
    responses(
        (status = 201, body = CreateTokenResponse),
        (status = 401, body = ApiErrorBody),
        (status = 400, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn create_my_token(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::AuthClaims>,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), ApiError> {
    let subject = subject_from_claims(&state, &claims)?;
    let response = create_token_for_subject(&state, &subject, payload.description).await?;
    let token_id_ref = response.id.as_str();
    info!(
        actor = "self",
        subject = subject.as_str(),
        token_id = token_id_ref,
        "created API token"
    );
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    delete,
    path = "/api/users/{sub}/tokens/{id}",
    tag = "admin-token-management",
    security(
        ("oauth2" = [])
    ),
    params(
        ("sub" = String, Path, description = "Subject identifier"),
        ("id" = String, Path, description = "Token identifier (hashed)")
    ),
    responses(
        (status = 204),
        (status = 401, body = ApiErrorBody),
        (status = 403, body = ApiErrorBody),
        (status = 404, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn delete_token(
    State(state): State<AppState>,
    Path((sub, token_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let subject = sub.trim().to_string();
    let token_id = token_id.trim().to_string();
    match delete_token_for_subject(&state.client, &subject, &token_id).await {
        Ok(status) => {
            info!(
                actor = "admin",
                subject = subject.as_str(),
                token_id = token_id.as_str(),
                "deleted API token"
            );
            Ok(status)
        }
        Err(err) => {
            let status_code = err.status;
            warn!(
                actor = "admin",
                subject = subject.as_str(),
                token_id = token_id.as_str(),
                status = %status_code,
                "failed to delete API token"
            );
            Err(err)
        }
    }
}

#[utoipa::path(
    delete,
    path = "/api/me/tokens/{id}",
    tag = "self-token-management",
    security(
        ("oauth2" = [])
    ),
    params(
        ("id" = String, Path, description = "Token identifier (hashed)")
    ),
    responses(
        (status = 204),
        (status = 401, body = ApiErrorBody),
        (status = 404, body = ApiErrorBody),
        (status = 500, body = ApiErrorBody)
    )
)]
async fn delete_my_token(
    State(state): State<AppState>,
    Extension(claims): Extension<auth::AuthClaims>,
    Path(token_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let subject = subject_from_claims(&state, &claims)?;
    let token_id = token_id.trim().to_string();
    match delete_token_for_subject(&state.client, &subject, &token_id).await {
        Ok(status) => {
            info!(
                actor = "self",
                subject = subject.as_str(),
                token_id = token_id.as_str(),
                "deleted API token"
            );
            Ok(status)
        }
        Err(err) => {
            let status_code = err.status;
            warn!(
                actor = "self",
                subject = subject.as_str(),
                token_id = token_id.as_str(),
                status = %status_code,
                "failed to delete API token"
            );
            Err(err)
        }
    }
}

#[utoipa::path(
    get,
    path = "/forward-auth",
    tag = "forward-auth",
    responses(
        (status = 204, description = "Token accepted"),
        (status = 401, body = ApiErrorBody)
    )
)]
async fn forward_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = match extract_token(&headers) {
        Some(token) => token,
        None => {
            warn!("forward-auth request missing token");
            return Err(ApiError::unauthorized("missing token"));
        }
    };

    let token_hash = hash_token(&token, &state.token_salt);
    let sub = match storage::read_api_token_sub(&state.client, &token_hash)
        .await
        .map_err(ApiError::from)?
    {
        Some(subject) => subject,
        None => {
            warn!(
                token_id = token_hash.as_str(),
                "forward-auth rejected unknown token"
            );
            return Err(ApiError::unauthorized("invalid token"));
        }
    };

    info!(
        subject = sub.as_str(),
        token_id = token_hash.as_str(),
        "forward-auth accepted token"
    );

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("X-Authenticated-User", sub.as_str())
        .header("X-Authenticated-Token-Id", token_hash.as_str())
        .body(Body::empty())
        .map_err(|_| ApiError::internal("failed to build response"))
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_authorization)
    {
        return Some(token);
    }

    None
}

fn parse_authorization(raw: &str) -> Option<String> {
    let header = raw.trim();
    if header.is_empty() {
        return None;
    }

    let split_idx = header
        .char_indices()
        .find_map(|(idx, ch)| ch.is_ascii_whitespace().then_some(idx))?;
    let scheme = header[..split_idx].trim();
    let value = header[split_idx..].trim();

    if scheme.is_empty() || value.is_empty() {
        return None;
    }

    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some(value.to_string());
    }

    if scheme.eq_ignore_ascii_case("Basic") {
        return parse_basic_authorization(value);
    }

    None
}

fn parse_basic_authorization(value: &str) -> Option<String> {
    let decoded = BASE64_STANDARD.decode(value).ok()?;
    if decoded.is_empty() {
        return None;
    }

    let decoded = String::from_utf8(decoded).ok()?;
    let decoded = decoded.trim();
    if decoded.is_empty() {
        return None;
    }

    if let Some((user, pass)) = decoded.split_once(':') {
        let pass = pass.trim();
        if !pass.is_empty() {
            return Some(pass.to_string());
        }

        let user = user.trim();
        if !user.is_empty() {
            return Some(user.to_string());
        }

        return None;
    }

    Some(decoded.to_string())
}

fn hash_token(token: &str, salt: &[u8; 32]) -> String {
    blake3::keyed_hash(salt, token.as_bytes())
        .to_hex()
        .to_string()
}

fn generate_token(length: usize) -> String {
    const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if length == 0 {
        return String::new();
    }

    let alphabet_len = ALPHANUMERIC.len() as u32;
    let max_multiple = ((u32::from(u8::MAX) + 1) / alphabet_len) * alphabet_len; // largest multiple <= 256
    let mut token = String::with_capacity(length);
    let mut bytes = vec![0u8; length];
    let mut rng = SysRng;

    while token.len() < length {
        rng.try_fill_bytes(bytes.as_mut_slice())
            .expect("operating system RNG unavailable");
        for &byte in &bytes {
            let value = u32::from(byte);
            if value < max_multiple {
                let idx = (value % alphabet_len) as usize;
                token.push(ALPHANUMERIC[idx] as char);
                if token.len() == length {
                    break;
                }
            }
        }
    }

    token
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::extract::{Extension, State};
    use axum::http::{HeaderValue, header};
    use fred::interfaces::KeysInterface;
    use fred::prelude::{Builder, Config};
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    const TEST_TOKEN_SALT: [u8; 32] = [0u8; 32];

    async fn setup_test_client() -> fred::clients::Client {
        let config = Config::from_url("valkey://localhost:6379").expect("invalid valkey url");
        let client = Builder::from_config(config)
            .build()
            .expect("failed to build valkey client");
        client.connect();
        client
            .wait_for_connect()
            .await
            .expect("failed to connect to valkey");
        client
    }

    fn test_suffix() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let thread_id = std::thread::current().id();

        format!("{}_{}_{:?}", nanos, counter, thread_id)
    }

    async fn cleanup_token(client: &fred::clients::Client, token_hash: &str, user_sub: &str) {
        let _ = storage::delete_api_token(client, token_hash).await;
        let _: Result<(), _> = client.del(format!("auth:user_tokens:{}", user_sub)).await;
    }

    fn test_frontend_config() -> FrontendPublicConfig {
        FrontendPublicConfig {
            api_base_url: Some("http://localhost:8080".to_string()),
            app_name: "Valkey Token Manager".to_string(),
            oidc_authority: Some("https://example.test/auth".to_string()),
            oidc_client_id: Some("test-client-id".to_string()),
            oidc_redirect_uri: None,
            docs_html: Some("<p>Example documentation</p>".to_string()),
            api_docs_path: "/docs".to_string(),
        }
    }

    fn build_state(client: fred::clients::Client) -> AppState {
        AppState {
            client,
            token_salt: TEST_TOKEN_SALT,
            auth: Arc::new(auth::AuthState::disabled_for_tests()),
            frontend: test_frontend_config(),
        }
    }

    async fn build_state_with_oauth(client: fred::clients::Client) -> AppState {
        AppState {
            client,
            token_salt: TEST_TOKEN_SALT,
            auth: Arc::new(auth::AuthState::for_tests_with_layer().await),
            frontend: test_frontend_config(),
        }
    }

    #[tokio::test]
    #[serial]
    async fn build_router_registers_routes_without_panic() {
        let client = setup_test_client().await;
        let state = build_state_with_oauth(client.clone()).await;

        // If the route definitions use an invalid syntax (e.g. old `:param` segments),
        // axum panics when constructing the router. This ensures we notice regressions.
        let _ = build_router(state, None, None);
    }

    #[tokio::test]
    async fn frontend_config_returns_frontend_metadata() {
        let client = setup_test_client().await;
        let state = build_state(client);
        let response = frontend_config(State(state)).await;
        let Json(body) = response;
        assert_eq!(body.app_name, "Valkey Token Manager");
        assert_eq!(body.api_base_url.as_deref(), Some("http://localhost:8080"));
        assert_eq!(
            body.oidc_authority.as_deref(),
            Some("https://example.test/auth")
        );
        assert_eq!(body.oidc_client_id.as_deref(), Some("test-client-id"));
        assert_eq!(body.api_docs_path, "/docs");
        assert!(body.docs_html.as_deref().is_some());
    }

    #[tokio::test]
    async fn api_error_into_response_sets_status_and_body() {
        let error = ApiError::bad_request("invalid input");
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = to_bytes(response.into_body(), 128)
            .await
            .expect("body bytes");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert_eq!(body, r#"{"message":"invalid input"}"#);
    }

    #[test]
    fn hash_token_is_deterministic() {
        let first = hash_token("example-token", &TEST_TOKEN_SALT);
        let second = hash_token("example-token", &TEST_TOKEN_SALT);
        assert_eq!(first, second);
        // Hash with keyed blake3 using an all-zeros salt
        assert_eq!(
            first,
            "2d00e35e3e78f77fa4eb0454a48fb41e45963e0f9b5a335be231a2b582790189"
        );
    }

    #[test]
    fn generate_token_uses_alphanumeric_charset() {
        let token = generate_token(64);
        assert_eq!(token.len(), 64);
        assert!(
            token.chars().all(|c| c.is_ascii_alphanumeric()),
            "token contains unexpected characters"
        );
    }

    #[test]
    fn extract_token_reads_from_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token "),
        );
        let token = extract_token(&headers);
        assert_eq!(token.as_deref(), Some("header-token"));
    }

    #[test]
    fn extract_token_returns_none_when_unavailable() {
        let headers = HeaderMap::new();
        assert!(extract_token(&headers).is_none());
    }

    #[test]
    fn extract_token_supports_case_insensitive_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer MixedCaseToken"),
        );

        let token = extract_token(&headers);
        assert_eq!(token.as_deref(), Some("MixedCaseToken"));
    }

    #[test]
    fn extract_token_supports_basic_auth() {
        let mut headers = HeaderMap::new();
        let encoded = BASE64_STANDARD.encode("token-user:my-secret-token");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );

        let token = extract_token(&headers);
        assert_eq!(token.as_deref(), Some("my-secret-token"));

        let encoded = BASE64_STANDARD.encode("token-without-password:");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );

        let token = extract_token(&headers);
        assert_eq!(token.as_deref(), Some("token-without-password"));
    }

    #[tokio::test]
    #[serial]
    async fn live_endpoint_returns_ok() {
        let response = live().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[serial]
    async fn ready_returns_ready_when_ping_succeeds() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());

        let Json(status) = ready(State(state)).await.expect("ready ok");
        assert_eq!(status.status, "ready");
    }

    #[tokio::test]
    #[serial]
    async fn list_tokens_returns_stored_tokens() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());

        let token_one = "token-one";
        let token_two = "token-two";
        let hash_one = hash_token(token_one, &TEST_TOKEN_SALT);
        let hash_two = hash_token(token_two, &TEST_TOKEN_SALT);

        storage::create_api_token(&client, &sub, &hash_one, "first")
            .await
            .expect("store first token");
        storage::create_api_token(&client, &sub, &hash_two, "")
            .await
            .expect("store second token");

        let Json(tokens) = list_tokens(State(state), Path(sub.clone()))
            .await
            .expect("list tokens");

        assert_eq!(tokens.len(), 2);
        assert!(
            tokens
                .iter()
                .any(|t| t.id == hash_one && t.description == Some("first".into()))
        );
        assert!(
            tokens
                .iter()
                .any(|t| t.id == hash_two && t.description.is_none())
        );

        cleanup_token(&client, &hash_one, &sub).await;
        cleanup_token(&client, &hash_two, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn list_my_tokens_returns_authenticated_token_set() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());

        let hash_one = hash_token("token-one", &TEST_TOKEN_SALT);
        let hash_two = hash_token("token-two", &TEST_TOKEN_SALT);

        storage::create_api_token(&client, &sub, &hash_one, "")
            .await
            .expect("store token");
        storage::create_api_token(&client, &sub, &hash_two, "device")
            .await
            .expect("store token");

        let claims = Extension(auth::AuthClaims {
            iss: None,
            sub: Some(sub.clone()),
            aud: Vec::new(),
            jti: None,
            extra: HashMap::new(),
        });

        let Json(tokens) = list_my_tokens(State(state.clone()), claims)
            .await
            .expect("list tokens");
        assert_eq!(tokens.len(), 2);

        cleanup_token(&client, &hash_one, &sub).await;
        cleanup_token(&client, &hash_two, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn list_my_tokens_rejects_missing_subject_claim() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());

        let claims = Extension(auth::AuthClaims {
            iss: None,
            sub: None,
            aud: Vec::new(),
            jti: None,
            extra: HashMap::new(),
        });

        let err = list_my_tokens(State(state), claims)
            .await
            .expect_err("subject should be required");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[serial]
    async fn create_token_stores_and_returns_token() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());

        let payload = CreateTokenRequest {
            description: Some("api access".into()),
        };

        let (status, Json(response)) =
            create_token(State(state.clone()), Path(sub.clone()), Json(payload))
                .await
                .expect("token created");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response.sub, sub);
        assert_eq!(response.description.as_deref(), Some("api access"));
        assert_eq!(response.token.len(), 32); // 256 bits
        assert_eq!(hash_token(&response.token, &TEST_TOKEN_SALT), response.id);

        let stored = storage::read_api_token(&client, &response.id)
            .await
            .expect("read token")
            .expect("token present");
        assert_eq!(stored.sub, sub);

        cleanup_token(&client, &response.id, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn create_my_token_uses_subject_from_claims() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());

        let claims = Extension(auth::AuthClaims {
            iss: None,
            sub: Some(sub.clone()),
            aud: Vec::new(),
            jti: None,
            extra: HashMap::new(),
        });

        let payload = CreateTokenRequest {
            description: Some("self-service".into()),
        };

        let (status, Json(response)) = create_my_token(State(state.clone()), claims, Json(payload))
            .await
            .expect("token created");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response.sub, sub);
        assert_eq!(response.description.as_deref(), Some("self-service"));

        let stored = storage::read_api_token(&client, &response.id)
            .await
            .expect("read token")
            .expect("token present");
        assert_eq!(stored.sub, response.sub);

        cleanup_token(&client, &response.id, &stored.sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn create_token_rejects_empty_subject() {
        let client = setup_test_client().await;
        let state = build_state(client);

        let payload = CreateTokenRequest { description: None };

        let err = create_token(State(state), Path(String::new()), Json(payload))
            .await
            .expect_err("subject validation should fail");

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial]
    async fn create_token_rejects_overlong_description() {
        let client = setup_test_client().await;
        let state = build_state(client);
        let sub = format!("user_{}", test_suffix());
        let payload = CreateTokenRequest {
            description: Some("x".repeat(MAX_DESCRIPTION_LENGTH + 1)),
        };

        let err = create_token(State(state), Path(sub), Json(payload))
            .await
            .expect_err("description validation should fail");

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial]
    async fn delete_token_removes_existing_token() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());
        let token = "delete-me";
        let hash = hash_token(token, &TEST_TOKEN_SALT);

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let status = delete_token(State(state), Path((sub.clone(), hash.clone())))
            .await
            .expect("delete ok");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored = storage::read_api_token(&client, &hash)
            .await
            .expect("read token");
        assert!(stored.is_none());

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn delete_my_token_removes_owned_token() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());
        let token = "self-delete";
        let hash = hash_token(token, &TEST_TOKEN_SALT);

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let claims = Extension(auth::AuthClaims {
            iss: None,
            sub: Some(sub.clone()),
            aud: Vec::new(),
            jti: None,
            extra: HashMap::new(),
        });

        let status = delete_my_token(State(state.clone()), claims, Path(hash.clone()))
            .await
            .expect("delete ok");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored = storage::read_api_token(&client, &hash)
            .await
            .expect("read token");
        assert!(stored.is_none());

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn delete_token_fails_for_wrong_owner() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let real_sub = format!("user_{}", test_suffix());
        let wrong_sub = format!("user_{}", test_suffix());
        let token = "wrong-owner";
        let hash = hash_token(token, &TEST_TOKEN_SALT);

        storage::create_api_token(&client, &real_sub, &hash, "")
            .await
            .expect("store token");

        let err = delete_token(State(state), Path((wrong_sub.clone(), hash.clone())))
            .await
            .expect_err("should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        cleanup_token(&client, &hash, &real_sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn delete_my_token_rejects_foreign_token() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let real_sub = format!("user_{}", test_suffix());
        let attacker_sub = format!("user_{}", test_suffix());
        let hash = hash_token("shared-token", &TEST_TOKEN_SALT);

        storage::create_api_token(&client, &real_sub, &hash, "")
            .await
            .expect("store token");

        let claims = Extension(auth::AuthClaims {
            iss: None,
            sub: Some(attacker_sub.clone()),
            aud: Vec::new(),
            jti: None,
            extra: HashMap::new(),
        });

        let err = delete_my_token(State(state), claims, Path(hash.clone()))
            .await
            .expect_err("should reject");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        cleanup_token(&client, &hash, &real_sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_accepts_bearer_token() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());
        let token = "forward-header";
        let hash = hash_token(token, &TEST_TOKEN_SALT);

        // Clean up any leftover data from previous failed test runs
        let _ = storage::delete_api_token(&client, &hash).await;

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {}", token)).unwrap(),
        );
        let response = forward_auth(State(state), headers).await.expect("auth ok");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_accepts_basic_token() {
        let client = setup_test_client().await;
        let state = build_state(client.clone());
        let sub = format!("user_{}", test_suffix());
        let token = "forward-basic";
        let hash = hash_token(token, &TEST_TOKEN_SALT);

        let _ = storage::delete_api_token(&client, &hash).await;

        storage::create_api_token(&client, &sub, &hash, "")
            .await
            .expect("store token");

        let mut headers = HeaderMap::new();
        let encoded = BASE64_STANDARD.encode(format!("ignored:{}", token));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap(),
        );

        let response = forward_auth(State(state), headers).await.expect("auth ok");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        cleanup_token(&client, &hash, &sub).await;
    }

    #[tokio::test]
    #[serial]
    async fn forward_auth_rejects_missing_token() {
        let client = setup_test_client().await;
        let state = build_state(client);
        let headers = HeaderMap::new();

        let err = forward_auth(State(state), headers)
            .await
            .expect_err("should reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
}
