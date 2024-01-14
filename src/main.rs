use lyram::{
    config,
    db::{self},
    error::AppError,
    init_tracing, middleware as mw, schema,
    utils::{self, Argon2Pwd, JwtClaims},
    AppState,
};

use axum::{
    body::Body,
    extract::{Json, Path, Query, State},
    http::{header, HeaderMap, Method, Request, Response, StatusCode},
    middleware::from_fn_with_state,
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};

use axum_extra::{
    body::AsyncReadBody,
    extract::cookie::{Cookie, CookieJar, SameSite},
    headers::HeaderValue,
};

use axum_macros::debug_handler;
use bytes::Bytes;

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use validator::Validate;

use tokio::{io::BufReader, signal};
use tower::ServiceBuilder;
use tower_http::{
    classify::ServerErrorsFailureClass, compression::CompressionLayer, cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::{instrument, Span};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // initialize tracing log
    init_tracing();

    // add admin user when not exists
    if !db::user::username_exists("admin", db::get_db().await).await? {
        let user = db::model::DbUser {
            username: "admin".to_string(),
            email: "admin@localhost".to_string(),
            is_admin: true,
            hashed_pwd: config::admin_pwd().as_str().to_argon2_hashed_pwd()?,
            ..Default::default()
        };
        db::user::create(&user, db::get_db().await).await?;
        tracing::info!("No admin user found, created admin user: {}", user.username);
    }

    let shared_state = Arc::new(AppState {
        pool: db::get_db().await.clone(),
    });

    let tracing_layer = ServiceBuilder::new().layer(
        TraceLayer::new_for_http()
            .make_span_with(|_request: &Request<Body>| tracing::debug_span!("http-request"))
            .on_request(|request: &Request<Body>, _span: &Span| {
                tracing::debug!("started {} {}", request.method(), request.uri().path())
            })
            .on_response(
                |_response: &Response<Body>, latency: Duration, _span: &Span| {
                    tracing::debug!("response generated in {:?}", latency)
                },
            )
            .on_body_chunk(|chunk: &Bytes, _latency: Duration, _span: &Span| {
                tracing::debug!("sending {} bytes", chunk.len())
            })
            .on_eos(
                |_trailers: Option<&HeaderMap>, stream_duration: Duration, _span: &Span| {
                    tracing::debug!("stream closed after {:?}", stream_duration)
                },
            )
            .on_failure(
                |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                    tracing::debug!("something went wrong")
                },
            ),
    );

    let cors_layer = CorsLayer::new()
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    let compression_layer = CompressionLayer::new();

    let routes_need_auth = Router::new()
        .route("/test-auth", get(test_auth_handler))
        .route("/logout", post(logout_handler))
        .route_layer(from_fn_with_state(shared_state.clone(), mw::auth_verify));

    let app = Router::new()
        .route("/", get(root))
        .route("/login", post(login_handler))
        .route("/signup", post(signup_handler))
        .route("/version", get(version_handler))
        .route("/stream", get(stream))
        .merge(routes_need_auth)
        .layer(tracing_layer)
        .layer(cors_layer)
        .layer(compression_layer)
        .with_state(shared_state);

    let addr = "0.0.0.0:3000";
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::warn!("Received termination signal shutting down");
}

// basic handler that responds with a static string
#[debug_handler]
#[instrument]
async fn root() -> impl IntoResponse {
    "Hello, World!"
}

#[debug_handler]
#[instrument]
async fn version_handler() -> impl IntoResponse {
    "0.1.0"
}

#[debug_handler]
#[instrument]
async fn signup_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<schema::Signup>,
) -> Result<impl IntoResponse, AppError> {
    body.validate()?;

    if db::user::username_exists(&body.username, &state.pool).await? {
        return Err(AppError::AuthUsernameExists);
    }

    let hashed_pwd = body.password.as_str().to_argon2_hashed_pwd()?;

    let user = db::model::DbUser {
        username: body.username,
        email: body.email,
        hashed_pwd,
        ..Default::default()
    };

    db::user::create(&user, &state.pool).await?;

    let response = Response::new(serde_json::json!({"status": "success"}).to_string());
    Ok(response)
}

#[debug_handler]
#[instrument]
async fn login_handler(
    _cookie_jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Json(body): Json<schema::Login>,
) -> Result<impl IntoResponse, AppError> {
    body.validate()?;

    let db_user = db::user::get_by_name(&body.username, &state.pool)
        .await?
        .ok_or_else(|| AppError::AuthWrongCredentials)?;

    db_user
        .hashed_pwd
        .as_str()
        .argon2_verify_with_pwd(body.password.as_str())
        .map_err(|e| {
            tracing::error!("Argon2 error: {}", e);
            AppError::AuthWrongCredentials
        })?;

    let claims = JwtClaims {
        sub: db_user.id.to_string(),
        name: body.username,
        ..Default::default()
    };

    tracing::trace!("Claims: {:?}", claims);

    let token = utils::jwt_enc(&claims)?;

    let cookie = Cookie::build(("jwt_token", token.to_owned()))
        .path("/")
        .max_age(time::Duration::seconds(config::jwt_expire()))
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response =
        Response::new(serde_json::json!({"status": "success", "jwt_token": token}).to_string());

    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie
            .to_string()
            .parse()
            .map_err(|_| AppError::InternalServerGeneric)?,
    );

    Ok(response)
}

#[debug_handler]
#[instrument]
async fn logout_handler(
    cookie_jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, AppError> {
    let cookie = Cookie::build(("jwt_token", "".to_owned()))
        .path("/")
        .expires(time::OffsetDateTime::UNIX_EPOCH)
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response = Response::new(
        serde_json::json!({"status": "success", "msg": format!("`{}` logged out", claims.name), })
            .to_string(),
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie
            .to_string()
            .parse()
            .map_err(|_| AppError::InternalServerGeneric)?,
    );
    Ok(response)
}

#[debug_handler]
#[instrument]
async fn test_auth_handler(
    cookie_jar: CookieJar,
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, AppError> {
    let body = Json(json!({"status": "success", "message": claims.to_string()}));
    let response = (StatusCode::OK, body).into_response();
    Ok(response)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct StreamParams {
    pub id: Uuid,
}

#[debug_handler]
async fn stream(
    Query(params): Query<StreamParams>,
    State(state): State<Arc<AppState>>,
    // Extension(claims): Extension<Claims>,
) -> Result<impl IntoResponse, AppError> {
    // TODO: query from database
    let db_result = Some("./tests/music/牛尾憲輔 - Trace Of Twilight.mp3".to_string());

    // TODO: find out the different between stream and AsyncReadBody
    // USE stream

    // match db_result {
    //     Some(path) => {
    //         let file = tokio::fs::File::open(path)
    //             .await
    //             .map_err(|_| AppError::InternalServerGeneric)?;

    //         let length = &file
    //             .metadata()
    //             .await
    //             .map_err(|_| AppError::InternalServerGeneric)?
    //             .len();

    //         let reader = BufReader::new(file);

    //         let stream = ReaderStream::new(reader);
    //         let body = StreamBody::new(stream);

    //         let headers = [
    //             (header::CONTENT_LENGTH, length.to_string()),
    //             (header::CONTENT_TYPE, "audio/mpeg".to_string()),
    //         ];

    //         Ok((headers, body).into_response())
    //     }
    //     None => Ok((StatusCode::NOT_FOUND, Json(json!({"status": "not found"}))).into_response()),
    // }

    // use AsyncReadBody
    match db_result {
        Some(path) => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|_| AppError::InternalServerGeneric)?;

            let length = &file
                .metadata()
                .await
                .map_err(|_| AppError::InternalServerGeneric)?
                .len();

            let reader = BufReader::new(file);

            let headers = [
                (header::CONTENT_LENGTH, length.to_string()),
                (header::CONTENT_TYPE, "audio/mpeg".to_string()),
            ];
            // CONTENT_TYPE (audio)
            // https://www.iana.org/assignments/media-types/media-types.xhtml#audio

            let body = AsyncReadBody::new(reader);

            Ok((headers, body).into_response())
        }
        None => Ok((StatusCode::NOT_FOUND, Json(json!({"status": "not found"}))).into_response()),
    }
}

#[cfg(test)]
mod tests {
    use lyram::db;

    #[tokio::test]
    async fn migration() {
        let pool = db::get_db().await;
        sqlx::migrate!("./migrations").run(pool).await.unwrap();
    }
}
