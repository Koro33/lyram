use crate::{error::AppError, utils::jwt_dec, AppState};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};

use axum_extra::{
    extract::cookie::CookieJar,
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};
use std::sync::Arc;

pub async fn auth_verify(
    cookie_jar: CookieJar,
    State(_state): State<Arc<AppState>>,
    header_auth: Option<TypedHeader<Authorization<Bearer>>>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let token = cookie_jar
        .get("jwt_token")
        .map(|cookie| {
            tracing::trace!("Token from cookie: {}", cookie.value());
            cookie.value().to_owned()
        })
        .or_else(|| {
            header_auth.map(|auth| {
                tracing::trace!("Token from header authorization: {}", auth.token());
                auth.token().to_owned()
            })
        })
        .ok_or_else(|| AppError::AuthInvalidToken)?;

    let claims = jwt_dec(token.as_ref()).map_err(|e| {
        tracing::error!("JWT error: {}", e);
        AppError::AuthInvalidToken
    })?;

    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
