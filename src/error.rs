use axum::{http::StatusCode, response::IntoResponse, Json};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Internal server error")]
    InternalServerGeneric,

    #[error("Auth error -> WrongCredentials")]
    AuthWrongCredentials,
    #[error("Auth error -> MissingCredentials")]
    AuthMissingCredentials,
    #[error("Auth error -> InvalidToken")]
    AuthInvalidToken,
    #[error("Auth error -> Unauthorized")]
    AuthUnauthorized,
    #[error("Auth error -> UsernameExists")]
    AuthUsernameExists,

    #[error(transparent)]
    ValidateFailed(#[from] validator::ValidationErrors),

    #[error("Argon2 error -> {}", .0)]
    Argon2(#[from] argon2::Error),

    #[error("JWT error -> {}", .0)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Db error -> Sqlx: {}", .0)]
    DbSqlx(#[from] sqlx::Error),

    #[error("Db error -> Argon2 parse error")]
    DbArgon2HashParse(#[from] argon2::password_hash::Error),
}

// impl From<sqlx::error::Error> for AppError {
//     fn from(e: sqlx::error::Error) -> Self {
//         AppError::Db(DbError::Generic)
//     }
// }

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status_code, message) = match self {
            AppError::InternalServerGeneric => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
            AppError::AuthWrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong Credentials"),
            AppError::AuthMissingCredentials => {
                (StatusCode::UNAUTHORIZED, "Missing email or password")
            }
            AppError::AuthInvalidToken => (StatusCode::BAD_REQUEST, "No valid token provided"),
            AppError::AuthUnauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::AuthUsernameExists => (StatusCode::BAD_REQUEST, "Username exists"),
            
            AppError::ValidateFailed(e) => {
                tracing::debug!("validate error: {}", e);
                (StatusCode::BAD_REQUEST, "Bad Request")
            }

            AppError::Argon2(e) => {
                tracing::debug!("argon2 error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
            AppError::Jwt(e) => {
                tracing::debug!("jwt error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
            AppError::DbSqlx(e) => {
                tracing::debug!("sqlx error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
            AppError::DbArgon2HashParse(e) => {
                tracing::debug!("argon2 error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }
        };

        let body = Json(serde_json::json!({
            "status": "error",
            "message": message,
        }));

        (status_code, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_type() {
        println!("error type: {}", AppError::DbSqlx(sqlx::Error::PoolClosed));
    }
}
