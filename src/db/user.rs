use crate::db::model;
use crate::error::AppError;

use chrono::prelude::*;
// use model::{AlbumDb, ArtistDb, DbUser, Song};
use model::DbUser;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn get_by_name(username: &str, pool: &PgPool) -> Result<Option<DbUser>, AppError> {
    let user = sqlx::query_as::<_, DbUser>(
        "
        SELECT * FROM users
        WHERE username = $1
        ",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub async fn get_by_email(email: &str, pool: &PgPool) -> Result<Vec<DbUser>, AppError> {
    let user = sqlx::query_as::<_, DbUser>(
        "
        SELECT * FROM users
        WHERE email = $1
        ",
    )
    .bind(email)
    .fetch_all(pool)
    .await?;
    Ok(user)
}

pub async fn username_exists(username: &str, pool: &PgPool) -> Result<bool, AppError> {
    let user = get_by_name(username, pool).await?;
    match user {
        Some(user) => {
            tracing::trace!("username `{}` exists with id: `{}`", user.username, user.id);
            Ok(true)
        }
        None => Ok(false),
    }
}

pub async fn create(user: &DbUser, pool: &PgPool) -> Result<(), AppError> {
    let user = user.clone();

    sqlx::query(
        "
        INSERT INTO users (id, username, email, hashed_pwd, is_admin, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, DEFAULT, DEFAULT)
        ",
    )
    .bind(user.id)
    .bind(user.username)
    .bind(user.email)
    .bind(user.hashed_pwd)
    .bind(user.is_admin)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update(user: &DbUser, pool: &PgPool) -> Result<(), AppError> {
    let user = user.clone();
    sqlx::query(
        "
        UPDATE users
        SET email = $1, hashed_pwd = $2, is_admin = $3, updated_at = $4
        WHERE id = $5
        ",
    )
    .bind(user.email)
    .bind(user.hashed_pwd)
    .bind(user.is_admin)
    .bind(Utc::now())
    .bind(user.id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(id: &Uuid, pool: &PgPool) -> Result<(), AppError> {
    sqlx::query(
        "
        DELETE FROM users
        WHERE id = $1
        ",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::Argon2Pwd;
    use tokio::sync::OnceCell;

    static DB: OnceCell<PgPool> = OnceCell::const_new();

    async fn user_create_ignore_duplicate(user: &DbUser, pool: &PgPool) {
        let user = user.clone();
        sqlx::query(
            "
            INSERT INTO users (id, username, email, hashed_pwd, is_admin, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, DEFAULT, DEFAULT)
            ON CONFLICT (username) DO NOTHING
            ",
        )
        .bind(user.id)
        .bind(user.username)
        .bind(user.email)
        .bind(user.hashed_pwd)
        .bind(user.is_admin)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn init_db() -> PgPool {
        println!("init db...");
        let db_url = "postgres://postgres:admin@192.168.0.11:5432/postgres";
        let pool = PgPool::connect(db_url).await.unwrap();

        // insert test user1 if not exists
        let user = DbUser {
            username: "test_user".to_string(),
            email: "test-email@test-domain.com".to_string(),
            hashed_pwd: "test_password".to_argon2_hashed_pwd().unwrap(),
            is_admin: true,
            ..Default::default()
        };
        user_create_ignore_duplicate(&user, &pool).await;

        // insert test user2 with the same email
        let user = DbUser {
            username: "test_user2".to_string(),
            email: "test-email@test-domain.com".to_string(),
            hashed_pwd: "test_password2".to_argon2_hashed_pwd().unwrap(),
            ..Default::default()
        };
        user_create_ignore_duplicate(&user, &pool).await;

        pool
    }

    #[tokio::test]
    async fn test_username_exists() {
        let pool = DB.get_or_init(init_db).await;
        let res = username_exists("test_user", pool).await.unwrap();
        assert!(res);
        let res = username_exists("test_user_not_exist", pool).await.unwrap();
        assert!(!res);
    }

    #[tokio::test]
    async fn test_get_by_email() {
        let pool = DB.get_or_init(init_db).await;
        let res = get_by_email("test-email@test-domain.com", pool)
            .await
            .unwrap();
        assert_eq!(res.len(), 2)
    }
}
