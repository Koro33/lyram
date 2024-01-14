pub mod model;
pub mod user;

use sqlx::PgPool;
use tokio::sync::OnceCell;

use crate::config;

#[derive(Debug, Clone)]
pub struct DbLogin {
    pub user: String,
    pub pwd: String,
    pub host: String,
    pub port: String,
    pub database: String,
}

impl Default for DbLogin {
    fn default() -> Self {
        Self {
            user: "postgres".to_owned(),
            pwd: "admin".to_owned(),
            host: "192.168.0.11".to_owned(),
            port: "5432".to_owned(),
            database: "lyram".to_owned(),
        }
    }
}

impl DbLogin {
    pub fn to_uri(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user, self.pwd, self.host, self.port, self.database
        )
    }
    pub fn to_display_uri(&self) -> String {
        format!(
            "postgres://{}:***@{}:{}/{}",
            self.user, self.host, self.port, self.database
        )
    }
}

static DB: OnceCell<PgPool> = OnceCell::const_new();

pub async fn get_db() -> &'static PgPool {
    DB.get_or_init(|| async {
        match PgPool::connect(config::db_login().to_uri().as_str()).await {
            Ok(pool) => {
                tracing::info!(
                    "Connected to database: {}",
                    config::db_login().to_display_uri()
                );
                pool
            }
            Err(_e) => {
                tracing::error!(
                    "Failed to connect to database: {}",
                    config::db_login().to_display_uri()
                );
                panic!(
                    "Failed to connect to database: {}",
                    config::db_login().to_display_uri()
                )
            }
        }
    })
    .await
}
