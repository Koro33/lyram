pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod schema;
pub mod utils;

use sqlx::PgPool;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug)]
pub struct AppState {
    pub pool: PgPool,
}

pub fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lyram=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
