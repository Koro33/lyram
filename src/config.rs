use crate::db::DbLogin;
use std::sync::OnceLock;

// set DB login info
static DB_LOGIN: OnceLock<DbLogin> = OnceLock::new();

#[cfg(debug_assertions)]
pub fn db_login() -> DbLogin {
    DB_LOGIN
        .get_or_init(|| DbLogin {
            user: std::env::var("DB_PG_USER").unwrap_or_else(|_| DbLogin::default().user),
            pwd: std::env::var("DB_PG_PWD").unwrap_or_else(|_| DbLogin::default().pwd),
            host: std::env::var("DB_PG_HOST").unwrap_or_else(|_| DbLogin::default().host),
            port: std::env::var("DB_PG_PORT").unwrap_or_else(|_| DbLogin::default().port),
            database: std::env::var("DB_PG_DATABASE")
                .unwrap_or_else(|_| DbLogin::default().database),
        })
        .to_owned()
}

#[cfg(not(debug_assertions))]
pub fn db_login() -> DbLogin {
    DB_LOGIN
        .get_or_init(|| {
            let msg = "The env `DB_PG_USER`, `DB_PG_PWD`, `DB_PG_HOST`, `DB_PG_PORT`, `DB_PG_DATABASE` must be set";

            let user = std::env::var("DB_PG_USER").map_err(|e| {
                tracing::error!("`DB_PG_USER` not set");
                e
            });
            let pwd = std::env::var("DB_PG_PWD").map_err(|e| {
                tracing::error!("`DB_PG_PWD` not set");
                e
            });
            let host = std::env::var("DB_PG_HOST").map_err(|e| {
                tracing::error!("`DB_PG_HOST` not set");
                e
            });
            let port = std::env::var("DB_PG_PORT").map_err(|e| {
                tracing::error!("`DB_PG_PORT` not set");
                e
            });
            let database = std::env::var("DB_PG_DATABASE").map_err(|e| {
                tracing::error!("`DB_PG_DATABASE` not set");
                e
            });
            DbLogin {
                user: user.expect(msg),
                pwd: pwd.expect(msg),
                host: host.expect(msg),
                port: port.expect(msg),
                database: database.expect(msg),
            }
        })
        .to_owned()
}

// set jwt secret
static JWT_SECRET: OnceLock<String> = OnceLock::new();

#[cfg(debug_assertions)]
pub fn jwt_secret() -> String {
    JWT_SECRET
        .get_or_init(|| {
            std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "*4w*8Df&4r^E6LM!ao&T2L7pMkR65$vN".to_owned())
        })
        .to_owned()
}

#[cfg(not(debug_assertions))]
pub fn jwt_secret() -> String {
    JWT_SECRET
        .get_or_init(|| std::env::var("JWT_SECRET").expect("The env JWT_SECRET must be set"))
        .to_owned()
}

// set admin password
static ADMIN_PWD: OnceLock<String> = OnceLock::new();

pub fn admin_pwd() -> String {
    ADMIN_PWD
        .get_or_init(|| std::env::var("ADMIN_PWD").unwrap_or_else(|_| "adminadmin".to_owned()))
        .to_owned()
}

static JWT_EXPIRE: OnceLock<i64> = OnceLock::new();
pub fn jwt_expire() -> i64 {
    JWT_EXPIRE
        .get_or_init(|| {
            std::env::var("JWT_EXPIRE")
                .map(|a| a.parse().expect("The env JWT_EXPIRE should be an integer"))
                .unwrap_or(30 * 24 * 60 * 60)
        })
        .to_owned()
}
