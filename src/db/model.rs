use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::prelude::*;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, FromRow)]
pub struct DbUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub hashed_pwd: String,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for DbUser {
    fn default() -> Self {
        DbUser {
            id: Uuid::now_v7(),
            username: "".to_string(),
            email: "".to_string(),
            hashed_pwd: "".to_string(),
            is_admin: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Song {
    pub id: Uuid,
    pub title: String,
    pub artists: Vec<String>,
    pub album_title: String,
    pub album_artist: String,
    pub suffix: String,
    pub duration: i32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtistDb {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlbumDb {
    pub id: Uuid,
    pub title: String,
}
