use crate::config;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken as jwt;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use uuid::Uuid;

pub trait Argon2Pwd {
    fn to_argon2_hashed_pwd(&self) -> Result<String, argon2::password_hash::Error>;
    fn argon2_verify_with_pwd(&self, ori_pwd: &str) -> Result<bool, argon2::password_hash::Error>;
    fn argon2_verify_with_hashed_pwd(
        &self,
        hashed_pwd: &str,
    ) -> Result<bool, argon2::password_hash::Error>;
}

impl Argon2Pwd for &str {
    fn to_argon2_hashed_pwd(&self) -> Result<String, argon2::password_hash::Error> {
        // let password = b"test_password";
        let argon2 = Argon2::default();
        let hashed_pwd = argon2
            .hash_password(self.as_ref(), &SaltString::generate(&mut OsRng))?
            .to_string();
        Ok(hashed_pwd)
    }

    fn argon2_verify_with_pwd(&self, pwd: &str) -> Result<bool, argon2::password_hash::Error> {
        Argon2::default()
            .verify_password(pwd.as_ref(), &PasswordHash::new(self)?)
            .map(|_| true)
            .or(Ok(false))
    }

    fn argon2_verify_with_hashed_pwd(
        &self,
        hashed_pwd: &str,
    ) -> Result<bool, argon2::password_hash::Error> {
        Argon2::default()
            .verify_password(self.as_ref(), &PasswordHash::new(hashed_pwd)?)
            .map(|_| true)
            .or(Ok(false))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd)]
pub struct JwtClaims {
    pub aud: String, // Optional. Audience
    pub exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub iat: usize, // Optional. Issued at (as UTC timestamp)
    pub iss: String, // Optional. Issuer
    pub nbf: usize, // Optional. Not Before (as UTC timestamp)
    pub sub: String, // Optional. Subject (whom token refers to)
    pub name: String,
}

impl Default for JwtClaims {
    fn default() -> Self {
        let now = chrono::Utc::now();
        Self {
            aud: "lyram".to_owned(),
            exp: (now + chrono::Duration::seconds(config::jwt_expire())).timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: "lyram".to_owned(),
            nbf: now.timestamp() as usize,
            sub: Uuid::new_v4().to_string(),
            name: "admin".to_owned(),
        }
    }
}

impl Display for JwtClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UserId: {},\nUsername: {},\nIssuer: {},\nAudience: {},\nIssued at: {},\nNot Before: {},\nExpire at: {}",
            self.sub,
            self.name,
            self.iss,
            self.aud,
            chrono::DateTime::from_timestamp(self.iat as i64, 0)
                .map_or_else(|| "Error when convert".to_owned(), |d| d.to_rfc3339()),
            chrono::DateTime::from_timestamp(self.nbf as i64, 0)
                .map_or_else(|| "Error when convert".to_owned(), |d| d.to_rfc3339()),
            chrono::DateTime::from_timestamp(self.exp as i64, 0)
                .map_or_else(|| "Error when convert".to_owned(), |d| d.to_rfc3339()),
        )
    }
}

pub fn jwt_enc(claims: &JwtClaims) -> Result<String, jwt::errors::Error> {
    let token = jwt::encode(
        &jwt::Header::default(),
        claims,
        &jwt::EncodingKey::from_secret(config::jwt_secret().as_ref()),
    )?;
    Ok(token)
}

pub fn jwt_dec(token: &str) -> Result<JwtClaims, jwt::errors::Error> {
    let mut jwt_validation = jwt::Validation::default();
    jwt_validation.set_audience(&["lyram"]);
    jwt_validation.set_issuer(&["lyram"]);

    let claims = jwt::decode::<JwtClaims>(
        token,
        &jwt::DecodingKey::from_secret(config::jwt_secret().as_ref()),
        &jwt_validation,
    )?
    .claims;

    Ok(claims)
}

#[cfg(test)]
mod tests {

    use super::*;

    const PWD: &str = "test_password";
    const HASHED_PWD: &str = "$argon2id$v=19$m=19456,t=2,p=1$O6cp3HvZKu9vox9zBUrjUw$Jyn6E4+l2iG2c8V5BdlZOp0mLaBXdgSeEhtfmxFlRcU";

    #[test]
    fn test_jwt_enc_dec() {
        let claims = JwtClaims {
            sub: "test_user".to_owned(),
            ..Default::default()
        };
        let token = jwt_enc(&claims).unwrap();

        let claims_dec = jwt_dec(&token).unwrap();

        assert_eq!(claims, claims_dec);
    }

    #[test]
    fn test_argon2pwd_to_argon2_hashed_pwd() {
        assert_eq!(PWD.to_argon2_hashed_pwd().unwrap(), HASHED_PWD);
    }

    #[test]
    fn test_argon2pwd_verify_with_pwd() {
        assert!(HASHED_PWD.argon2_verify_with_pwd(PWD).unwrap())
    }

    #[test]
    fn test_argon2pwd_verify_with_hashed_pwd() {
        assert!(PWD.argon2_verify_with_hashed_pwd(HASHED_PWD).unwrap());
    }
}
