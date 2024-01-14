use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct Login {
    #[validate(custom = "username_validate")]
    pub username: String,
    #[validate(custom = "pwd_validate")]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct Signup {
    #[validate(custom = "username_validate")]
    pub username: String,
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub password: String,
}

fn username_validate(value: &str) -> Result<(), ValidationError> {
    if value.len() < 3 || value.len() > 20 {
        return Err(ValidationError::new("Length must be 3-20"));
    }

    if !value
        .chars()
        .all(|c| char::is_ascii_alphanumeric(&c) || c == '_')
    {
        return Err(ValidationError::new(
            "should contains only A-Z, a-z, 0-9, _",
        ));
    }

    Ok(())
}

fn pwd_validate(value: &str) -> Result<(), ValidationError> {
    if value.len() < 6 || value.len() > 40 {
        return Err(ValidationError::new("Length must be 6-40"));
    }

    if !value
        .chars()
        .all(|c| char::is_ascii_alphanumeric(&c) || "!@#$%^&*".contains(c))
    {
        return Err(ValidationError::new(
            "should contains only A-Z, a-z, 0-9, !@#$%^&*",
        ));
    }

    Ok(())
}
