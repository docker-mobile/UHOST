//! Input validation and canonicalization helpers.

use crate::error::{PlatformError, Result};

/// Validate and normalize a slug.
pub fn validate_slug(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 63 {
        return Err(PlatformError::invalid(
            "slug must be between 1 and 63 bytes",
        ));
    }

    if !value.chars().all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
    }) {
        return Err(PlatformError::invalid(
            "slug must contain only lowercase ascii letters, digits, and dashes",
        ));
    }

    if value.starts_with('-') || value.ends_with('-') {
        return Err(PlatformError::invalid(
            "slug may not start or end with a dash",
        ));
    }

    Ok(value.to_owned())
}

/// Validate an email address conservatively.
pub fn validate_email(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(PlatformError::invalid("email must contain a single @"));
    };

    if local.is_empty() || domain.is_empty() {
        return Err(PlatformError::invalid(
            "email local or domain part is empty",
        ));
    }

    let canonical_domain = validate_domain_name(domain)?;
    Ok(format!("{local}@{canonical_domain}"))
}

/// Validate a domain name.
pub fn validate_domain_name(value: &str) -> Result<String> {
    let trimmed = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(PlatformError::invalid("domain length is invalid"));
    }

    for label in trimmed.split('.') {
        validate_slug(label)?;
    }

    Ok(trimmed)
}

/// Canonicalize hostnames for consistent routing and policy lookups.
pub fn canonicalize_hostname(value: &str) -> Result<String> {
    validate_domain_name(value)
}

/// Normalize label keys to a restricted format.
pub fn normalize_label_key(value: &str) -> Result<String> {
    validate_slug(&value.trim().to_ascii_lowercase())
}

/// Validate label values.
pub fn validate_label_value(value: &str) -> Result<String> {
    if value.len() > 128 {
        return Err(PlatformError::invalid("label value exceeds 128 bytes"));
    }

    if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
    }) {
        return Ok(value.to_owned());
    }

    Err(PlatformError::invalid(
        "label value contains unsupported characters",
    ))
}

#[cfg(test)]
mod tests {
    use super::{normalize_label_key, validate_domain_name, validate_email, validate_slug};
    use proptest::prelude::*;

    #[test]
    fn valid_slug_passes() {
        assert_eq!(
            validate_slug("platform-api").unwrap_or_else(|error| panic!("{error}")),
            "platform-api"
        );
    }

    proptest! {
        #[test]
        fn normalized_label_keys_are_lowercase(input in "[A-Za-z0-9]{1,8}(-[A-Za-z0-9]{1,8}){0,1}") {
            let lowered = input.to_ascii_lowercase();
            let result = normalize_label_key(&lowered).unwrap_or_else(|error| panic!("{error}"));
            prop_assert_eq!(result, lowered);
        }
    }

    #[test]
    fn domain_validation_trims_trailing_dot() {
        let value = validate_domain_name("example.com.").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(value, "example.com");
    }

    #[test]
    fn email_validation_preserves_local_part_and_canonicalizes_domain() {
        let value = validate_email("  User.Name+Tag@Example.COM.  ")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(value, "User.Name+Tag@example.com");
    }
}
