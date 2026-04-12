//! API contracts shared across control-plane services.

use serde::{Deserialize, Serialize};

/// Cursor used for stable pagination across list endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PageCursor(pub String);

impl PageCursor {
    /// Create a cursor from a stable string token.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the cursor as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Direction of a sortable list query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    /// Ascending order.
    #[default]
    Asc,
    /// Descending order.
    Desc,
}

/// Filter predicate passed to list endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterPredicate {
    /// Field name on the target resource.
    pub field: String,
    /// Comparison operator such as `eq`, `prefix`, `contains`, or `lt`.
    pub operator: String,
    /// String form of the compared value.
    pub value: String,
}

/// Standard list request used by all collection endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRequest {
    /// Optional page size. Services clamp this to a safe upper bound.
    #[serde(default = "default_list_limit")]
    pub limit: Option<usize>,
    /// Cursor for continued iteration.
    #[serde(default)]
    pub cursor: Option<PageCursor>,
    /// Requested sort field.
    #[serde(default)]
    pub sort_by: Option<String>,
    /// Sort direction.
    #[serde(default)]
    pub direction: SortDirection,
    /// Collection filters.
    #[serde(default)]
    pub filters: Vec<FilterPredicate>,
}

fn default_list_limit() -> Option<usize> {
    Some(50)
}

impl Default for ListRequest {
    fn default() -> Self {
        Self {
            limit: Some(50),
            cursor: None,
            sort_by: None,
            direction: SortDirection::Asc,
            filters: Vec::new(),
        }
    }
}

/// Validation failures for list contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListRequestError {
    /// The requested limit was zero.
    InvalidLimit,
    /// A filter contained an empty field, operator, or value.
    EmptyFilterField {
        /// Filter index.
        index: usize,
        /// Problematic field name.
        field: &'static str,
    },
}

impl ListRequest {
    /// Validate list request invariants.
    pub fn validate(&self) -> Result<(), ListRequestError> {
        if matches!(self.limit, Some(0)) {
            return Err(ListRequestError::InvalidLimit);
        }

        for (index, filter) in self.filters.iter().enumerate() {
            for (field, value) in [
                ("field", &filter.field),
                ("operator", &filter.operator),
                ("value", &filter.value),
            ] {
                if value.trim().is_empty() {
                    return Err(ListRequestError::EmptyFilterField { index, field });
                }
            }
        }

        Ok(())
    }
}

/// Standard paginated response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// Records on the current page.
    pub items: Vec<T>,
    /// Cursor for the next page when available.
    pub next_cursor: Option<PageCursor>,
}

/// Idempotency key wrapper used by mutating APIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    /// Create a new idempotency key wrapper.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Optimistic concurrency token wrapper used across APIs and storage layers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConcurrencyToken(pub String);

impl ConcurrencyToken {
    /// Create a new concurrency token wrapper.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the token as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ListRequest, SortDirection};

    #[test]
    fn list_request_defaults_survive_missing_fields() {
        let request: ListRequest =
            serde_json::from_str("{}").unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(request, ListRequest::default());
    }

    #[test]
    fn list_request_validation_rejects_zero_limit() {
        let request = ListRequest {
            limit: Some(0),
            cursor: None,
            sort_by: None,
            direction: SortDirection::Asc,
            filters: Vec::new(),
        };

        assert!(request.validate().is_err());
    }
}
