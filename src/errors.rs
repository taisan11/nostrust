use std::fmt;

/// Custom error types for Nostr relay operations
#[derive(Debug, Clone)]
pub enum RelayError {
    /// Event validation errors
    Invalid(String),
    /// Event blocked by policy or deletion
    Blocked(String),
    /// Rate limiting or proof-of-work errors
    RateLimited(String),
    /// Internal server errors
    Internal(String),
    /// Authentication errors
    AuthRequired(String),
    /// Event already exists
    Duplicate,
    /// NIP-specific validation errors
    NipValidation(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::Invalid(msg) => write!(f, "invalid: {}", msg),
            RelayError::Blocked(msg) => write!(f, "blocked: {}", msg),
            RelayError::RateLimited(msg) => write!(f, "rate-limited: {}", msg),
            RelayError::Internal(msg) => write!(f, "error: {}", msg),
            RelayError::AuthRequired(msg) => write!(f, "auth-required: {}", msg),
            RelayError::Duplicate => write!(f, "duplicate: event already exists"),
            RelayError::NipValidation(msg) => write!(f, "invalid: {}", msg),
        }
    }
}

impl std::error::Error for RelayError {}

/// Conversion to String for backwards compatibility
impl From<RelayError> for String {
    fn from(err: RelayError) -> Self {
        err.to_string()
    }
}

/// Conversion from String for backwards compatibility
impl From<String> for RelayError {
    fn from(s: String) -> Self {
        // Parse error message prefix to determine error type
        if s.starts_with("invalid:") {
            RelayError::Invalid(s)
        } else if s.starts_with("blocked:") {
            RelayError::Blocked(s)
        } else if s.starts_with("rate-limited:") {
            RelayError::RateLimited(s)
        } else if s.starts_with("auth-required:") {
            RelayError::AuthRequired(s)
        } else if s.starts_with("duplicate:") {
            RelayError::Duplicate
        } else if s.starts_with("error:") {
            RelayError::Internal(s)
        } else {
            // Default to Invalid for unknown formats
            RelayError::Invalid(s)
        }
    }
}

impl From<&str> for RelayError {
    fn from(s: &str) -> Self {
        RelayError::from(s.to_string())
    }
}

/// Helper methods for creating specific error types
impl RelayError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        RelayError::Invalid(msg.into())
    }

    pub fn blocked(msg: impl Into<String>) -> Self {
        RelayError::Blocked(msg.into())
    }

    pub fn rate_limited(msg: impl Into<String>) -> Self {
        RelayError::RateLimited(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        RelayError::Internal(msg.into())
    }

    pub fn auth_required(msg: impl Into<String>) -> Self {
        RelayError::AuthRequired(msg.into())
    }

    pub fn nip_validation(msg: impl Into<String>) -> Self {
        RelayError::NipValidation(msg.into())
    }

    /// Convert to a String representation (for compatibility with existing code)
    pub fn to_message(&self) -> String {
        self.to_string()
    }
}
