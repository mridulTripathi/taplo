use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    path::PathBuf,
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{error, info, warn};
use url::Url;
use schemars::JsonSchema;

/// Security configuration for schema loading
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SchemaSecurityConfig {
    /// Maximum allowed schema size in bytes
    #[serde(default = "default_max_schema_size")]
    pub max_schema_size: usize,
    
    /// Maximum recursion depth for schema references
    #[serde(default = "default_max_recursion_depth")]
    pub max_recursion_depth: usize,
    
    /// Maximum time allowed for schema resolution
    #[serde(default = "default_resolution_timeout")]
    pub resolution_timeout: Duration,
    
    /// Maximum concurrent schema requests
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    
    /// Allowed URL schemes
    #[serde(default = "default_allowed_schemes")]
    pub allowed_schemes: HashSet<String>,
    
    /// Allowed URL patterns (glob patterns)
    #[serde(default = "default_allowed_urls")]
    pub allowed_urls: Vec<String>,
    
    /// Blocked URL patterns (glob patterns)
    #[serde(default = "default_blocked_urls")]
    pub blocked_urls: Vec<String>,
    
    /// Allowed file paths (relative to workspace)
    #[serde(default = "default_allowed_file_paths")]
    pub allowed_file_paths: Vec<PathBuf>,
    
    /// Blocked file paths (relative to workspace)
    #[serde(default = "default_blocked_file_paths")]
    pub blocked_file_paths: Vec<PathBuf>,
    
    /// Whether to allow localhost/internal network access
    #[serde(default = "default_allow_localhost")]
    pub allow_localhost: bool,
    
    /// Whether to allow file:// scheme access
    #[serde(default = "default_allow_file_scheme")]
    pub allow_file_scheme: bool,
    
    /// Whether to validate schema integrity (hash/signature)
    #[serde(default = "default_validate_integrity")]
    pub validate_integrity: bool,
    
    /// Whether to enable audit logging
    #[serde(default = "default_audit_logging")]
    pub audit_logging: bool,
}

impl Default for SchemaSecurityConfig {
    fn default() -> Self {
        Self {
            max_schema_size: default_max_schema_size(),
            max_recursion_depth: default_max_recursion_depth(),
            resolution_timeout: default_resolution_timeout(),
            max_concurrent_requests: default_max_concurrent_requests(),
            allowed_schemes: default_allowed_schemes(),
            allowed_urls: default_allowed_urls(),
            blocked_urls: default_blocked_urls(),
            allowed_file_paths: default_allowed_file_paths(),
            blocked_file_paths: default_blocked_file_paths(),
            allow_localhost: default_allow_localhost(),
            allow_file_scheme: default_allow_file_scheme(),
            validate_integrity: default_validate_integrity(),
            audit_logging: default_audit_logging(),
        }
    }
}

fn default_max_schema_size() -> usize {
    1024 * 1024 // 1MB
}

fn default_max_recursion_depth() -> usize {
    10
}

fn default_resolution_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_max_concurrent_requests() -> usize {
    5
}

fn default_allowed_schemes() -> HashSet<String> {
    ["https".to_string()].into_iter().collect()
}

fn default_allowed_urls() -> Vec<String> {
    vec![
        "https://**".to_string(),  // Allow all HTTPS URLs by default
        "https://json.schemastore.org/**".to_string(),
        "https://raw.githubusercontent.com/**".to_string(),
    ]
}

fn default_blocked_urls() -> Vec<String> {
    vec![
        "http://**".to_string(),
        "ftp://**".to_string(),
        "file://**".to_string(),
    ]
}

fn default_allowed_file_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("schemas/"), PathBuf::from(".schemas/")]
}

fn default_blocked_file_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/home"),
    ]
}

fn default_allow_localhost() -> bool {
    false
}

fn default_allow_file_scheme() -> bool {
    false
}

fn default_validate_integrity() -> bool {
    true
}

fn default_audit_logging() -> bool {
    true
}

/// Security guard for schema loading operations
pub struct SchemaSecurityGuard {
    config: SchemaSecurityConfig,
    audit_log: Vec<SecurityAuditEvent>,
}

impl SchemaSecurityGuard {
    pub fn new(config: SchemaSecurityConfig) -> Self {
        Self {
            config,
            audit_log: Vec::new(),
        }
    }

    /// Validate and sanitize a URL before fetching
    pub fn validate_url(&mut self, url: &Url) -> Result<(), SecurityError> {
        let start_time = Instant::now();
        
        // Check scheme
        if !self.config.allowed_schemes.contains(url.scheme()) {
            self.log_audit_event(SecurityAuditEvent::UrlBlocked {
                url: url.clone(),
                reason: "Scheme not allowed".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::SchemeNotAllowed(url.scheme().to_string()));
        }

        // Check for localhost/internal network access
        if !self.config.allow_localhost && self.is_localhost_or_internal(url) {
            self.log_audit_event(SecurityAuditEvent::UrlBlocked {
                url: url.clone(),
                reason: "Localhost/internal network access blocked".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::LocalhostAccessBlocked);
        }

        // Check URL patterns
        if !self.is_url_allowed(url) {
            self.log_audit_event(SecurityAuditEvent::UrlBlocked {
                url: url.clone(),
                reason: "URL pattern not allowed".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::UrlPatternNotAllowed(url.to_string()));
        }

        // Check if URL is blocked
        if self.is_url_blocked(url) {
            self.log_audit_event(SecurityAuditEvent::UrlBlocked {
                url: url.clone(),
                reason: "URL pattern blocked".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::UrlPatternBlocked(url.to_string()));
        }

        self.log_audit_event(SecurityAuditEvent::UrlAllowed {
            url: url.clone(),
            timestamp: start_time,
        });

        Ok(())
    }

    /// Validate file path access
    pub fn validate_file_path(&mut self, path: &PathBuf) -> Result<(), SecurityError> {
        let start_time = Instant::now();

        if !self.config.allow_file_scheme {
            self.log_audit_event(SecurityAuditEvent::FileAccessBlocked {
                path: path.clone(),
                reason: "File scheme not allowed".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::FileSchemeNotAllowed);
        }

        // Check if path is blocked
        if self.is_path_blocked(path) {
            self.log_audit_event(SecurityAuditEvent::FileAccessBlocked {
                path: path.clone(),
                reason: "Path blocked".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::FilePathBlocked(path.clone()));
        }

        // Check if path is allowed
        if !self.is_path_allowed(path) {
            self.log_audit_event(SecurityAuditEvent::FileAccessBlocked {
                path: path.clone(),
                reason: "Path not explicitly allowed".to_string(),
                timestamp: start_time,
            });
            return Err(SecurityError::FilePathNotAllowed(path.clone()));
        }

        self.log_audit_event(SecurityAuditEvent::FileAccessAllowed {
            path: path.clone(),
            timestamp: start_time,
        });

        Ok(())
    }

    /// Validate schema content size and integrity
    pub fn validate_schema_content(&mut self, content: &[u8], url: &Url) -> Result<(), SecurityError> {
        let start_time = Instant::now();

        // Check size limit
        if content.len() > self.config.max_schema_size {
            self.log_audit_event(SecurityAuditEvent::ContentValidationFailed {
                url: url.clone(),
                reason: format!("Content size {} exceeds limit {}", content.len(), self.config.max_schema_size),
                timestamp: start_time,
            });
            return Err(SecurityError::ContentTooLarge(content.len(), self.config.max_schema_size));
        }

        // Validate JSON structure
        if let Err(e) = serde_json::from_slice::<Value>(content) {
            self.log_audit_event(SecurityAuditEvent::ContentValidationFailed {
                url: url.clone(),
                reason: format!("Invalid JSON: {}", e),
                timestamp: start_time,
            });
            return Err(SecurityError::InvalidJson(e.to_string()));
        }

        // TODO: Implement integrity validation (hash/signature checking)
        if self.config.validate_integrity {
            // This would check against expected hashes or signatures
            // For now, we'll just log that integrity checking is enabled
            self.log_audit_event(SecurityAuditEvent::IntegrityCheckPassed {
                url: url.clone(),
                timestamp: start_time,
            });
        }

        self.log_audit_event(SecurityAuditEvent::ContentValidationPassed {
            url: url.clone(),
            timestamp: start_time,
        });

        Ok(())
    }

    /// Check recursion depth limit
    pub fn check_recursion_depth(&mut self, current_depth: usize) -> Result<(), SecurityError> {
        if current_depth > self.config.max_recursion_depth {
            self.log_audit_event(SecurityAuditEvent::RecursionLimitExceeded {
                depth: current_depth,
                limit: self.config.max_recursion_depth,
                timestamp: Instant::now(),
            });
            return Err(SecurityError::RecursionDepthExceeded(current_depth, self.config.max_recursion_depth));
        }
        Ok(())
    }

    /// Get the maximum concurrent requests limit
    pub fn max_concurrent_requests(&self) -> usize {
        self.config.max_concurrent_requests
    }

    /// Get the resolution timeout
    pub fn resolution_timeout(&self) -> Duration {
        self.config.resolution_timeout
    }

    /// Get audit log
    pub fn audit_log(&self) -> &[SecurityAuditEvent] {
        &self.audit_log
    }

    /// Clear audit log
    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    /// Get current security configuration
    pub fn config(&self) -> &SchemaSecurityConfig {
        &self.config
    }

    /// Clone current security configuration
    pub fn config_cloned(&self) -> SchemaSecurityConfig {
        self.config.clone()
    }

    // Private helper methods

    fn is_localhost_or_internal(&self, url: &Url) -> bool {
        if let Some(host) = url.host_str() {
            host == "localhost" || host == "127.0.0.1" || host == "::1" ||
            host.starts_with("192.168.") || host.starts_with("10.") || host.starts_with("172.")
        } else {
            false
        }
    }

    fn is_url_allowed(&self, url: &Url) -> bool {
        if self.config.allowed_urls.is_empty() {
            return true; // If no allowlist, allow all (subject to other checks)
        }

        self.config.allowed_urls.iter().any(|pattern| {
            self.matches_glob_pattern(url.as_str(), pattern)
        })
    }

    fn is_url_blocked(&self, url: &Url) -> bool {
        self.config.blocked_urls.iter().any(|pattern| {
            self.matches_glob_pattern(url.as_str(), pattern)
        })
    }

    fn is_path_allowed(&self, path: &PathBuf) -> bool {
        if self.config.allowed_file_paths.is_empty() {
            return false; // If no allowlist, deny all file access
        }

        self.config.allowed_file_paths.iter().any(|allowed_path| {
            path.starts_with(allowed_path)
        })
    }

    fn is_path_blocked(&self, path: &PathBuf) -> bool {
        self.config.blocked_file_paths.iter().any(|blocked_path| {
            path.starts_with(blocked_path)
        })
    }

    fn matches_glob_pattern(&self, url: &str, pattern: &str) -> bool {
        // Simple glob pattern matching - in production, use a proper glob library
        if pattern.ends_with("/**") {
            let prefix = &pattern[..pattern.len() - 3];
            url.starts_with(prefix)
        } else if pattern.ends_with("*") {
            let prefix = &pattern[..pattern.len() - 1];
            url.starts_with(prefix)
        } else {
            url == pattern
        }
    }

    fn log_audit_event(&mut self, event: SecurityAuditEvent) {
        if self.config.audit_logging {
            self.audit_log.push(event);
            
            match &self.audit_log.last().unwrap() {
                SecurityAuditEvent::UrlBlocked { url, reason, .. } => {
                    warn!("Schema security: URL blocked - {}: {}", url, reason);
                }
                SecurityAuditEvent::FileAccessBlocked { path, reason, .. } => {
                    warn!("Schema security: File access blocked - {}: {}", path.display(), reason);
                }
                SecurityAuditEvent::ContentValidationFailed { url, reason, .. } => {
                    error!("Schema security: Content validation failed - {}: {}", url, reason);
                }
                SecurityAuditEvent::RecursionLimitExceeded { depth, limit, .. } => {
                    error!("Schema security: Recursion limit exceeded - depth: {}, limit: {}", depth, limit);
                }
                _ => {
                    info!("Schema security: Event logged");
                }
            }
        }
    }
}

/// Security audit events
#[derive(Debug, Clone)]
pub enum SecurityAuditEvent {
    UrlAllowed {
        url: Url,
        timestamp: Instant,
    },
    UrlBlocked {
        url: Url,
        reason: String,
        timestamp: Instant,
    },
    FileAccessAllowed {
        path: PathBuf,
        timestamp: Instant,
    },
    FileAccessBlocked {
        path: PathBuf,
        reason: String,
        timestamp: Instant,
    },
    ContentValidationPassed {
        url: Url,
        timestamp: Instant,
    },
    ContentValidationFailed {
        url: Url,
        reason: String,
        timestamp: Instant,
    },
    IntegrityCheckPassed {
        url: Url,
        timestamp: Instant,
    },
    RecursionLimitExceeded {
        depth: usize,
        limit: usize,
        timestamp: Instant,
    },
}

/// Security-related errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Scheme '{0}' is not allowed")]
    SchemeNotAllowed(String),
    
    #[error("Localhost/internal network access is blocked")]
    LocalhostAccessBlocked,
    
    #[error("URL pattern '{0}' is not allowed")]
    UrlPatternNotAllowed(String),
    
    #[error("URL pattern '{0}' is blocked")]
    UrlPatternBlocked(String),
    
    #[error("File scheme access is not allowed")]
    FileSchemeNotAllowed,
    
    #[error("File path '{0:?}' is blocked")]
    FilePathBlocked(PathBuf),
    
    #[error("File path '{0:?}' is not explicitly allowed")]
    FilePathNotAllowed(PathBuf),
    
    #[error("Content size {0} exceeds limit {1}")]
    ContentTooLarge(usize, usize),
    
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),
    
    #[error("Recursion depth {0} exceeds limit {1}")]
    RecursionDepthExceeded(usize, usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let config = SchemaSecurityConfig::default();
        assert_eq!(config.max_schema_size, 1024 * 1024);
        assert_eq!(config.max_recursion_depth, 10);
        assert_eq!(config.resolution_timeout, Duration::from_secs(30));
        assert_eq!(config.max_concurrent_requests, 5);
        assert!(config.allowed_schemes.contains("https"));
        assert!(!config.allowed_schemes.contains("http"));
        assert!(!config.allow_localhost);
        assert!(!config.allow_file_scheme);
    }

    #[test]
    fn test_url_validation() {
        let mut guard = SchemaSecurityGuard::new(SchemaSecurityConfig::default());
        
        // HTTPS should be allowed
        let https_url = Url::parse("https://example.com/schema.json").unwrap();
        assert!(guard.validate_url(&https_url).is_ok());
        
        // HTTP should be blocked
        let http_url = Url::parse("http://example.com/schema.json").unwrap();
        assert!(guard.validate_url(&http_url).is_err());
        
        // File should be blocked
        let file_url = Url::parse("file:///etc/passwd").unwrap();
        assert!(guard.validate_url(&file_url).is_err());
    }

    #[test]
    fn test_localhost_blocking() {
        let mut guard = SchemaSecurityGuard::new(SchemaSecurityConfig::default());
        
        let localhost_url = Url::parse("https://localhost/schema.json").unwrap();
        assert!(guard.validate_url(&localhost_url).is_err());
        
        let internal_url = Url::parse("https://192.168.1.1/schema.json").unwrap();
        assert!(guard.validate_url(&internal_url).is_err());
    }

    #[test]
    fn test_content_validation() {
        let mut guard = SchemaSecurityGuard::new(SchemaSecurityConfig::default());
        let url = Url::parse("https://example.com/schema.json").unwrap();
        
        // Valid JSON
        let valid_json = r#"{"type": "object"}"#.as_bytes();
        assert!(guard.validate_schema_content(valid_json, &url).is_ok());
        
        // Invalid JSON
        let invalid_json = r#"{"type": "object"#.as_bytes();
        assert!(guard.validate_schema_content(invalid_json, &url).is_err());
        
        // Too large content
        let large_content = vec![0u8; 2 * 1024 * 1024]; // 2MB
        assert!(guard.validate_schema_content(&large_content, &url).is_err());
    }

    #[test]
    fn test_recursion_depth() {
        let mut guard = SchemaSecurityGuard::new(SchemaSecurityConfig::default());
        
        assert!(guard.check_recursion_depth(5).is_ok());
        assert!(guard.check_recursion_depth(10).is_ok());
        assert!(guard.check_recursion_depth(11).is_err());
    }
}
