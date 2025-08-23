# Schema Security Guide

This document describes the security features implemented in taplo's schema loading system to protect against various attack vectors when loading external JSON schemas.

## Security Threats Addressed

### 1. Remote Code Execution (RCE)
- **Threat**: Malicious schemas could potentially execute arbitrary code
- **Mitigation**: Content validation, size limits, and integrity checks

### 2. Denial of Service (DoS)
- **Threat**: Infinite recursion, extremely large schemas, resource exhaustion
- **Mitigation**: Recursion depth limits, schema size limits, concurrent request limits

### 3. Server-Side Request Forgery (SSRF)
- **Threat**: Access to internal networks, localhost, or file system
- **Mitigation**: URL allowlisting, scheme restrictions, file path controls

### 4. Cache Poisoning & Supply Chain Attacks
- **Threat**: Malicious schemas cached and served to other users
- **Mitigation**: Integrity validation, audit logging, content verification

## Security Configuration

### Basic Security Settings

```toml
[schema_security]
# Resource limits
max_schema_size = 1048576        # 1MB maximum
max_recursion_depth = 10         # Maximum reference depth
resolution_timeout = 30          # 30 seconds timeout
max_concurrent_requests = 5      # Limit concurrent fetches

# Network access controls
allowed_schemes = ["https"]      # Only HTTPS allowed
allow_localhost = false          # Block internal network access
allowed_urls = [                 # Whitelist allowed domains
    "https://json.schemastore.org/**",
    "https://raw.githubusercontent.com/**"
]

# File system controls
allow_file_scheme = false        # Block file:// URLs
allowed_file_paths = [           # Whitelist allowed directories
    "schemas/",
    ".schemas/"
]

# Security features
validate_integrity = true        # Enable integrity checks
audit_logging = true             # Log security events
```

### Production Security Configuration

For production environments, use restrictive settings:

```toml
[schema_security]
# Strict resource limits
max_schema_size = 512000         # 500KB maximum
max_recursion_depth = 5          # Low recursion limit
resolution_timeout = 15          # Short timeout
max_concurrent_requests = 2      # Minimal concurrency

# Network restrictions
allowed_schemes = ["https"]
allow_localhost = false
allowed_urls = [
    "https://json.schemastore.org/**"  # Only trusted sources
]

# File access disabled
allow_file_scheme = false

# Security enabled
validate_integrity = true
audit_logging = true
```

### Development Configuration

For development, more permissive settings may be needed:

```toml
[schema_security]
# Relaxed resource limits
max_schema_size = 2097152       # 2MB maximum
max_recursion_depth = 15         # Higher recursion limit
resolution_timeout = 60          # Longer timeout
max_concurrent_requests = 10     # More concurrency

# Network access
allowed_schemes = ["https", "http"]
allow_localhost = true           # Allow local development
allowed_urls = [
    "https://json.schemastore.org/**",
    "http://localhost/**"        # Local development servers
]

# File access for local schemas
allow_file_scheme = true
allowed_file_paths = [
    "schemas/",
    ".schemas/",
    "../shared-schemas/"         # Shared schema directories
]

# Security features
validate_integrity = false       # Disable for development speed
audit_logging = false            # Reduce log noise
```

## Security Features

### 1. Resource Limits

- **Schema Size**: Prevents memory exhaustion from extremely large schemas
- **Recursion Depth**: Prevents infinite recursion attacks
- **Timeout**: Prevents hanging requests
- **Concurrent Requests**: Prevents resource exhaustion

### 2. Network Access Controls

- **Scheme Restrictions**: Only allow HTTPS by default
- **URL Allowlisting**: Whitelist trusted domains
- **URL Blocking**: Blacklist malicious or untrusted domains
- **Localhost Blocking**: Prevent internal network access

### 3. File System Controls

- **Path Allowlisting**: Only allow access to specific directories
- **Path Blocking**: Block access to sensitive system directories
- **Scheme Control**: Disable file:// URLs by default

### 4. Content Validation

- **JSON Validation**: Ensure downloaded content is valid JSON
- **Size Verification**: Check content size before processing
- **Integrity Checks**: Validate schema integrity (future enhancement)

### 5. Audit Logging

- **Security Events**: Log all security-related actions
- **Access Attempts**: Track blocked and allowed requests
- **Performance Metrics**: Monitor resource usage

## Security Best Practices

### 1. Principle of Least Privilege

- Start with restrictive settings
- Only allow what's absolutely necessary
- Regularly review and tighten permissions

### 2. Trust but Verify

- Use HTTPS for all external requests
- Validate content before processing
- Implement integrity checks where possible

### 3. Defense in Depth

- Multiple layers of security controls
- Fail-safe defaults
- Comprehensive logging and monitoring

### 4. Regular Updates

- Keep allowlists updated
- Monitor security advisories
- Update blocked URL patterns

## Monitoring and Alerting

### Audit Log Events

The security system logs various events:

- `UrlAllowed`: Successfully validated URLs
- `UrlBlocked`: Blocked URLs with reasons
- `FileAccessAllowed`: Allowed file access
- `FileAccessBlocked`: Blocked file access
- `ContentValidationPassed`: Content validation success
- `ContentValidationFailed`: Content validation failures
- `RecursionLimitExceeded`: Recursion depth violations

### Example Monitoring Setup

```rust
// Get security audit log
let audit_log = schemas.security_audit_log();

// Monitor for security violations
for event in audit_log {
    match event {
        SecurityAuditEvent::UrlBlocked { url, reason, .. } => {
            // Alert on blocked URLs
            log::warn!("Security alert: URL blocked - {}: {}", url, reason);
        }
        SecurityAuditEvent::ContentValidationFailed { url, reason, .. } => {
            // Alert on content validation failures
            log::error!("Security alert: Content validation failed - {}: {}", url, reason);
        }
        SecurityAuditEvent::RecursionLimitExceeded { depth, limit, .. } => {
            // Alert on recursion violations
            log::error!("Security alert: Recursion limit exceeded - depth: {}, limit: {}", depth, limit);
        }
        _ => {}
    }
}
```

## Migration Guide

### From Unsecured to Secured

1. **Enable Security**: Add `[schema_security]` section to config
2. **Set Resource Limits**: Configure appropriate size and depth limits
3. **Restrict Network Access**: Configure allowed schemes and URLs
4. **Control File Access**: Set file path restrictions
5. **Enable Logging**: Turn on audit logging
6. **Test**: Verify functionality with security enabled
7. **Monitor**: Watch logs for blocked requests
8. **Adjust**: Refine settings based on actual usage

### Backward Compatibility

The security system is designed to be backward compatible:

- Default settings provide reasonable security
- Existing configurations continue to work
- Security can be gradually enabled
- Per-environment configurations supported

## Troubleshooting

### Common Issues

1. **Schemas Not Loading**: Check URL allowlists and scheme restrictions
2. **File Access Denied**: Verify file path allowlists
3. **Timeout Errors**: Adjust resolution timeout settings
4. **Recursion Errors**: Increase recursion depth limits if needed
5. **Size Errors**: Increase schema size limits for large schemas

### Debug Mode

Enable detailed logging to troubleshoot security issues:

```toml
[schema_security]
audit_logging = true
```

### Security Override (Use with Caution)

For emergency situations, temporarily disable security:

```toml
[schema_security]
# WARNING: This disables all security features
max_schema_size = 1073741824    # 1GB
max_recursion_depth = 100
allow_localhost = true
allow_file_scheme = true
validate_integrity = false
```

**Note**: Only use security overrides temporarily and restore security as soon as possible.

## Future Enhancements

- **Digital Signatures**: Verify schema authenticity
- **Hash Validation**: Check schema integrity against known hashes
- **Rate Limiting**: Prevent abuse through request throttling
- **Machine Learning**: Detect anomalous schema patterns
- **Integration**: Security monitoring and alerting systems
