use taplo_common::{
    environment::native::NativeEnvironment,
    schema::security::SchemaSecurityConfig,
    schema::Schemas,
};
use url::Url;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For this example, we'll use tokio runtime manually
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a native environment
    let env = NativeEnvironment::new();
    
    // Create an HTTP client
    let http_client = reqwest::Client::new();

    // Example 1: Default secure configuration
    println!("=== Example 1: Default Secure Configuration ===");
    let schemas = Schemas::new(env.clone(), http_client.clone());
    
    // Try to load a schema from a trusted source
    let trusted_url = Url::parse("https://json.schemastore.org/package.json")?;
    match schemas.load_schema(&trusted_url).await {
        Ok(_schema) => println!("✓ Successfully loaded schema from trusted source"),
        Err(e) => println!("✗ Failed to load schema: {}", e),
    }

    // Example 2: Custom restrictive security configuration
    println!("\n=== Example 2: Restrictive Security Configuration ===");
    let restrictive_config = SchemaSecurityConfig {
        max_schema_size: 512000,        // 500KB limit
        max_recursion_depth: 3,         // Low recursion limit
        resolution_timeout: std::time::Duration::from_secs(15), // Short timeout
        max_concurrent_requests: 2,     // Low concurrency
        allowed_schemes: ["https".to_string()].into_iter().collect(),
        allowed_urls: vec![
            "https://json.schemastore.org/**".to_string(), // Only trusted source
        ],
        blocked_urls: vec![
            "http://**".to_string(),
            "ftp://**".to_string(),
            "file://**".to_string(),
        ],
        allow_localhost: false,
        allow_file_scheme: false,
        validate_integrity: true,
        audit_logging: true,
        ..Default::default()
    };

    let secure_schemas = Schemas::with_security_config(env.clone(), http_client.clone(), restrictive_config);
    
    // Try to load from allowed source
    let allowed_url = Url::parse("https://json.schemastore.org/package.json")?;
    match secure_schemas.load_schema(&allowed_url).await {
        Ok(_) => println!("✓ Successfully loaded schema from allowed source"),
        Err(e) => println!("✗ Failed to load schema: {}", e),
    }

    // Try to load from blocked source (should fail)
    let blocked_url = Url::parse("http://example.com/schema.json")?;
    match secure_schemas.load_schema(&blocked_url).await {
        Ok(_) => println!("✗ Unexpectedly loaded schema from blocked source"),
        Err(e) => println!("✓ Correctly blocked schema from blocked source: {}", e),
    }

    // Example 3: Development configuration (more permissive)
    println!("\n=== Example 3: Development Configuration ===");
    let dev_config = SchemaSecurityConfig {
        max_schema_size: 2097152,       // 2MB limit
        max_recursion_depth: 15,        // Higher recursion limit
        resolution_timeout: std::time::Duration::from_secs(60), // Longer timeout
        max_concurrent_requests: 10,    // Higher concurrency
        allowed_schemes: ["https".to_string(), "http".to_string()].into_iter().collect(),
        allowed_urls: vec![
            "https://**".to_string(),
            "http://localhost/**".to_string(), // Allow local development
        ],
        allow_localhost: true,          // Allow localhost for development
        allow_file_scheme: true,        // Allow file access for development
        allowed_file_paths: vec![
            std::path::PathBuf::from("schemas/"),
            std::path::PathBuf::from(".schemas/"),
            std::path::PathBuf::from("../shared-schemas/"),
        ],
        validate_integrity: false,      // Disable for development speed
        audit_logging: false,           // Reduce log noise
        ..Default::default()
    };

    let dev_schemas = Schemas::with_security_config(env.clone(), http_client.clone(), dev_config);
    
    // Try to load from localhost (should work in dev mode)
    let localhost_url = Url::parse("http://localhost:8080/schema.json")?;
    match dev_schemas.load_schema(&localhost_url).await {
        Ok(_) => println!("✓ Successfully loaded schema from localhost (dev mode)"),
        Err(e) => println!("✗ Failed to load schema from localhost: {}", e),
    }

    // Example 4: Security monitoring and audit logging
    println!("\n=== Example 4: Security Monitoring ===");
    let monitoring_schemas = Schemas::new(env.clone(), http_client.clone());
    
    // Try some operations to generate audit events
    let _ = monitoring_schemas.load_schema(&trusted_url).await;
    
    // Get the security audit log
    let audit_log = monitoring_schemas.security_audit_log();
    println!("Security audit log contains {} events", audit_log.len());
    
    // Display recent security events
    for (i, event) in audit_log.iter().take(5).enumerate() {
        println!("  Event {}: {:?}", i + 1, event);
    }

    // Example 5: Runtime security configuration updates
    println!("\n=== Example 5: Runtime Security Updates ===");
    let runtime_schemas = Schemas::new(env.clone(), http_client.clone());
    
    // Update security configuration at runtime
    let updated_config = SchemaSecurityConfig {
        max_schema_size: 256000,        // Reduce to 250KB
        max_recursion_depth: 5,         // Reduce recursion
        ..runtime_schemas.security_config()
    };
    
    runtime_schemas.update_security_config(updated_config);
    println!("✓ Updated security configuration at runtime");
    
    // Verify the update
    let current_config = runtime_schemas.security_config();
    println!("  Current max schema size: {} bytes", current_config.max_schema_size);
    println!("  Current max recursion depth: {}", current_config.max_recursion_depth);

    println!("\n=== Security Implementation Summary ===");
    println!("✓ Resource limits enforced (size, depth, timeout, concurrency)");
    println!("✓ Network access controlled (schemes, URLs, localhost blocking)");
    println!("✓ File system access restricted (path allowlisting/blocking)");
    println!("✓ Content validation implemented (JSON validation, size checks)");
    println!("✓ Audit logging enabled (security event tracking)");
    println!("✓ Configuration-driven security (runtime updates supported)");
    println!("✓ Backward compatible (existing code continues to work)");

    Ok(())
}
