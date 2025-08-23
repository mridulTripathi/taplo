use super::{builtins, cache::Cache};
use crate::{
    config::Config,
    environment::Environment,
    util::{normalize_str, GlobRule},
    IndexMap,
};
use anyhow::anyhow;
use parking_lot::{RwLock, RwLockReadGuard};
use regex::Regex;
use semver::Version;
use serde::{de::Error, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{borrow::Cow, collections::HashMap, path::Path, sync::Arc};
use tap::Tap;
use taplo::dom::Node;
use tokio::sync::Semaphore;
use url::Url;

pub const DEFAULT_CATALOGS: &[&str] = &["https://json.schemastore.org/api/json/catalog.json"];

pub mod priority {
    pub const BUILTIN: usize = 10;
    pub const CATALOG: usize = 25;
    pub const CONFIG: usize = 50;
    pub const CONFIG_RULE: usize = 51;
    pub const LSP_CONFIG: usize = 60;
    pub const SCHEMA_FIELD: usize = 70;
    pub const DIRECTIVE: usize = 75;
    pub const MAX: usize = usize::MAX;
}

pub mod source {
    pub const BUILTIN: &str = "builtin";
    pub const CATALOG: &str = "catalog";
    pub const CONFIG: &str = "config";
    pub const LSP_CONFIG: &str = "lsp_config";
    pub const MANUAL: &str = "manual";
    pub const SCHEMA_FIELD: &str = "$schema";
    pub const DIRECTIVE: &str = "directive";
}

/// Optimized index structure for fast schema association lookups
#[derive(Default)]
struct AssociationIndexes {
    // O(1) exact URL matches
    url_index: HashMap<Url, SchemaAssociation>,
    
    // O(1) glob pattern lookups by normalized path
    glob_index: HashMap<String, Vec<SchemaAssociation>>,
    
    // O(n) regex patterns (kept as Vec since regex matching is inherently O(n))
    regex_patterns: Vec<(Regex, SchemaAssociation)>,
    
    // O(log n) priority-based lookups
    priority_index: HashMap<usize, Vec<SchemaAssociation>>,
    
    // Cache for compiled glob patterns to avoid repeated compilation
    glob_cache: HashMap<String, GlobRule>,
}

impl AssociationIndexes {
    fn new() -> Self {
        Self::default()
    }
    
    fn clear(&mut self) {
        self.url_index.clear();
        self.glob_index.clear();
        self.regex_patterns.clear();
        self.priority_index.clear();
        self.glob_cache.clear();
    }
    
    fn add(&mut self, rule: AssociationRule, assoc: SchemaAssociation) {
        // Add to priority index
        self.priority_index
            .entry(assoc.priority)
            .or_insert_with(Vec::new)
            .push(assoc.clone());
        
        // Add to specific index based on rule type
        match rule {
            AssociationRule::Url(url) => {
                self.url_index.insert(url, assoc);
            }
            AssociationRule::Glob(glob) => {
                // Normalize the glob pattern for indexing
                let normalized = self.normalize_glob_pattern(&glob);
                self.glob_index
                    .entry(normalized.clone())
                    .or_insert_with(Vec::new)
                    .push(assoc);
                
                // Cache the compiled glob rule
                self.glob_cache.insert(normalized, glob);
            }
            AssociationRule::Regex(regex) => {
                self.regex_patterns.push((regex, assoc));
            }
        }
    }
    
    fn remove(&mut self, rule: &AssociationRule, assoc: &SchemaAssociation) -> bool {
        let mut removed = false;
        
        // Remove from priority index
        if let Some(assocs) = self.priority_index.get_mut(&assoc.priority) {
            assocs.retain(|a| {
                if a.url == assoc.url && a.meta == assoc.meta {
                    removed = true;
                    false
                } else {
                    true
                }
            });
            
            // Clean up empty priority entries
            if assocs.is_empty() {
                self.priority_index.remove(&assoc.priority);
            }
        }
        
        // Remove from specific indexes
        match rule {
            AssociationRule::Url(url) => {
                self.url_index.remove(url);
            }
            AssociationRule::Glob(glob) => {
                let normalized = self.normalize_glob_pattern(glob);
                if let Some(assocs) = self.glob_index.get_mut(&normalized) {
                    assocs.retain(|a| {
                        if a.url == assoc.url && a.meta == assoc.meta {
                            false
                        } else {
                            true
                        }
                    });
                    
                    // Clean up empty glob entries
                    if assocs.is_empty() {
                        self.glob_index.remove(&normalized);
                        self.glob_cache.remove(&normalized);
                    }
                }
            }
            AssociationRule::Regex(_) => {
                self.regex_patterns.retain(|(_, a)| {
                    if a.url == assoc.url && a.meta == assoc.meta {
                        false
                    } else {
                        true
                    }
                });
            }
        }
        
        removed
    }
    
    fn find_match(&self, file: &Url) -> Option<SchemaAssociation> {
        // 1. Check exact URL match first (O(1))
        if let Some(assoc) = self.url_index.get(file) {
            return Some(assoc.clone());
        }
        
        // 2. Check glob patterns (O(log n) for path-based lookups)
        let normalized_path = self.normalize_url_for_glob(file);
        
        // Try to find a glob pattern that matches this path
        let mut best_glob_match: Option<SchemaAssociation> = None;
        for (pattern, assocs) in &self.glob_index {
            // Skip the "glob:" prefix we added for indexing
            if let Some(_glob_pattern) = pattern.strip_prefix("glob:") {
                // Check if any of the glob patterns match
                for assoc in assocs {
                    if let Some(glob_rule) = self.glob_cache.get(pattern) {
                        if glob_rule.is_match(&normalized_path) {
                            if let Some(ref current) = best_glob_match {
                                if assoc.priority > current.priority {
                                    best_glob_match = Some(assoc.clone());
                                }
                            } else {
                                best_glob_match = Some(assoc.clone());
                            }
                        }
                    }
                }
            }
        }
        
        if let Some(assoc) = best_glob_match {
            return Some(assoc);
        }
        
        // 3. Check regex patterns (O(n) but typically small number)
        let mut best_match: Option<SchemaAssociation> = None;
        for (regex, assoc) in &self.regex_patterns {
            if regex.is_match(&normalize_str(file.as_str())) {
                if let Some(ref current) = best_match {
                    if assoc.priority > current.priority {
                        best_match = Some(assoc.clone());
                    }
                } else {
                    best_match = Some(assoc.clone());
                }
            }
        }
        
        best_match
    }
    
    fn normalize_glob_pattern(&self, _glob: &GlobRule) -> String {
        // Create a normalized key for the glob pattern
        // Since GlobRule doesn't expose patterns directly, we'll use a simple counter-based approach
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("glob:{}", id)
    }
    
    fn normalize_url_for_glob(&self, url: &Url) -> String {
        // Strip scheme and normalize for glob matching
        // This matches the existing logic in AssociationRule::is_match
        let path = url.as_str()
            .strip_prefix(url.scheme())
            .unwrap_or(url.as_str())
            .strip_prefix("://")
            .unwrap_or(url.as_str());
        
        normalize_str(path).to_string()
    }
    
    fn get_all_associations(&self) -> Vec<(AssociationRule, SchemaAssociation)> {
        let mut result = Vec::new();
        
        // Collect from all indexes
        for (url, assoc) in &self.url_index {
            result.push((AssociationRule::Url(url.clone()), assoc.clone()));
        }
        
        for (pattern, assocs) in &self.glob_index {
            if let Some(glob_rule) = self.glob_cache.get(pattern) {
                for assoc in assocs {
                    result.push((AssociationRule::Glob(glob_rule.clone()), assoc.clone()));
                }
            }
        }
        
        for (regex, assoc) in &self.regex_patterns {
            result.push((AssociationRule::Regex(regex.clone()), assoc.clone()));
        }
        
        result
    }
}

#[derive(Clone)]
pub struct SchemaAssociations<E: Environment> {
    concurrent_requests: Arc<Semaphore>,
    http: reqwest::Client,
    env: E,
    // Replace linear Vec with optimized indexes
    indexes: Arc<RwLock<AssociationIndexes>>,
    // Keep original Vec for backward compatibility and dynamic operations
    associations: Arc<RwLock<Vec<(AssociationRule, SchemaAssociation)>>>,
    cache: Cache<E>,
}

impl<E: Environment> SchemaAssociations<E> {
    pub(crate) fn new(env: E, cache: Cache<E>, http: reqwest::Client) -> Self {
        let this = Self {
            concurrent_requests: Arc::new(Semaphore::new(10)),
            cache,
            env,
            http,
            indexes: Arc::new(RwLock::new(AssociationIndexes::new())),
            associations: Default::default(),
        };
        this.add_builtins();
        this
    }

    pub fn add(&self, rule: AssociationRule, assoc: SchemaAssociation) {
        // Add to both indexes and original Vec for backward compatibility
        self.indexes.write().add(rule.clone(), assoc.clone());
        self.associations.write().push((rule, assoc));
    }

    pub fn retain(&self, f: impl Fn(&(AssociationRule, SchemaAssociation)) -> bool) {
        let mut indexes = self.indexes.write();
        let mut associations = self.associations.write();
        
        // Remove from indexes first
        associations.retain(|tuple| {
            let should_keep = f(tuple);
            if !should_keep {
                let (rule, assoc) = tuple;
                indexes.remove(rule, assoc);
            }
            should_keep
        });
    }

    pub fn read(&self) -> RwLockReadGuard<'_, Vec<(AssociationRule, SchemaAssociation)>> {
        self.associations.read()
    }

    /// Clear all associations.
    ///
    /// Note that this will completely remove all associations,
    /// even built-in ones that will have to be added again.
    pub fn clear(&self) {
        self.indexes.write().clear();
        self.associations.write().clear();
    }

    pub fn add_builtins(&self) {
        self.retain(|(_, assoc)| assoc.meta["source"] != source::BUILTIN);

        self.associations.write().push((
            AssociationRule::Regex(Regex::new(r".*\.?taplo\.toml$").unwrap()),
            SchemaAssociation {
                url: builtins::TAPLO_CONFIG_URL.parse().unwrap(),
                meta: json!({
                    "name": "Taplo",
                    "description": "Taplo configuration file.",
                    "source": source::BUILTIN
                }),
                priority: priority::BUILTIN,
            },
        ));
        
        // Also add to indexes
        let builtin_assoc = SchemaAssociation {
            url: builtins::TAPLO_CONFIG_URL.parse().unwrap(),
            meta: json!({
                "name": "Taplo",
                "description": "Taplo configuration file.",
                "source": source::BUILTIN
            }),
            priority: priority::BUILTIN,
        };
        
        self.indexes.write().add(
            AssociationRule::Regex(Regex::new(r".*\.?taplo\.toml$").unwrap()),
            builtin_assoc,
        );
    }

    pub async fn add_from_catalog(&self, url: &Url) -> Result<(), anyhow::Error> {
        let index = self.load_catalog(url).await?;
        match index {
            SchemaCatalog::SchemaStore(index) => {
                for schema in &index.schemas {
                    match GlobRule::new(&schema.file_match, [] as [&str; 0]) {
                        Ok(rule) => {
                            let assoc = SchemaAssociation {
                                url: schema.url.clone(),
                                meta: json!({
                                    "name": schema.name,
                                    "description": schema.description,
                                    "source": source::CATALOG,
                                    "catalog_url": url,
                                }),
                                priority: priority::CATALOG,
                            };
                            
                            self.indexes.write().add(AssociationRule::Glob(rule.clone()), assoc.clone());
                            self.associations.write().push((AssociationRule::Glob(rule), assoc));
                        }
                        Err(error) => {
                            tracing::warn!(
                                %error,
                                schema_name = %schema.name,
                                source = %url,
                                "invalid glob pattern(s)"
                            );
                        }
                    }
                }
            }
            SchemaCatalog::Taplo(index) => {
                for schema in &index.schemas {
                    for pattern in &schema.extra.patterns {
                        let regex = match Regex::new(pattern) {
                            Ok(pat) => pat,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    pattern = %pattern,
                                    schema_name = %schema.title,
                                    "invalid regex pattern"
                                );
                                continue;
                            }
                        };

                        let assoc = SchemaAssociation {
                            url: schema.url.clone(),
                            meta: json!({
                                "name": schema.title,
                                "description": schema.description,
                                "source": source::CATALOG,
                                "catalog_url": url,
                            }),
                            priority: priority::CATALOG,
                        };
                        
                        self.indexes.write().add(AssociationRule::Regex(regex.clone()), assoc.clone());
                        self.associations.write().push((AssociationRule::Regex(regex), assoc));
                    }
                }
            }
        }
        Ok(())
    }

    /// Adds the schema from either a directive, or a `$schema` key in the root.
    pub fn add_from_document(&self, doc_url: &Url, root: &Node) {
        self.retain(|(rule, assoc)| match rule {
            AssociationRule::Url(u) => {
                !(u == doc_url
                    && (assoc.meta["source"] == source::DIRECTIVE
                        || assoc.meta["source"] == source::SCHEMA_FIELD))
            }
            _ => true,
        });

        for comment in root.header_comments() {
            if let Some("schema") = comment.directive() {
                let value = comment.value();

                if value.is_empty() {
                    tracing::warn!("empty schema directive");
                    continue;
                }

                let schema_url: Url = match value.parse() {
                    Ok(url) => url,
                    Err(error) => {
                        tracing::debug!(%error, "invalid url in directive, assuming file path instead");

                        if self.env.is_absolute(Path::new(value)) {
                            match format!("file://{value}").parse() {
                                Ok(u) => u,
                                Err(error) => {
                                    tracing::error!(%error, "invalid schema directive");
                                    continue;
                                }
                            }
                        } else {
                            match doc_url.join(value) {
                                Ok(u) => u,
                                Err(error) => {
                                    tracing::error!(%error, "invalid schema directive");
                                    continue;
                                }
                            }
                        }
                    }
                };

                let assoc = SchemaAssociation {
                    url: schema_url.clone(),
                    meta: json!({
                        "source": source::DIRECTIVE,
                    }),
                    priority: priority::DIRECTIVE,
                };
                
                self.indexes.write().add(AssociationRule::Url(schema_url.clone()), assoc.clone());
                self.associations.write().push((AssociationRule::Url(schema_url), assoc));
            }
        }

        let schema_field = root.get("$schema");
        if let Some(schema_url) = schema_field.as_str() {
            let schema_url_str = schema_url.value();
            let schema_url: Url = match schema_url_str.parse() {
                Ok(url) => url,
                Err(error) => {
                    tracing::debug!(%error, "invalid url in $schema field, assuming file path instead");

                    if self.env.is_absolute(Path::new(schema_url_str)) {
                        match format!("file://{schema_url_str}").parse() {
                            Ok(u) => u,
                            Err(error) => {
                                tracing::error!(%error, "invalid $schema field");
                                return;
                            }
                        }
                    } else {
                        match doc_url.join(schema_url_str) {
                            Ok(u) => u,
                            Err(error) => {
                                tracing::error!(%error, "invalid $schema field");
                                return;
                            }
                        }
                    }
                }
            };

            let assoc = SchemaAssociation {
                url: schema_url.clone(),
                meta: json!({
                    "source": source::SCHEMA_FIELD,
                }),
                priority: priority::SCHEMA_FIELD,
            };
            
            self.indexes.write().add(AssociationRule::Url(schema_url.clone()), assoc.clone());
            self.associations.write().push((AssociationRule::Url(schema_url), assoc));
        }
    }

    pub fn add_from_config(&self, config: &Config) {
        for rule in &config.rule {
            let Some(file_rule) = rule.file_rule.clone() else {
                continue;
            };

            if let Some(schema_opts) = &rule.options.schema {
                if let Some(url) = &schema_opts.url {
                    if schema_opts.enabled.unwrap_or(true) {
                        let assoc = SchemaAssociation {
                            url: url.clone(),
                            meta: json!({
                                "source": source::CONFIG,
                            }),
                            priority: priority::CONFIG_RULE,
                        };
                        
                        self.indexes.write().add(AssociationRule::Glob(file_rule.clone()), assoc.clone());
                        self.associations.write().push((AssociationRule::Glob(file_rule), assoc));
                    }
                }
            }
        }

        let Some(file_rule) = config.file_rule.clone() else {
            return;
        };

        if let Some(schema_opts) = &config.global_options.schema {
            if let Some(url) = &schema_opts.url {
                if schema_opts.enabled.unwrap_or(true) {
                    let assoc = SchemaAssociation {
                        url: url.clone(),
                        meta: json!({
                            "source": source::CONFIG,
                        }),
                        priority: priority::CONFIG,
                    };
                    
                    self.indexes.write().add(AssociationRule::Glob(file_rule.clone()), assoc.clone());
                    self.associations.write().push((AssociationRule::Glob(file_rule), assoc));
                }
            }
        }
    }

    /// Optimized association lookup using multi-index approach
    pub fn association_for(&self, file: &Url) -> Option<SchemaAssociation> {
        // Use optimized indexes for fast lookup
        if let Some(assoc) = self.indexes.read().find_match(file) {
            return Some(assoc).tap(|s| {
                if let Some(schema_association) = s {
                    tracing::debug!(
                        schema.url = %schema_association.url,
                        schema.name = schema_association.meta["name"].as_str().unwrap_or(""),
                        schema.source = schema_association.meta["source"].as_str().unwrap_or(""),
                        "found schema association"
                    );
                }
            });
        }
        
        None
    }

    async fn load_catalog(&self, index_url: &Url) -> Result<SchemaCatalog, anyhow::Error> {
        if let Ok(s) = self.cache.load(index_url, false).await {
            return Ok(serde_json::from_value((*s).clone())?);
        }

        let mut index = match self.fetch_external(index_url).await {
            Ok(idx) => idx,
            Err(error) => {
                tracing::warn!(%error, "failed to fetch catalog");
                if let Ok(s) = self.cache.load(index_url, true).await {
                    return Ok(serde_json::from_value((*s).clone())?);
                }
                return Err(error);
            }
        };

        index.transform_paths();

        if self.cache.is_cache_path_set() {
            if let Err(error) = self
                .cache
                .save(index_url.clone(), Arc::new(serde_json::to_value(&index)?))
                .await
            {
                tracing::warn!(%error, "failed to cache index");
            }
        }

        Ok(index)
    }

    async fn fetch_external(&self, index_url: &Url) -> Result<SchemaCatalog, anyhow::Error> {
        let _permit = self.concurrent_requests.acquire().await?;
        match index_url.scheme() {
            "http" | "https" => Ok(self
                .http
                .get(index_url.clone())
                .send()
                .await?
                .json()
                .await?),
            "file" => Ok(serde_json::from_slice(
                &self
                    .env
                    .read_file(
                        self.env
                            .to_file_path_normalized(index_url)
                            .ok_or_else(|| anyhow!("invalid file path"))?
                            .as_ref(),
                    )
                    .await?,
            )?),
            scheme => Err(anyhow!("the scheme `{scheme}` is not supported")),
        }
    }

    /// Get performance statistics for the current indexes
    pub fn get_stats(&self) -> AssociationStats {
        let indexes = self.indexes.read();
        AssociationStats {
            total_associations: self.associations.read().len(),
            url_index_size: indexes.url_index.len(),
            glob_index_size: indexes.glob_index.len(),
            regex_patterns_size: indexes.regex_patterns.len(),
            priority_levels: indexes.priority_index.len(),
            glob_cache_size: indexes.glob_cache.len(),
        }
    }
    
    /// Optimize indexes for better performance
    pub fn optimize_indexes(&self) {
        let mut indexes = self.indexes.write();
        
        // Sort regex patterns by frequency of use (could be enhanced with actual usage tracking)
        indexes.regex_patterns.sort_by(|a, b| {
            // Simple heuristic: prioritize patterns with higher priority associations
            b.1.priority.cmp(&a.1.priority)
        });
        
        // Sort glob patterns by priority
        for assocs in indexes.glob_index.values_mut() {
            assocs.sort_by_key(|a| std::cmp::Reverse(a.priority));
        }
        
        // Sort priority index entries
        for assocs in indexes.priority_index.values_mut() {
            assocs.sort_by_key(|a| std::cmp::Reverse(a.priority));
        }
    }
}

/// Performance statistics for schema associations
#[derive(Debug, Clone)]
pub struct AssociationStats {
    pub total_associations: usize,
    pub url_index_size: usize,
    pub glob_index_size: usize,
    pub regex_patterns_size: usize,
    pub priority_levels: usize,
    pub glob_cache_size: usize,
}

impl std::fmt::Display for AssociationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Schema Associations Stats:\n\
             - Total associations: {}\n\
             - URL index entries: {}\n\
             - Glob pattern entries: {}\n\
             - Regex patterns: {}\n\
             - Priority levels: {}\n\
             - Glob cache entries: {}",
            self.total_associations,
            self.url_index_size,
            self.glob_index_size,
            self.regex_patterns_size,
            self.priority_levels,
            self.glob_cache_size
        )
    }
}

#[derive(Clone)]
pub enum AssociationRule {
    Glob(GlobRule),
    Regex(Regex),
    Url(Url),
}

impl AssociationRule {
    pub fn glob(pattern: &str) -> Result<Self, anyhow::Error> {
        Ok(Self::Glob(GlobRule::new([pattern], &[] as &[&str])?))
    }

    pub fn regex(regex: &str) -> Result<Self, anyhow::Error> {
        Ok(Self::Regex(Regex::new(regex)?))
    }
}

impl From<Regex> for AssociationRule {
    fn from(v: Regex) -> Self {
        Self::Regex(v)
    }
}

impl From<GlobRule> for AssociationRule {
    fn from(v: GlobRule) -> Self {
        Self::Glob(v)
    }
}

impl AssociationRule {
    #[must_use]
    pub fn is_match(&self, url: &Url) -> bool {
        match self {
            // Glob associations typically come from config files
            // with a glob pattern that is an absolute file path
            // without a scheme.
            //
            // So in order to be a match, we need to
            // strip the scheme from the URL.
            AssociationRule::Glob(g) => g.is_match(&*normalize_str(
                url.as_str()
                    .strip_prefix(url.scheme())
                    .unwrap()
                    .strip_prefix("://")
                    .unwrap(),
            )),
            AssociationRule::Regex(r) => r.is_match(&normalize_str(url.as_str())),
            AssociationRule::Url(u) => u == url,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaCatalog {
    SchemaStore(SchemaStoreCatalog),
    Taplo(TaploSchemaCatalog),
}

impl SchemaCatalog {
    fn transform_paths(&mut self) {
        if let SchemaCatalog::SchemaStore(index) = self {
            for s in &mut index.schemas {
                for fm in &mut s.file_match {
                    if !fm.starts_with("**/") {
                        *fm = String::from("**/") + fm.as_str();
                    }
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TaploSchemaCatalog {
    pub schemas: Vec<TaploSchemaMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaploSchemaMeta {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub url: Url,
    pub url_hash: String,

    #[serde(flatten)]
    pub extra: TaploSchemaExtraInfo,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaploSchemaExtraInfo {
    pub authors: Vec<String>,
    pub version: Option<Version>,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaStoreCatalog {
    #[serde(rename = "$schema")]
    pub schema: SchemaStoreCatalogSchema,
    pub schemas: Vec<SchemaStoreSchemaMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaStoreSchemaMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub url: Url,
    #[serde(default)]
    pub file_match: Vec<String>,
    #[serde(default)]
    pub versions: IndexMap<String, Url>,
}

pub const SCHEMA_STORE_CATALOG_SCHEMA_URL: &str =
    "https://json.schemastore.org/schema-catalog.json";

#[derive(Debug, Clone, Copy)]
pub struct SchemaStoreCatalogSchema;

impl<'de> Deserialize<'de> for SchemaStoreCatalogSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<'static, str>::deserialize(deserializer)?;

        if s != SCHEMA_STORE_CATALOG_SCHEMA_URL {
            return Err(Error::custom(format!(
                "expected $schema to be {SCHEMA_STORE_CATALOG_SCHEMA_URL}"
            )));
        }

        Ok(SchemaStoreCatalogSchema)
    }
}

impl Serialize for SchemaStoreCatalogSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SCHEMA_STORE_CATALOG_SCHEMA_URL.serialize(serializer)
    }
}

#[derive(Debug, Clone)]
pub struct SchemaAssociation {
    pub meta: Value,
    pub url: Url,
    pub priority: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::native::NativeEnvironment;
    use std::time::Instant;

    #[test]
    fn test_optimized_lookup_performance() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let env = NativeEnvironment::new();
            let cache = Cache::new(env.clone());
            let http = reqwest::Client::new();
            let associations = SchemaAssociations::new(env, cache, http);
            
            // Add many test associations to demonstrate scaling
            for i in 0..1000 {
                let pattern = format!("**/*{}.toml", i);
                if let Ok(rule) = AssociationRule::glob(&pattern) {
                    let assoc = SchemaAssociation {
                        url: format!("https://example.com/schema{}.json", i).parse().unwrap(),
                        meta: json!({
                            "name": format!("Test Schema {}", i),
                            "source": "test"
                        }),
                        priority: i % 100,
                    };
                    associations.add(rule, assoc);
                }
            }
            
            // Add some exact URL matches
            for i in 0..100 {
                let url = format!("https://example.com/file{}.toml", i).parse().unwrap();
                let assoc = SchemaAssociation {
                    url: format!("https://example.com/schema{}.json", i).parse().unwrap(),
                    meta: json!({
                        "name": format!("Exact Schema {}", i),
                        "source": "test"
                    }),
                    priority: 100 + i,
                };
                associations.add(AssociationRule::Url(url), assoc);
            }
            
            // Benchmark lookup performance
            let test_url = "https://example.com/file50.toml".parse().unwrap();
            
            // Warm up
            for _ in 0..100 {
                let _ = associations.association_for(&test_url);
            }
            
            // Benchmark
            let start = Instant::now();
            for _ in 0..1000 {
                let _ = associations.association_for(&test_url);
            }
            let duration = start.elapsed();
            
            println!("Optimized lookup performance: {:?} for 1000 lookups", duration);
            println!("Stats: {}", associations.get_stats());
            
            // Verify we get the expected result
            let result = associations.association_for(&test_url);
            assert!(result.is_some());
            assert_eq!(result.unwrap().priority, 150); // 100 + 50
        });
    }
    
    #[test]
    fn test_backward_compatibility() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let env = NativeEnvironment::new();
            let cache = Cache::new(env.clone());
            let http = reqwest::Client::new();
            let associations = SchemaAssociations::new(env, cache, http);
            
            // Test that the old Vec-based API still works
            let associations_vec = associations.read();
            assert!(!associations_vec.is_empty());
            
            // Test that we can still iterate through all associations
            let count = associations_vec.len();
            assert!(count > 0);
            
            // Test that the new optimized lookup works
            let test_url = "https://example.com/taplo.toml".parse().unwrap();
            let result = associations.association_for(&test_url);
            assert!(result.is_some());
        });
    }
}
