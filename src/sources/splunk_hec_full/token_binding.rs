use std::collections::HashMap;
use std::path::Path;

use vector_lib::configurable::configurable_component;

/// Configuration for a single token binding entry.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct TokenBindingConfig {
    /// The default index for events received with this token.
    pub index: Option<String>,
    /// The default sourcetype for events received with this token.
    pub sourcetype: Option<String>,
    /// The default source for events received with this token.
    pub source: Option<String>,
}

/// Resolved token binding with metadata defaults.
#[derive(Clone, Debug)]
pub struct TokenBinding {
    pub index: Option<String>,
    pub sourcetype: Option<String>,
    pub source: Option<String>,
}

impl From<&TokenBindingConfig> for TokenBinding {
    fn from(config: &TokenBindingConfig) -> Self {
        TokenBinding {
            index: config.index.clone(),
            sourcetype: config.sourcetype.clone(),
            source: config.source.clone(),
        }
    }
}

/// Engine that resolves token strings to their metadata bindings.
#[derive(Clone, Debug, Default)]
pub struct TokenBindingEngine {
    bindings: HashMap<String, TokenBinding>,
}

impl TokenBindingEngine {
    /// Create from inline config bindings.
    pub fn from_config(config_bindings: &HashMap<String, TokenBindingConfig>) -> Self {
        let bindings = config_bindings
            .iter()
            .map(|(token, cfg)| (token.clone(), TokenBinding::from(cfg)))
            .collect();
        TokenBindingEngine { bindings }
    }

    /// Create from inputs.conf file content, merging with existing config bindings.
    /// Config bindings take precedence over inputs.conf bindings on conflict.
    pub fn from_config_and_inputs_conf(
        config_bindings: &HashMap<String, TokenBindingConfig>,
        inputs_conf_path: Option<&Path>,
    ) -> Result<Self, String> {
        let mut bindings: HashMap<String, TokenBinding> = HashMap::new();

        // Load from inputs.conf first (lower priority)
        if let Some(path) = inputs_conf_path {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read inputs.conf at {}: {}", path.display(), e))?;
            let parsed = parse_inputs_conf(&content)?;
            bindings.extend(parsed);
        }

        // Overlay config bindings (higher priority)
        for (token, cfg) in config_bindings {
            bindings.insert(token.clone(), TokenBinding::from(cfg));
        }

        Ok(TokenBindingEngine { bindings })
    }

    /// Resolve a token to its binding. The token should be the raw token string
    /// (without "Splunk " prefix).
    pub fn resolve(&self, token: &str) -> Option<&TokenBinding> {
        self.bindings.get(token)
    }

    /// Returns true if the engine has no bindings.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// Parse Splunk inputs.conf content into token bindings.
///
/// Format:
/// ```ini
/// [http://stanza_name]
/// disabled = 0
/// token = <uuid>
/// index = <index_name>
/// sourcetype = <sourcetype>
/// source = <source>
/// ```
///
/// Rules:
/// - Only `[http://...]` sections are processed (skip global `[http]` or other sections)
/// - Stanzas with `disabled = 1` or `disabled = true` are skipped
/// - Stanzas without a `token` field are skipped with a warning
pub fn parse_inputs_conf(content: &str) -> Result<HashMap<String, TokenBinding>, String> {
    let mut bindings = HashMap::new();
    let mut current_section: Option<String> = None;
    let mut current_token: Option<String> = None;
    let mut current_index: Option<String> = None;
    let mut current_sourcetype: Option<String> = None;
    let mut current_source: Option<String> = None;
    let mut current_disabled = false;

    let flush = |bindings: &mut HashMap<String, TokenBinding>,
                 section: &Option<String>,
                 token: &mut Option<String>,
                 index: &mut Option<String>,
                 sourcetype: &mut Option<String>,
                 source: &mut Option<String>,
                 disabled: &mut bool| {
        if let Some(_section_name) = section {
            if !*disabled {
                if let Some(tok) = token.take() {
                    bindings.insert(
                        tok,
                        TokenBinding {
                            index: index.take(),
                            sourcetype: sourcetype.take(),
                            source: source.take(),
                        },
                    );
                } else {
                    // No token in this stanza, skip it
                    *index = None;
                    *sourcetype = None;
                    *source = None;
                }
            } else {
                // Disabled stanza, reset all
                *token = None;
                *index = None;
                *sourcetype = None;
                *source = None;
            }
        }
        *disabled = false;
    };

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            // Flush previous section
            flush(
                &mut bindings,
                &current_section,
                &mut current_token,
                &mut current_index,
                &mut current_sourcetype,
                &mut current_source,
                &mut current_disabled,
            );

            let section_name = &line[1..line.len() - 1];
            // Only process [http://...] sections
            if section_name.starts_with("http://") {
                current_section = Some(section_name.to_string());
            } else {
                current_section = None;
            }
            continue;
        }

        // Only process key=value pairs if we're in a valid section
        if current_section.is_none() {
            continue;
        }

        // Parse key = value
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();

            match key.as_str() {
                "disabled" => {
                    current_disabled = value == "1" || value.eq_ignore_ascii_case("true");
                }
                "token" => {
                    current_token = Some(value);
                }
                "index" => {
                    current_index = Some(value);
                }
                "sourcetype" => {
                    current_sourcetype = Some(value);
                }
                "source" => {
                    current_source = Some(value);
                }
                _ => {
                    // Ignore other fields (indexes, connection_host, etc.)
                }
            }
        }
    }

    // Flush last section
    flush(
        &mut bindings,
        &current_section,
        &mut current_token,
        &mut current_index,
        &mut current_sourcetype,
        &mut current_source,
        &mut current_disabled,
    );

    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_inputs_conf_basic() {
        let content = r#"
[http]
disabled = 0
port = 8088

[http://honeypot]
disabled = 0
token = 942b6b3a-dca4-466e-8513-bdada8797549
index = kp_security_honeypot
sourcetype = honeypot_api
indexes = kp_security_honeypot

[http://prometheus_metric]
disabled = 0
token = 8f91673f-b8bd-42c8-aaa6-ecca2eeec988
index = kp_security_prometheus_metric
"#;

        let bindings = parse_inputs_conf(content).unwrap();
        assert_eq!(bindings.len(), 2);

        let honeypot = bindings
            .get("942b6b3a-dca4-466e-8513-bdada8797549")
            .unwrap();
        assert_eq!(honeypot.index.as_deref(), Some("kp_security_honeypot"));
        assert_eq!(honeypot.sourcetype.as_deref(), Some("honeypot_api"));
        assert_eq!(honeypot.source, None);

        let prometheus = bindings
            .get("8f91673f-b8bd-42c8-aaa6-ecca2eeec988")
            .unwrap();
        assert_eq!(
            prometheus.index.as_deref(),
            Some("kp_security_prometheus_metric")
        );
        assert_eq!(prometheus.sourcetype, None);
    }

    #[test]
    fn test_parse_inputs_conf_disabled_stanza() {
        let content = r#"
[http://disabled_input]
disabled = 1
token = aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
index = should_not_appear

[http://enabled_input]
disabled = 0
token = 11111111-2222-3333-4444-555555555555
index = active_index
"#;

        let bindings = parse_inputs_conf(content).unwrap();
        assert_eq!(bindings.len(), 1);
        assert!(!bindings.contains_key("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

        let active = bindings
            .get("11111111-2222-3333-4444-555555555555")
            .unwrap();
        assert_eq!(active.index.as_deref(), Some("active_index"));
    }

    #[test]
    fn test_parse_inputs_conf_no_token() {
        let content = r#"
[http://no_token_stanza]
disabled = 0
index = orphan_index
sourcetype = orphan_type
"#;

        let bindings = parse_inputs_conf(content).unwrap();
        assert_eq!(bindings.len(), 0);
    }

    #[test]
    fn test_parse_inputs_conf_comments_and_empty_lines() {
        let content = r#"
# This is a comment
; This is also a comment

[http://test]
disabled = 0
token = test-token-123
index = test_index
# inline comment section
sourcetype = test_type
"#;

        let bindings = parse_inputs_conf(content).unwrap();
        assert_eq!(bindings.len(), 1);
        let binding = bindings.get("test-token-123").unwrap();
        assert_eq!(binding.index.as_deref(), Some("test_index"));
        assert_eq!(binding.sourcetype.as_deref(), Some("test_type"));
    }

    #[test]
    fn test_token_binding_engine_from_config() {
        let mut config_bindings = HashMap::new();
        config_bindings.insert(
            "token-a".to_string(),
            TokenBindingConfig {
                index: Some("index_a".to_string()),
                sourcetype: Some("type_a".to_string()),
                source: None,
            },
        );

        let engine = TokenBindingEngine::from_config(&config_bindings);
        let binding = engine.resolve("token-a").unwrap();
        assert_eq!(binding.index.as_deref(), Some("index_a"));
        assert_eq!(binding.sourcetype.as_deref(), Some("type_a"));
        assert!(engine.resolve("nonexistent").is_none());
    }

    #[test]
    fn test_token_binding_engine_empty() {
        let engine = TokenBindingEngine::from_config(&HashMap::new());
        assert!(engine.is_empty());
        assert!(engine.resolve("any-token").is_none());
    }
}
