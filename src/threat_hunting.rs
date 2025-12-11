//! Threat Hunting Module v2.0
//!
//! Proactive threat hunting capabilities with hypothesis-driven
//! investigation, IOC sweeps, and hunt playbooks.

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::LogEntry;

/// Hunt status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HuntStatus {
    Draft,
    Active,
    Paused,
    Completed,
    Archived,
}

/// Hunt result classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HuntResultType {
    NoFindings,
    FalsePositive,
    TruePositive,
    RequiresInvestigation,
    Inconclusive,
}

/// Threat hunt definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHunt {
    pub id: String,
    pub name: String,
    pub hypothesis: String,
    pub description: String,
    pub status: HuntStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub owner: String,
    pub mitre_techniques: Vec<String>,
    pub data_sources: Vec<String>,
    pub queries: Vec<HuntQuery>,
    pub findings: Vec<HuntFinding>,
    pub timeline: Vec<HuntTimelineEntry>,
}

/// Hunt query definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntQuery {
    pub id: String,
    pub name: String,
    pub description: String,
    pub query_type: QueryType,
    pub pattern: String,
    pub data_source: String,
    pub expected_results: String,
}

/// Query types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryType {
    Regex,
    Keyword,
    Statistical,
    Behavioral,
    IOC,
}

/// Hunt finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntFinding {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub query_id: String,
    pub result_type: HuntResultType,
    pub description: String,
    pub evidence: Vec<String>,
    pub affected_assets: Vec<String>,
    pub severity: FindingSeverity,
    pub recommendations: Vec<String>,
}

/// Finding severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Hunt timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntTimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub details: String,
}

impl ThreatHunt {
    /// Create new threat hunt
    pub fn new(name: &str, hypothesis: &str, owner: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            hypothesis: hypothesis.to_string(),
            description: String::new(),
            status: HuntStatus::Draft,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            owner: owner.to_string(),
            mitre_techniques: Vec::new(),
            data_sources: Vec::new(),
            queries: Vec::new(),
            findings: Vec::new(),
            timeline: vec![HuntTimelineEntry {
                timestamp: Utc::now(),
                action: "Created".to_string(),
                actor: owner.to_string(),
                details: "Hunt created".to_string(),
            }],
        }
    }

    /// Start the hunt
    pub fn start(&mut self, actor: &str) {
        self.status = HuntStatus::Active;
        self.started_at = Some(Utc::now());
        self.add_timeline_entry("Started", actor, "Hunt execution started");
    }

    /// Pause the hunt
    pub fn pause(&mut self, actor: &str, reason: &str) {
        self.status = HuntStatus::Paused;
        self.add_timeline_entry("Paused", actor, reason);
    }

    /// Complete the hunt
    pub fn complete(&mut self, actor: &str, summary: &str) {
        self.status = HuntStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.add_timeline_entry("Completed", actor, summary);
    }

    /// Add query to hunt
    pub fn add_query(&mut self, query: HuntQuery) {
        self.queries.push(query);
    }

    /// Add finding to hunt
    pub fn add_finding(&mut self, finding: HuntFinding) {
        self.findings.push(finding);
    }

    /// Add timeline entry
    pub fn add_timeline_entry(&mut self, action: &str, actor: &str, details: &str) {
        self.timeline.push(HuntTimelineEntry {
            timestamp: Utc::now(),
            action: action.to_string(),
            actor: actor.to_string(),
            details: details.to_string(),
        });
    }

    /// Get hunt duration
    pub fn duration(&self) -> Option<Duration> {
        let start = self.started_at?;
        let end = self.completed_at.unwrap_or_else(Utc::now);
        Some(end - start)
    }

    /// Count findings by type
    pub fn count_findings_by_type(&self) -> HashMap<HuntResultType, usize> {
        let mut counts = HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.result_type).or_insert(0) += 1;
        }
        counts
    }
}

/// IOC (Indicator of Compromise) for hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntIOC {
    pub indicator: String,
    pub ioc_type: IOCType,
    pub description: String,
    pub confidence: f32,
    pub source: String,
    pub tags: Vec<String>,
}

/// IOC types for hunting
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IOCType {
    IPAddress,
    Domain,
    URL,
    FileHash,
    FileName,
    Registry,
    EmailAddress,
    UserAgent,
    ProcessName,
    Command,
}

/// Threat hunting engine
pub struct ThreatHuntingEngine {
    hunts: HashMap<String, ThreatHunt>,
    ioc_database: Vec<HuntIOC>,
    hunt_templates: Vec<HuntTemplate>,
}

/// Hunt template for common scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub hypothesis_template: String,
    pub mitre_techniques: Vec<String>,
    pub suggested_queries: Vec<HuntQuery>,
    pub data_sources: Vec<String>,
}

impl ThreatHuntingEngine {
    /// Create new threat hunting engine
    pub fn new() -> Self {
        let mut engine = Self {
            hunts: HashMap::new(),
            ioc_database: Vec::new(),
            hunt_templates: Vec::new(),
        };
        engine.load_default_templates();
        engine
    }

    /// Load default hunt templates
    fn load_default_templates(&mut self) {
        // Lateral Movement Hunt Template
        self.hunt_templates.push(HuntTemplate {
            id: "TMPL-001".to_string(),
            name: "Lateral Movement Detection".to_string(),
            description: "Hunt for signs of lateral movement within the network".to_string(),
            hypothesis_template: "An attacker may be moving laterally using {{technique}}"
                .to_string(),
            mitre_techniques: vec![
                "T1021".to_string(),
                "T1076".to_string(),
                "T1077".to_string(),
            ],
            suggested_queries: vec![
                HuntQuery {
                    id: "Q-001".to_string(),
                    name: "RDP Connections".to_string(),
                    description: "Find unusual RDP connections".to_string(),
                    query_type: QueryType::Regex,
                    pattern: r"(?i)(rdp|3389|remote\s+desktop)".to_string(),
                    data_source: "network_logs".to_string(),
                    expected_results: "RDP connection events".to_string(),
                },
                HuntQuery {
                    id: "Q-002".to_string(),
                    name: "PsExec Usage".to_string(),
                    description: "Detect PsExec and similar tools".to_string(),
                    query_type: QueryType::Regex,
                    pattern: r"(?i)(psexec|psexesvc|paexec)".to_string(),
                    data_source: "process_logs".to_string(),
                    expected_results: "PsExec execution events".to_string(),
                },
            ],
            data_sources: vec![
                "network_logs".to_string(),
                "auth_logs".to_string(),
                "process_logs".to_string(),
            ],
        });

        // Credential Theft Hunt Template
        self.hunt_templates.push(HuntTemplate {
            id: "TMPL-002".to_string(),
            name: "Credential Theft Detection".to_string(),
            description: "Hunt for credential dumping and theft activities".to_string(),
            hypothesis_template: "Credentials may have been compromised via {{method}}".to_string(),
            mitre_techniques: vec!["T1003".to_string(), "T1110".to_string()],
            suggested_queries: vec![
                HuntQuery {
                    id: "Q-003".to_string(),
                    name: "LSASS Access".to_string(),
                    description: "Detect processes accessing LSASS".to_string(),
                    query_type: QueryType::Regex,
                    pattern: r"(?i)(lsass|mimikatz|sekurlsa)".to_string(),
                    data_source: "process_logs".to_string(),
                    expected_results: "LSASS access events".to_string(),
                },
                HuntQuery {
                    id: "Q-004".to_string(),
                    name: "Failed Auth Spike".to_string(),
                    description: "Find spikes in failed authentication".to_string(),
                    query_type: QueryType::Statistical,
                    pattern: "failed_auth_count > baseline * 3".to_string(),
                    data_source: "auth_logs".to_string(),
                    expected_results: "Authentication anomalies".to_string(),
                },
            ],
            data_sources: vec![
                "process_logs".to_string(),
                "auth_logs".to_string(),
                "windows_security".to_string(),
            ],
        });

        // Data Exfiltration Hunt Template
        self.hunt_templates.push(HuntTemplate {
            id: "TMPL-003".to_string(),
            name: "Data Exfiltration Detection".to_string(),
            description: "Hunt for potential data theft and exfiltration".to_string(),
            hypothesis_template: "Data may be exfiltrating via {{channel}}".to_string(),
            mitre_techniques: vec!["T1041".to_string(), "T1048".to_string()],
            suggested_queries: vec![
                HuntQuery {
                    id: "Q-005".to_string(),
                    name: "Large Outbound Transfers".to_string(),
                    description: "Find unusually large data transfers".to_string(),
                    query_type: QueryType::Statistical,
                    pattern: "bytes_out > 100MB".to_string(),
                    data_source: "network_logs".to_string(),
                    expected_results: "Large outbound transfers".to_string(),
                },
                HuntQuery {
                    id: "Q-006".to_string(),
                    name: "DNS Tunneling".to_string(),
                    description: "Detect potential DNS tunneling".to_string(),
                    query_type: QueryType::Behavioral,
                    pattern: "dns_query_length > 50 OR dns_query_entropy > 3.5".to_string(),
                    data_source: "dns_logs".to_string(),
                    expected_results: "Suspicious DNS activity".to_string(),
                },
            ],
            data_sources: vec![
                "network_logs".to_string(),
                "dns_logs".to_string(),
                "proxy_logs".to_string(),
            ],
        });

        // Persistence Hunt Template
        self.hunt_templates.push(HuntTemplate {
            id: "TMPL-004".to_string(),
            name: "Persistence Mechanism Detection".to_string(),
            description: "Hunt for attacker persistence mechanisms".to_string(),
            hypothesis_template: "Attacker may have established persistence using {{mechanism}}"
                .to_string(),
            mitre_techniques: vec![
                "T1053".to_string(),
                "T1547".to_string(),
                "T1546".to_string(),
            ],
            suggested_queries: vec![
                HuntQuery {
                    id: "Q-007".to_string(),
                    name: "Scheduled Tasks".to_string(),
                    description: "Find suspicious scheduled tasks".to_string(),
                    query_type: QueryType::Regex,
                    pattern: r"(?i)(schtasks|at\.exe|task\s+scheduler)".to_string(),
                    data_source: "process_logs".to_string(),
                    expected_results: "Scheduled task events".to_string(),
                },
                HuntQuery {
                    id: "Q-008".to_string(),
                    name: "Registry Run Keys".to_string(),
                    description: "Detect modifications to run keys".to_string(),
                    query_type: QueryType::Regex,
                    pattern: r"(?i)(run|runonce|userinit)".to_string(),
                    data_source: "registry_logs".to_string(),
                    expected_results: "Registry modifications".to_string(),
                },
            ],
            data_sources: vec![
                "process_logs".to_string(),
                "registry_logs".to_string(),
                "file_logs".to_string(),
            ],
        });
    }

    /// Create hunt from template
    pub fn create_hunt_from_template(
        &mut self,
        template_id: &str,
        owner: &str,
        customization: HashMap<String, String>,
    ) -> Option<String> {
        let template = self
            .hunt_templates
            .iter()
            .find(|t| t.id == template_id)?
            .clone();

        let mut hypothesis = template.hypothesis_template.clone();
        for (key, value) in &customization {
            hypothesis = hypothesis.replace(&format!("{{{{{}}}}}", key), value);
        }

        let mut hunt = ThreatHunt::new(&template.name, &hypothesis, owner);
        hunt.description = template.description.clone();
        hunt.mitre_techniques = template.mitre_techniques.clone();
        hunt.data_sources = template.data_sources.clone();

        for query in &template.suggested_queries {
            hunt.add_query(query.clone());
        }

        let id = hunt.id.clone();
        self.hunts.insert(id.clone(), hunt);
        Some(id)
    }

    /// Create custom hunt
    pub fn create_custom_hunt(&mut self, name: &str, hypothesis: &str, owner: &str) -> String {
        let hunt = ThreatHunt::new(name, hypothesis, owner);
        let id = hunt.id.clone();
        self.hunts.insert(id.clone(), hunt);
        id
    }

    /// Get hunt by ID
    pub fn get_hunt(&self, id: &str) -> Option<&ThreatHunt> {
        self.hunts.get(id)
    }

    /// Get mutable hunt
    pub fn get_hunt_mut(&mut self, id: &str) -> Option<&mut ThreatHunt> {
        self.hunts.get_mut(id)
    }

    /// Execute hunt query against logs
    pub fn execute_query(&self, query: &HuntQuery, logs: &[LogEntry]) -> Vec<QueryMatch> {
        let mut matches = Vec::new();

        match query.query_type {
            QueryType::Regex | QueryType::Keyword => {
                if let Ok(regex) = Regex::new(&query.pattern) {
                    for log in logs {
                        if regex.is_match(&log.message) {
                            matches.push(QueryMatch {
                                query_id: query.id.clone(),
                                log_timestamp: log.timestamp,
                                matched_content: log.message.clone(),
                                source_ip: log.source_ip.clone(),
                                user: log.user.clone(),
                                match_details: "Regex match".to_string(),
                            });
                        }
                    }
                }
            }
            QueryType::IOC => {
                for log in logs {
                    for ioc in &self.ioc_database {
                        if log.message.contains(&ioc.indicator) {
                            matches.push(QueryMatch {
                                query_id: query.id.clone(),
                                log_timestamp: log.timestamp,
                                matched_content: log.message.clone(),
                                source_ip: log.source_ip.clone(),
                                user: log.user.clone(),
                                match_details: format!("IOC match: {}", ioc.indicator),
                            });
                        }
                    }
                }
            }
            _ => {
                // Statistical and Behavioral queries require special handling
            }
        }

        matches
    }

    /// Sweep logs for IOCs
    pub fn ioc_sweep(&self, logs: &[LogEntry]) -> Vec<IOCSweepResult> {
        let mut results = Vec::new();

        for ioc in &self.ioc_database {
            let mut matches = Vec::new();

            for log in logs {
                if log.message.contains(&ioc.indicator) {
                    matches.push(log.clone());
                }
            }

            if !matches.is_empty() {
                results.push(IOCSweepResult {
                    ioc: ioc.clone(),
                    match_count: matches.len(),
                    first_seen: matches.iter().map(|l| l.timestamp).min(),
                    last_seen: matches.iter().map(|l| l.timestamp).max(),
                    affected_assets: matches.iter().filter_map(|l| l.source_ip.clone()).collect(),
                });
            }
        }

        results
    }

    /// Add IOC to database
    pub fn add_ioc(&mut self, ioc: HuntIOC) {
        self.ioc_database.push(ioc);
    }

    /// Add multiple IOCs
    pub fn add_iocs(&mut self, iocs: Vec<HuntIOC>) {
        self.ioc_database.extend(iocs);
    }

    /// Get active hunts
    pub fn get_active_hunts(&self) -> Vec<&ThreatHunt> {
        self.hunts
            .values()
            .filter(|h| h.status == HuntStatus::Active)
            .collect()
    }

    /// Get all templates
    pub fn get_templates(&self) -> &[HuntTemplate] {
        &self.hunt_templates
    }

    /// Get hunt statistics
    pub fn get_statistics(&self) -> HuntStatistics {
        let total = self.hunts.len();
        let active = self
            .hunts
            .values()
            .filter(|h| h.status == HuntStatus::Active)
            .count();
        let completed = self
            .hunts
            .values()
            .filter(|h| h.status == HuntStatus::Completed)
            .count();

        let total_findings: usize = self.hunts.values().map(|h| h.findings.len()).sum();
        let true_positives = self
            .hunts
            .values()
            .flat_map(|h| &h.findings)
            .filter(|f| f.result_type == HuntResultType::TruePositive)
            .count();

        HuntStatistics {
            total_hunts: total,
            active_hunts: active,
            completed_hunts: completed,
            total_findings,
            true_positives,
            iocs_in_database: self.ioc_database.len(),
            templates_available: self.hunt_templates.len(),
        }
    }
}

impl Default for ThreatHuntingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Query match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMatch {
    pub query_id: String,
    pub log_timestamp: DateTime<Utc>,
    pub matched_content: String,
    pub source_ip: Option<String>,
    pub user: Option<String>,
    pub match_details: String,
}

/// IOC sweep result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOCSweepResult {
    pub ioc: HuntIOC,
    pub match_count: usize,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub affected_assets: Vec<String>,
}

/// Hunt statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntStatistics {
    pub total_hunts: usize,
    pub active_hunts: usize,
    pub completed_hunts: usize,
    pub total_findings: usize,
    pub true_positives: usize,
    pub iocs_in_database: usize,
    pub templates_available: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hunt_creation() {
        let hunt = ThreatHunt::new("Test Hunt", "An attacker may be present", "analyst");

        assert_eq!(hunt.status, HuntStatus::Draft);
        assert_eq!(hunt.owner, "analyst");
        assert!(hunt.started_at.is_none());
    }

    #[test]
    fn test_hunt_lifecycle() {
        let mut hunt = ThreatHunt::new("Test Hunt", "Hypothesis", "analyst");

        hunt.start("analyst");
        assert_eq!(hunt.status, HuntStatus::Active);
        assert!(hunt.started_at.is_some());

        hunt.pause("analyst", "Need more data");
        assert_eq!(hunt.status, HuntStatus::Paused);

        hunt.start("analyst");
        hunt.complete("analyst", "No threats found");
        assert_eq!(hunt.status, HuntStatus::Completed);
        assert!(hunt.completed_at.is_some());
    }

    #[test]
    fn test_hunt_from_template() {
        let mut engine = ThreatHuntingEngine::new();

        let mut customization = HashMap::new();
        customization.insert("technique".to_string(), "RDP".to_string());

        let hunt_id = engine.create_hunt_from_template("TMPL-001", "analyst", customization);
        assert!(hunt_id.is_some());

        let hunt = engine.get_hunt(&hunt_id.unwrap());
        assert!(hunt.is_some());
        assert!(hunt.unwrap().hypothesis.contains("RDP"));
    }

    #[test]
    fn test_query_execution() {
        let engine = ThreatHuntingEngine::new();

        let query = HuntQuery {
            id: "TEST-Q1".to_string(),
            name: "Test Query".to_string(),
            description: "Test".to_string(),
            query_type: QueryType::Regex,
            pattern: r"(?i)failed\s+login".to_string(),
            data_source: "auth_logs".to_string(),
            expected_results: "Failed logins".to_string(),
        };

        let logs = vec![
            LogEntry {
                timestamp: Utc::now(),
                source_ip: Some("192.168.1.1".to_string()),
                user: Some("user1".to_string()),
                event_type: "auth".to_string(),
                message: "Failed login attempt for admin".to_string(),
                metadata: HashMap::new(),
            },
            LogEntry {
                timestamp: Utc::now(),
                source_ip: Some("192.168.1.2".to_string()),
                user: Some("user2".to_string()),
                event_type: "auth".to_string(),
                message: "Successful login".to_string(),
                metadata: HashMap::new(),
            },
        ];

        let matches = engine.execute_query(&query, &logs);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_content.contains("Failed login"));
    }

    #[test]
    fn test_ioc_sweep() {
        let mut engine = ThreatHuntingEngine::new();

        engine.add_ioc(HuntIOC {
            indicator: "evil.com".to_string(),
            ioc_type: IOCType::Domain,
            description: "Known malicious domain".to_string(),
            confidence: 0.9,
            source: "ThreatFeed".to_string(),
            tags: vec!["malware".to_string()],
        });

        let logs = vec![LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.1".to_string()),
            user: None,
            event_type: "dns".to_string(),
            message: "DNS query for evil.com".to_string(),
            metadata: HashMap::new(),
        }];

        let results = engine.ioc_sweep(&logs);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_count, 1);
    }

    #[test]
    fn test_hunt_statistics() {
        let mut engine = ThreatHuntingEngine::new();

        engine.create_custom_hunt("Hunt 1", "Hypothesis 1", "analyst");
        engine.create_custom_hunt("Hunt 2", "Hypothesis 2", "analyst");

        let stats = engine.get_statistics();
        assert_eq!(stats.total_hunts, 2);
        assert!(stats.templates_available > 0);
    }

    #[test]
    fn test_hunt_findings() {
        let mut hunt = ThreatHunt::new("Test", "Hypothesis", "analyst");

        hunt.add_finding(HuntFinding {
            id: "F-001".to_string(),
            timestamp: Utc::now(),
            query_id: "Q-001".to_string(),
            result_type: HuntResultType::TruePositive,
            description: "Found malicious activity".to_string(),
            evidence: vec!["log1".to_string()],
            affected_assets: vec!["host1".to_string()],
            severity: FindingSeverity::High,
            recommendations: vec!["Investigate".to_string()],
        });

        hunt.add_finding(HuntFinding {
            id: "F-002".to_string(),
            timestamp: Utc::now(),
            query_id: "Q-001".to_string(),
            result_type: HuntResultType::FalsePositive,
            description: "Not malicious".to_string(),
            evidence: vec![],
            affected_assets: vec![],
            severity: FindingSeverity::Informational,
            recommendations: vec![],
        });

        let counts = hunt.count_findings_by_type();
        assert_eq!(counts.get(&HuntResultType::TruePositive), Some(&1));
        assert_eq!(counts.get(&HuntResultType::FalsePositive), Some(&1));
    }
}
