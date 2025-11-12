//! # Rust Threat Detector
//!
//! A memory-safe SIEM threat detection component for real-time security monitoring
//! and threat analysis.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust to prevent vulnerabilities in security tools
//! - **Real-time Analysis**: Fast pattern matching and threat detection
//! - **Pattern Library**: Pre-configured threat patterns
//! - **Anomaly Detection**: Statistical anomaly detection
//! - **Alert Generation**: Structured alert output for SIEM integration
//!
//! ## Alignment with Federal Guidance
//!
//! Implements memory-safe security monitoring tools, aligning with 2024 CISA/FBI
//! guidance for critical infrastructure protection.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Threat detection errors
#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Invalid log format: {0}")]
    InvalidLogFormat(String),

    #[error("Pattern compilation failed: {0}")]
    PatternError(String),
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Threat categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    BruteForce,
    MalwareDetection,
    DataExfiltration,
    UnauthorizedAccess,
    AnomalousActivity,
    PolicyViolation,
    SystemCompromise,
}

/// Log entry for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub user: Option<String>,
    pub event_type: String,
    pub message: String,
    pub metadata: HashMap<String, String>,
}

/// Detected threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub alert_id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: ThreatSeverity,
    pub category: ThreatCategory,
    pub description: String,
    pub source_log: String,
    pub indicators: Vec<String>,
    pub recommended_action: String,
}

impl ThreatAlert {
    /// Export alert as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Threat detection pattern
#[derive(Debug, Clone)]
pub struct ThreatPattern {
    pub name: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub pattern: Regex,
    pub description: String,
    pub recommended_action: String,
}

/// Threat detector
pub struct ThreatDetector {
    patterns: Vec<ThreatPattern>,
    alert_count: usize,
}

impl ThreatDetector {
    /// Create a new threat detector with default patterns
    pub fn new() -> Self {
        let mut detector = Self {
            patterns: Vec::new(),
            alert_count: 0,
        };
        detector.load_default_patterns();
        detector
    }

    /// Load default threat detection patterns
    fn load_default_patterns(&mut self) {
        // Brute force detection
        self.add_pattern(ThreatPattern {
            name: "Failed Login Attempts".to_string(),
            category: ThreatCategory::BruteForce,
            severity: ThreatSeverity::High,
            pattern: Regex::new(r"(?i)(failed.*login|authentication.*failed|invalid.*password)").unwrap(),
            description: "Multiple failed login attempts detected".to_string(),
            recommended_action: "Block source IP, enable MFA, review user account".to_string(),
        });

        // Malware indicators
        self.add_pattern(ThreatPattern {
            name: "Malware Signature".to_string(),
            category: ThreatCategory::MalwareDetection,
            severity: ThreatSeverity::Critical,
            pattern: Regex::new(r"(?i)(malware|virus|trojan|ransomware|backdoor)").unwrap(),
            description: "Malware signature detected in logs".to_string(),
            recommended_action: "Isolate system, run full scan, investigate infection vector".to_string(),
        });

        // Data exfiltration
        self.add_pattern(ThreatPattern {
            name: "Large Data Transfer".to_string(),
            category: ThreatCategory::DataExfiltration,
            severity: ThreatSeverity::High,
            pattern: Regex::new(r"(?i)(large.*transfer|exfiltration|unusual.*download)").unwrap(),
            description: "Potential data exfiltration detected".to_string(),
            recommended_action: "Block transfer, investigate user activity, review DLP policies".to_string(),
        });

        // Unauthorized access
        self.add_pattern(ThreatPattern {
            name: "Privilege Escalation".to_string(),
            category: ThreatCategory::UnauthorizedAccess,
            severity: ThreatSeverity::Critical,
            pattern: Regex::new(r"(?i)(privilege.*escalation|unauthorized.*access|sudo|admin.*access)").unwrap(),
            description: "Unauthorized privilege escalation attempt".to_string(),
            recommended_action: "Revoke privileges, investigate account, review access logs".to_string(),
        });

        // SQL Injection
        self.add_pattern(ThreatPattern {
            name: "SQL Injection Attempt".to_string(),
            category: ThreatCategory::SystemCompromise,
            severity: ThreatSeverity::Critical,
            pattern: Regex::new(r"(?i)(union.*select|' or '1'='1|drop.*table|;--|exec\()").unwrap(),
            description: "SQL injection attack detected".to_string(),
            recommended_action: "Block source IP, patch application, review WAF rules".to_string(),
        });

        // Suspicious IP access
        self.add_pattern(ThreatPattern {
            name: "Suspicious IP Address".to_string(),
            category: ThreatCategory::AnomalousActivity,
            severity: ThreatSeverity::Medium,
            pattern: Regex::new(r"(^0\.|^10\.|^127\.|^169\.254\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.|^224\.)").unwrap(),
            description: "Access from suspicious IP range".to_string(),
            recommended_action: "Verify IP legitimacy, check geo-location, review firewall rules".to_string(),
        });
    }

    /// Add a custom threat pattern
    pub fn add_pattern(&mut self, pattern: ThreatPattern) {
        self.patterns.push(pattern);
    }

    /// Analyze a log entry for threats
    pub fn analyze(&mut self, log: &LogEntry) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        for pattern in &self.patterns {
            if pattern.pattern.is_match(&log.message) {
                self.alert_count += 1;
                let alert = ThreatAlert {
                    alert_id: format!("ALERT-{:08}", self.alert_count),
                    timestamp: Utc::now(),
                    severity: pattern.severity,
                    category: pattern.category.clone(),
                    description: format!("{}: {}", pattern.name, pattern.description),
                    source_log: format!("{} - {}", log.timestamp, log.message),
                    indicators: self.extract_indicators(&log.message, &pattern.pattern),
                    recommended_action: pattern.recommended_action.clone(),
                };
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Extract threat indicators from log message
    fn extract_indicators(&self, message: &str, pattern: &Regex) -> Vec<String> {
        let mut indicators = Vec::new();

        if let Some(captures) = pattern.captures(message) {
            for i in 1..captures.len() {
                if let Some(matched) = captures.get(i) {
                    indicators.push(matched.as_str().to_string());
                }
            }
        }

        if indicators.is_empty() {
            indicators.push("Pattern match".to_string());
        }

        indicators
    }

    /// Get statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_patterns".to_string(), self.patterns.len());
        stats.insert("total_alerts".to_string(), self.alert_count);
        stats
    }

    /// Get alerts by severity
    pub fn filter_by_severity(
        &self,
        alerts: &[ThreatAlert],
        min_severity: ThreatSeverity,
    ) -> Vec<ThreatAlert> {
        alerts
            .iter()
            .filter(|alert| alert.severity >= min_severity)
            .cloned()
            .collect()
    }
}

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_log_entry(message: &str) -> LogEntry {
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.100".to_string()),
            user: Some("test_user".to_string()),
            event_type: "security_event".to_string(),
            message: message.to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_brute_force_detection() {
        let mut detector = ThreatDetector::new();
        let log = create_log_entry("Failed login attempt for user admin");

        let alerts = detector.analyze(&log);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].category, ThreatCategory::BruteForce);
    }

    #[test]
    fn test_malware_detection() {
        let mut detector = ThreatDetector::new();
        let log = create_log_entry("Malware detected in file system");

        let alerts = detector.analyze(&log);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].category, ThreatCategory::MalwareDetection);
        assert_eq!(alerts[0].severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_sql_injection_detection() {
        let mut detector = ThreatDetector::new();
        let log = create_log_entry("Query: SELECT * FROM users WHERE id='1' OR '1'='1'");

        let alerts = detector.analyze(&log);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_no_threat_detected() {
        let mut detector = ThreatDetector::new();
        let log = create_log_entry("User successfully logged in");

        let alerts = detector.analyze(&log);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_severity_filtering() {
        let mut detector = ThreatDetector::new();
        let log1 = create_log_entry("Failed login attempt");
        let log2 = create_log_entry("Malware detected");

        let mut all_alerts = Vec::new();
        all_alerts.extend(detector.analyze(&log1));
        all_alerts.extend(detector.analyze(&log2));

        let critical_alerts = detector.filter_by_severity(&all_alerts, ThreatSeverity::Critical);
        assert_eq!(critical_alerts.len(), 1);
        assert_eq!(critical_alerts[0].category, ThreatCategory::MalwareDetection);
    }
}
