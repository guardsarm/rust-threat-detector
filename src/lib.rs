//! # Rust Threat Detector
//!
//! A memory-safe SIEM threat detection component for real-time security monitoring
//! and threat analysis.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust to prevent vulnerabilities in security tools
//! - **Real-time Analysis**: Fast pattern matching and threat detection
//! - **MITRE ATT&CK Framework**: 10+ technique detection patterns
//! - **Pattern Library**: Pre-configured threat patterns
//! - **Anomaly Detection**: Statistical anomaly detection
//! - **Alert Generation**: Structured alert output for SIEM integration
//!
//! ## Alignment with Federal Guidance
//!
//! Implements memory-safe security monitoring tools, aligning with 2024 CISA/FBI
//! guidance for critical infrastructure protection.

pub mod mitre_attack;
pub use mitre_attack::{AttackTactic, AttackTechnique, MitreAttackDetector, ThreatDetection, ThreatSeverity};

use chrono::{DateTime, Duration, Utc};
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
    pub threat_score: u32,
    pub correlated_alerts: Vec<String>,
}

impl ThreatAlert {
    /// Export alert as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get risk assessment based on threat score
    pub fn risk_assessment(&self) -> &str {
        match self.threat_score {
            0..=20 => "Low Risk",
            21..=50 => "Medium Risk",
            51..=80 => "High Risk",
            _ => "Critical Risk",
        }
    }
}

/// Alert aggregation for pattern analysis
#[derive(Debug, Clone)]
struct AlertAggregation {
    category: ThreatCategory,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    count: usize,
    sources: Vec<String>,
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
    alert_history: Vec<ThreatAlert>,
    aggregations: HashMap<String, AlertAggregation>,
}

impl ThreatDetector {
    /// Create a new threat detector with default patterns
    pub fn new() -> Self {
        let mut detector = Self {
            patterns: Vec::new(),
            alert_count: 0,
            alert_history: Vec::new(),
            aggregations: HashMap::new(),
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

                // Calculate threat score
                let threat_score = self.calculate_threat_score(pattern.severity, log);

                // Find correlated alerts
                let correlated = self.find_correlated_alerts(&pattern.category, log);

                let alert = ThreatAlert {
                    alert_id: format!("ALERT-{:08}", self.alert_count),
                    timestamp: Utc::now(),
                    severity: pattern.severity,
                    category: pattern.category.clone(),
                    description: format!("{}: {}", pattern.name, pattern.description),
                    source_log: format!("{} - {}", log.timestamp, log.message),
                    indicators: self.extract_indicators(&log.message, &pattern.pattern),
                    recommended_action: pattern.recommended_action.clone(),
                    threat_score,
                    correlated_alerts: correlated,
                };

                // Update aggregation
                self.update_aggregation(&alert, log);

                // Store in history
                self.alert_history.push(alert.clone());

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Calculate threat score based on multiple factors
    fn calculate_threat_score(&self, severity: ThreatSeverity, log: &LogEntry) -> u32 {
        let mut score: u32 = match severity {
            ThreatSeverity::Info => 5,
            ThreatSeverity::Low => 15,
            ThreatSeverity::Medium => 40,
            ThreatSeverity::High => 70,
            ThreatSeverity::Critical => 95,
        };

        // Increase score if from external IP (simplified check)
        if let Some(ref ip) = log.source_ip {
            if !ip.starts_with("192.168.") && !ip.starts_with("10.") {
                score += 10;
            }
        }

        // Increase score for root/admin users
        if let Some(ref user) = log.user {
            if user.contains("admin") || user.contains("root") {
                score += 15;
            }
        }

        score.min(100)
    }

    /// Find correlated alerts in recent history
    fn find_correlated_alerts(&self, category: &ThreatCategory, log: &LogEntry) -> Vec<String> {
        let window_start = log.timestamp - Duration::hours(1);
        let mut correlated = Vec::new();

        for alert in &self.alert_history {
            if alert.timestamp >= window_start && alert.category == *category {
                // Check for same source
                if let Some(ref ip) = log.source_ip {
                    if alert.source_log.contains(ip) {
                        correlated.push(alert.alert_id.clone());
                    }
                }
            }
        }

        correlated
    }

    /// Update alert aggregation for pattern analysis
    fn update_aggregation(&mut self, alert: &ThreatAlert, log: &LogEntry) {
        let key = format!("{:?}", alert.category);
        let source = log.source_ip.clone().unwrap_or_else(|| "unknown".to_string());

        self.aggregations
            .entry(key.clone())
            .and_modify(|agg| {
                agg.last_seen = alert.timestamp;
                agg.count += 1;
                if !agg.sources.contains(&source) {
                    agg.sources.push(source.clone());
                }
            })
            .or_insert(AlertAggregation {
                category: alert.category.clone(),
                first_seen: alert.timestamp,
                last_seen: alert.timestamp,
                count: 1,
                sources: vec![source],
            });
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

    /// Analyze multiple log entries in batch
    pub fn analyze_batch(&mut self, logs: &[LogEntry]) -> Vec<ThreatAlert> {
        let mut all_alerts = Vec::new();
        for log in logs {
            all_alerts.extend(self.analyze(log));
        }
        all_alerts
    }

    /// Get alert history for a time window
    pub fn get_alert_history(&self, since: DateTime<Utc>) -> Vec<&ThreatAlert> {
        self.alert_history
            .iter()
            .filter(|alert| alert.timestamp >= since)
            .collect()
    }

    /// Get aggregated patterns
    pub fn get_aggregations(&self) -> HashMap<String, (usize, usize)> {
        self.aggregations
            .iter()
            .map(|(k, v)| (k.clone(), (v.count, v.sources.len())))
            .collect()
    }

    /// Deduplicate alerts by removing similar alerts within time window
    pub fn deduplicate_alerts(&mut self, window_minutes: i64) -> usize {
        let mut to_remove = Vec::new();
        let mut seen = HashMap::new();

        for (i, alert) in self.alert_history.iter().enumerate() {
            let key = format!("{:?}-{}", alert.category, alert.source_log);
            if let Some(&prev_idx) = seen.get(&key) {
                let prev_alert = &self.alert_history[prev_idx];
                if (alert.timestamp - prev_alert.timestamp).num_minutes() <= window_minutes {
                    to_remove.push(i);
                    continue;
                }
            }
            seen.insert(key, i);
        }

        let removed_count = to_remove.len();
        // Remove in reverse order to maintain indices
        for &idx in to_remove.iter().rev() {
            self.alert_history.remove(idx);
        }

        removed_count
    }

    /// Get top threat sources
    pub fn get_top_sources(&self, limit: usize) -> Vec<(String, usize)> {
        let mut source_counts: HashMap<String, usize> = HashMap::new();

        for agg in self.aggregations.values() {
            for source in &agg.sources {
                *source_counts.entry(source.clone()).or_insert(0) += 1;
            }
        }

        let mut sorted: Vec<(String, usize)> = source_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    /// Clear old alerts from history (memory management)
    pub fn clear_old_alerts(&mut self, before: DateTime<Utc>) {
        self.alert_history.retain(|alert| alert.timestamp >= before);
    }

    /// Get statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_patterns".to_string(), self.patterns.len());
        stats.insert("total_alerts".to_string(), self.alert_count);
        stats.insert("alerts_in_history".to_string(), self.alert_history.len());
        stats.insert("active_aggregations".to_string(), self.aggregations.len());
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

    /// Get alerts by category
    pub fn filter_by_category(
        &self,
        alerts: &[ThreatAlert],
        category: &ThreatCategory,
    ) -> Vec<ThreatAlert> {
        alerts
            .iter()
            .filter(|alert| alert.category == *category)
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

    #[test]
    fn test_threat_scoring() {
        let mut detector = ThreatDetector::new();

        // High severity with external IP
        let log = LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("1.2.3.4".to_string()), // External IP
            user: Some("admin".to_string()),        // Admin user
            event_type: "security_event".to_string(),
            message: "Malware detected".to_string(),
            metadata: HashMap::new(),
        };

        let alerts = detector.analyze(&log);
        assert!(!alerts.is_empty());
        assert!(alerts[0].threat_score > 95); // Critical + external + admin
    }

    #[test]
    fn test_alert_correlation() {
        let mut detector = ThreatDetector::new();
        let ip = "192.168.1.100".to_string();

        // First alert
        let log1 = LogEntry {
            timestamp: Utc::now(),
            source_ip: Some(ip.clone()),
            user: Some("user1".to_string()),
            event_type: "security_event".to_string(),
            message: "Failed login attempt".to_string(),
            metadata: HashMap::new(),
        };

        let alerts1 = detector.analyze(&log1);
        assert_eq!(alerts1[0].correlated_alerts.len(), 0);

        // Second alert from same IP
        let log2 = LogEntry {
            timestamp: Utc::now(),
            source_ip: Some(ip),
            user: Some("user2".to_string()),
            event_type: "security_event".to_string(),
            message: "Failed login attempt again".to_string(),
            metadata: HashMap::new(),
        };

        let alerts2 = detector.analyze(&log2);
        assert!(alerts2[0].correlated_alerts.len() > 0); // Should correlate with first alert
    }

    #[test]
    fn test_batch_analysis() {
        let mut detector = ThreatDetector::new();

        let logs = vec![
            create_log_entry("Failed login"),
            create_log_entry("Malware detected"),
            create_log_entry("Normal activity"),
        ];

        let alerts = detector.analyze_batch(&logs);
        assert_eq!(alerts.len(), 2); // Only failed login and malware
    }

    #[test]
    fn test_alert_history() {
        let mut detector = ThreatDetector::new();

        let log1 = create_log_entry("Failed login");
        let log2 = create_log_entry("Malware detected");

        detector.analyze(&log1);
        detector.analyze(&log2);

        let since = Utc::now() - Duration::hours(1);
        let history = detector.get_alert_history(since);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_aggregations() {
        let mut detector = ThreatDetector::new();

        for _ in 0..5 {
            let log = create_log_entry("Failed login attempt");
            detector.analyze(&log);
        }

        let aggregations = detector.get_aggregations();
        assert!(!aggregations.is_empty());

        // Should have BruteForce aggregation with count of 5
        let brute_force_key = format!("{:?}", ThreatCategory::BruteForce);
        if let Some(&(count, _sources)) = aggregations.get(&brute_force_key) {
            assert_eq!(count, 5);
        }
    }

    #[test]
    fn test_deduplication() {
        let mut detector = ThreatDetector::new();

        // Create duplicate alerts within short time
        for _ in 0..3 {
            let log = create_log_entry("Failed login attempt");
            detector.analyze(&log);
        }

        let initial_count = detector.alert_history.len();
        assert_eq!(initial_count, 3);

        let removed = detector.deduplicate_alerts(60); // 60 minute window
        assert!(removed > 0); // Should remove duplicates
        assert!(detector.alert_history.len() < initial_count);
    }

    #[test]
    fn test_top_sources() {
        let mut detector = ThreatDetector::new();

        // Generate alerts from different sources
        for i in 0..5 {
            let log = LogEntry {
                timestamp: Utc::now(),
                source_ip: Some(format!("192.168.1.{}", i)),
                user: Some("user1".to_string()),
                event_type: "security_event".to_string(),
                message: "Failed login attempt".to_string(),
                metadata: HashMap::new(),
            };
            detector.analyze(&log);
        }

        let top_sources = detector.get_top_sources(3);
        assert!(top_sources.len() <= 3);
    }

    #[test]
    fn test_clear_old_alerts() {
        let mut detector = ThreatDetector::new();

        let log = create_log_entry("Failed login");
        detector.analyze(&log);

        assert_eq!(detector.alert_history.len(), 1);

        let cutoff = Utc::now() + Duration::hours(1); // Future time
        detector.clear_old_alerts(cutoff);

        assert_eq!(detector.alert_history.len(), 0);
    }

    #[test]
    fn test_risk_assessment() {
        let alert = ThreatAlert {
            alert_id: "TEST-001".to_string(),
            timestamp: Utc::now(),
            severity: ThreatSeverity::Critical,
            category: ThreatCategory::MalwareDetection,
            description: "Test alert".to_string(),
            source_log: "Test log".to_string(),
            indicators: vec![],
            recommended_action: "Test action".to_string(),
            threat_score: 95,
            correlated_alerts: vec![],
        };

        assert_eq!(alert.risk_assessment(), "Critical Risk");

        let low_alert = ThreatAlert {
            threat_score: 15,
            ..alert
        };
        assert_eq!(low_alert.risk_assessment(), "Low Risk");
    }

    #[test]
    fn test_category_filtering() {
        let mut detector = ThreatDetector::new();
        let log1 = create_log_entry("Failed login attempt");
        let log2 = create_log_entry("Malware detected");

        let mut all_alerts = Vec::new();
        all_alerts.extend(detector.analyze(&log1));
        all_alerts.extend(detector.analyze(&log2));

        let brute_force_alerts =
            detector.filter_by_category(&all_alerts, &ThreatCategory::BruteForce);
        assert_eq!(brute_force_alerts.len(), 1);
        assert_eq!(brute_force_alerts[0].category, ThreatCategory::BruteForce);
    }

    #[test]
    fn test_json_export() {
        let mut detector = ThreatDetector::new();
        let log = create_log_entry("Failed login attempt");
        let alerts = detector.analyze(&log);

        let json = alerts[0].to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("threat_score"));
        assert!(json_str.contains("correlated_alerts"));
    }
}
