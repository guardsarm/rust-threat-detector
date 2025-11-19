//! # Threat Intelligence Module
//!
//! Indicators of Compromise (IOC) matching and threat intelligence integration
//! for identifying known malicious actors, IPs, domains, and file hashes.

use crate::{LogEntry, ThreatAlert, ThreatCategory, ThreatSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Type of indicator of compromise
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IOCType {
    IPAddress,
    Domain,
    FileHash,
    URL,
    Email,
    UserAgent,
}

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOC {
    pub ioc_type: IOCType,
    pub value: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub source: String, // Threat feed source
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: f64, // 0.0 to 1.0
}

impl IOC {
    pub fn new(
        ioc_type: IOCType,
        value: String,
        severity: ThreatSeverity,
        description: String,
        source: String,
    ) -> Self {
        Self {
            ioc_type,
            value,
            severity,
            description,
            source,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            confidence: 0.8, // Default confidence
        }
    }
}

/// Threat intelligence database
pub struct ThreatIntelligence {
    iocs: HashMap<IOCType, HashMap<String, IOC>>,
    malicious_ips: HashSet<String>,
    malicious_domains: HashSet<String>,
    malicious_hashes: HashSet<String>,
    threat_actors: HashMap<String, ThreatActor>,
    matches_count: usize,
}

/// Known threat actor/group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub name: String,
    pub aliases: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub techniques: Vec<String>, // MITRE ATT&CK techniques
    pub targeted_sectors: Vec<String>,
    pub associated_iocs: Vec<String>,
}

impl ThreatIntelligence {
    /// Create new threat intelligence database
    pub fn new() -> Self {
        let mut intel = Self {
            iocs: HashMap::new(),
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
            malicious_hashes: HashSet::new(),
            threat_actors: HashMap::new(),
            matches_count: 0,
        };

        // Initialize IOC type maps
        intel.iocs.insert(IOCType::IPAddress, HashMap::new());
        intel.iocs.insert(IOCType::Domain, HashMap::new());
        intel.iocs.insert(IOCType::FileHash, HashMap::new());
        intel.iocs.insert(IOCType::URL, HashMap::new());
        intel.iocs.insert(IOCType::Email, HashMap::new());
        intel.iocs.insert(IOCType::UserAgent, HashMap::new());

        // Load default threat intelligence
        intel.load_default_iocs();

        intel
    }

    /// Load default IOCs (example threat intelligence)
    fn load_default_iocs(&mut self) {
        // Add known malicious IPs (examples - these would come from threat feeds)
        self.add_ioc(IOC::new(
            IOCType::IPAddress,
            "185.220.101.1".to_string(),
            ThreatSeverity::High,
            "Tor exit node - potential anonymization".to_string(),
            "TorProject".to_string(),
        ));

        self.add_ioc(IOC::new(
            IOCType::IPAddress,
            "45.142.214.0".to_string(),
            ThreatSeverity::Critical,
            "Known C2 server IP".to_string(),
            "ThreatFeed".to_string(),
        ));

        // Add malicious domains
        self.add_ioc(IOC::new(
            IOCType::Domain,
            "malicious-example.com".to_string(),
            ThreatSeverity::Critical,
            "Known phishing domain".to_string(),
            "PhishTank".to_string(),
        ));

        // Add malicious file hashes (SHA-256)
        self.add_ioc(IOC::new(
            IOCType::FileHash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ThreatSeverity::Critical,
            "Known malware hash".to_string(),
            "VirusTotal".to_string(),
        ));

        // Add suspicious user agents
        self.add_ioc(IOC::new(
            IOCType::UserAgent,
            "sqlmap".to_string(),
            ThreatSeverity::High,
            "Automated SQL injection tool".to_string(),
            "SecurityTools".to_string(),
        ));

        self.add_ioc(IOC::new(
            IOCType::UserAgent,
            "nikto".to_string(),
            ThreatSeverity::High,
            "Automated vulnerability scanner".to_string(),
            "SecurityTools".to_string(),
        ));
    }

    /// Add an IOC to the database
    pub fn add_ioc(&mut self, ioc: IOC) {
        let value = ioc.value.clone();

        // Add to appropriate set for fast lookup
        match ioc.ioc_type {
            IOCType::IPAddress => {
                self.malicious_ips.insert(value.clone());
            }
            IOCType::Domain => {
                self.malicious_domains.insert(value.clone());
            }
            IOCType::FileHash => {
                self.malicious_hashes.insert(value.clone());
            }
            _ => {}
        }

        // Add to main IOC database
        if let Some(type_map) = self.iocs.get_mut(&ioc.ioc_type) {
            type_map.insert(value, ioc);
        }
    }

    /// Check log against threat intelligence
    pub fn check_log(&mut self, log: &LogEntry) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        // Check source IP
        if let Some(ref ip) = log.source_ip {
            if let Some(alert) = self.check_ioc(IOCType::IPAddress, ip, log) {
                alerts.push(alert);
            }
        }

        // Check for domains in message
        for domain in self.extract_domains(&log.message) {
            if let Some(alert) = self.check_ioc(IOCType::Domain, &domain, log) {
                alerts.push(alert);
            }
        }

        // Check for file hashes in metadata
        if let Some(hash) = log.metadata.get("file_hash") {
            if let Some(alert) = self.check_ioc(IOCType::FileHash, hash, log) {
                alerts.push(alert);
            }
        }

        // Check for URLs in metadata
        if let Some(url) = log.metadata.get("url") {
            if let Some(alert) = self.check_ioc(IOCType::URL, url, log) {
                alerts.push(alert);
            }
        }

        // Check user agent
        if let Some(user_agent) = log.metadata.get("user_agent") {
            for ioc_map in self.iocs.get(&IOCType::UserAgent).iter() {
                for (pattern, ioc) in ioc_map.iter() {
                    if user_agent.to_lowercase().contains(&pattern.to_lowercase()) {
                        self.matches_count += 1;
                        alerts.push(self.create_alert(ioc, log));
                    }
                }
            }
        }

        alerts
    }

    /// Check specific IOC
    fn check_ioc(&mut self, ioc_type: IOCType, value: &str, log: &LogEntry) -> Option<ThreatAlert> {
        if let Some(type_map) = self.iocs.get(&ioc_type) {
            if let Some(ioc) = type_map.get(value) {
                self.matches_count += 1;
                return Some(self.create_alert(ioc, log));
            }
        }
        None
    }

    /// Create alert from IOC match
    fn create_alert(&self, ioc: &IOC, log: &LogEntry) -> ThreatAlert {
        ThreatAlert {
            alert_id: format!("IOC-{}", self.matches_count),
            timestamp: Utc::now(),
            severity: ioc.severity,
            category: ThreatCategory::SystemCompromise,
            description: format!(
                "Threat Intelligence Match: {} ({:?})",
                ioc.description, ioc.ioc_type
            ),
            source_log: format!("{} - {}", log.timestamp, log.message),
            indicators: vec![
                format!("{:?}: {}", ioc.ioc_type, ioc.value),
                format!("Source: {}", ioc.source),
                format!("Confidence: {:.0}%", ioc.confidence * 100.0),
            ],
            recommended_action: format!(
                "Block {} {}, investigate affected systems, review network traffic",
                format!("{:?}", ioc.ioc_type).to_lowercase(),
                ioc.value
            ),
            threat_score: self.calculate_threat_score(ioc),
            correlated_alerts: vec![],
        }
    }

    /// Calculate threat score from IOC
    fn calculate_threat_score(&self, ioc: &IOC) -> u32 {
        let base_score = match ioc.severity {
            ThreatSeverity::Info => 10,
            ThreatSeverity::Low => 25,
            ThreatSeverity::Medium => 50,
            ThreatSeverity::High => 75,
            ThreatSeverity::Critical => 95,
        };

        let confidence_adjustment = (ioc.confidence * 10.0) as u32;
        (base_score + confidence_adjustment).min(100)
    }

    /// Extract domains from text
    fn extract_domains(&self, text: &str) -> Vec<String> {
        let mut domains = Vec::new();
        let words: Vec<&str> = text.split_whitespace().collect();

        for word in words {
            if word.contains('.') && !word.starts_with("http") {
                // Simple domain detection
                if let Some(domain) = word.split('/').next() {
                    if domain.contains('.') {
                        domains.push(domain.to_string());
                    }
                }
            }
        }

        domains
    }

    /// Get IOC by type and value
    pub fn get_ioc(&self, ioc_type: IOCType, value: &str) -> Option<&IOC> {
        self.iocs.get(&ioc_type)?.get(value)
    }

    /// Get all IOCs of a specific type
    pub fn get_iocs_by_type(&self, ioc_type: IOCType) -> Vec<&IOC> {
        self.iocs
            .get(&ioc_type)
            .map(|map| map.values().collect())
            .unwrap_or_default()
    }

    /// Get statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_matches".to_string(), self.matches_count);
        stats.insert("malicious_ips".to_string(), self.malicious_ips.len());
        stats.insert(
            "malicious_domains".to_string(),
            self.malicious_domains.len(),
        );
        stats.insert("malicious_hashes".to_string(), self.malicious_hashes.len());
        stats.insert("threat_actors".to_string(), self.threat_actors.len());

        let total_iocs: usize = self.iocs.values().map(|m| m.len()).sum();
        stats.insert("total_iocs".to_string(), total_iocs);

        stats
    }

    /// Import IOCs from JSON
    pub fn import_iocs_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let iocs: Vec<IOC> = serde_json::from_str(json)?;
        let count = iocs.len();
        for ioc in iocs {
            self.add_ioc(ioc);
        }
        Ok(count)
    }

    /// Export IOCs to JSON
    pub fn export_iocs_json(&self) -> Result<String, serde_json::Error> {
        let all_iocs: Vec<&IOC> = self.iocs.values().flat_map(|m| m.values()).collect();
        serde_json::to_string_pretty(&all_iocs)
    }

    /// Clear old IOCs
    pub fn clear_old_iocs(&mut self, before: DateTime<Utc>) {
        for type_map in self.iocs.values_mut() {
            type_map.retain(|_, ioc| ioc.last_seen >= before);
        }
        // Rebuild fast lookup sets
        self.rebuild_lookup_sets();
    }

    /// Rebuild fast lookup sets
    fn rebuild_lookup_sets(&mut self) {
        self.malicious_ips.clear();
        self.malicious_domains.clear();
        self.malicious_hashes.clear();

        if let Some(ip_map) = self.iocs.get(&IOCType::IPAddress) {
            self.malicious_ips.extend(ip_map.keys().cloned());
        }
        if let Some(domain_map) = self.iocs.get(&IOCType::Domain) {
            self.malicious_domains.extend(domain_map.keys().cloned());
        }
        if let Some(hash_map) = self.iocs.get(&IOCType::FileHash) {
            self.malicious_hashes.extend(hash_map.keys().cloned());
        }
    }
}

impl Default for ThreatIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_log_with_ip(ip: &str) -> LogEntry {
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some(ip.to_string()),
            user: Some("test_user".to_string()),
            event_type: "connection".to_string(),
            message: "Network connection established".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_ioc_creation() {
        let ioc = IOC::new(
            IOCType::IPAddress,
            "1.2.3.4".to_string(),
            ThreatSeverity::High,
            "Test IOC".to_string(),
            "TestFeed".to_string(),
        );

        assert_eq!(ioc.value, "1.2.3.4");
        assert_eq!(ioc.severity, ThreatSeverity::High);
    }

    #[test]
    fn test_add_ioc() {
        let mut intel = ThreatIntelligence::new();
        let initial_count = intel.malicious_ips.len();

        intel.add_ioc(IOC::new(
            IOCType::IPAddress,
            "10.0.0.1".to_string(),
            ThreatSeverity::Medium,
            "Test IP".to_string(),
            "Test".to_string(),
        ));

        assert_eq!(intel.malicious_ips.len(), initial_count + 1);
        assert!(intel.malicious_ips.contains("10.0.0.1"));
    }

    #[test]
    fn test_check_malicious_ip() {
        let mut intel = ThreatIntelligence::new();

        // Add malicious IP
        intel.add_ioc(IOC::new(
            IOCType::IPAddress,
            "99.99.99.99".to_string(),
            ThreatSeverity::Critical,
            "Malicious server".to_string(),
            "ThreatFeed".to_string(),
        ));

        let log = create_log_with_ip("99.99.99.99");
        let alerts = intel.check_log(&log);

        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, ThreatSeverity::Critical);
        assert!(alerts[0].description.contains("Threat Intelligence Match"));
    }

    #[test]
    fn test_check_clean_ip() {
        let mut intel = ThreatIntelligence::new();
        let log = create_log_with_ip("192.168.1.1");
        let alerts = intel.check_log(&log);

        // Should not match any default IOCs
        assert!(alerts
            .iter()
            .all(|a| a.severity != ThreatSeverity::Critical));
    }

    #[test]
    fn test_domain_extraction() {
        let intel = ThreatIntelligence::new();
        let text = "User accessed malicious-example.com and another.domain.org";
        let domains = intel.extract_domains(text);

        assert!(domains.contains(&"malicious-example.com".to_string()));
        assert!(domains.contains(&"another.domain.org".to_string()));
    }

    #[test]
    fn test_get_ioc() {
        let mut intel = ThreatIntelligence::new();

        intel.add_ioc(IOC::new(
            IOCType::Domain,
            "evil.com".to_string(),
            ThreatSeverity::High,
            "Malicious domain".to_string(),
            "Test".to_string(),
        ));

        let ioc = intel.get_ioc(IOCType::Domain, "evil.com");
        assert!(ioc.is_some());
        assert_eq!(ioc.unwrap().value, "evil.com");
    }

    #[test]
    fn test_get_iocs_by_type() {
        let intel = ThreatIntelligence::new();
        let ip_iocs = intel.get_iocs_by_type(IOCType::IPAddress);

        assert!(!ip_iocs.is_empty()); // Should have default IOCs
    }

    #[test]
    fn test_stats() {
        let intel = ThreatIntelligence::new();
        let stats = intel.get_stats();

        assert!(stats.contains_key("total_iocs"));
        assert!(stats.contains_key("malicious_ips"));
        assert!(stats.get("total_iocs").unwrap() > &0); // Has default IOCs
    }

    #[test]
    fn test_user_agent_detection() {
        let mut intel = ThreatIntelligence::new();
        let mut log = LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.1".to_string()),
            user: Some("attacker".to_string()),
            event_type: "web_request".to_string(),
            message: "HTTP request".to_string(),
            metadata: HashMap::new(),
        };

        log.metadata
            .insert("user_agent".to_string(), "sqlmap/1.0".to_string());

        let alerts = intel.check_log(&log);
        assert!(!alerts.is_empty());
        assert!(
            alerts[0].description.contains("UserAgent")
                || alerts[0].description.contains("SQL injection")
        );
    }

    #[test]
    fn test_threat_score_calculation() {
        let intel = ThreatIntelligence::new();

        let high_confidence_ioc = IOC {
            ioc_type: IOCType::IPAddress,
            value: "1.2.3.4".to_string(),
            severity: ThreatSeverity::Critical,
            description: "Test".to_string(),
            source: "Test".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            confidence: 1.0,
        };

        let score = intel.calculate_threat_score(&high_confidence_ioc);
        assert!(score >= 95);
    }

    #[test]
    fn test_clear_old_iocs() {
        let mut intel = ThreatIntelligence::new();

        let old_ioc = IOC {
            ioc_type: IOCType::IPAddress,
            value: "1.1.1.1".to_string(),
            severity: ThreatSeverity::Low,
            description: "Old IOC".to_string(),
            source: "Test".to_string(),
            first_seen: Utc::now() - chrono::Duration::days(100),
            last_seen: Utc::now() - chrono::Duration::days(100),
            confidence: 0.5,
        };

        intel.add_ioc(old_ioc);

        let cutoff = Utc::now() - chrono::Duration::days(50);
        intel.clear_old_iocs(cutoff);

        // Old IOC should be removed
        assert!(intel.get_ioc(IOCType::IPAddress, "1.1.1.1").is_none());
    }
}
