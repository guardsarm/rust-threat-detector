//! # Behavioral Analytics Module
//!
//! User and Entity Behavior Analytics (UEBA) for detecting anomalous behavior
//! patterns that may indicate insider threats or compromised accounts.

use crate::{LogEntry, ThreatAlert, ThreatCategory, ThreatSeverity};
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User behavior profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_events: usize,
    pub failed_logins: usize,
    pub successful_logins: usize,
    pub typical_login_hours: Vec<u32>,
    pub typical_source_ips: Vec<String>,
    pub average_session_duration_minutes: f64,
    pub accessed_resources: HashMap<String, usize>,
}

impl UserProfile {
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            total_events: 0,
            failed_logins: 0,
            successful_logins: 0,
            typical_login_hours: Vec::new(),
            typical_source_ips: Vec::new(),
            average_session_duration_minutes: 30.0,
            accessed_resources: HashMap::new(),
        }
    }

    /// Update profile with new event
    pub fn update(&mut self, log: &LogEntry) {
        self.last_seen = log.timestamp;
        self.total_events += 1;

        // Track login hours
        let hour = log.timestamp.hour();
        if !self.typical_login_hours.contains(&hour) && self.typical_login_hours.len() < 10 {
            self.typical_login_hours.push(hour);
        }

        // Track source IPs
        if let Some(ref ip) = log.source_ip {
            if !self.typical_source_ips.contains(ip) && self.typical_source_ips.len() < 20 {
                self.typical_source_ips.push(ip.clone());
            }
        }

        // Track login attempts
        if log.message.to_lowercase().contains("failed")
            && log.message.to_lowercase().contains("login")
        {
            self.failed_logins += 1;
        } else if log.message.to_lowercase().contains("successful")
            && log.message.to_lowercase().contains("login")
        {
            self.successful_logins += 1;
        }

        // Track resource access
        if let Some(resource) = log.metadata.get("resource") {
            *self.accessed_resources.entry(resource.clone()).or_insert(0) += 1;
        }
    }

    /// Calculate anomaly score for this event
    pub fn calculate_anomaly_score(&self, log: &LogEntry) -> f64 {
        let mut score = 0.0;

        // Check if login hour is unusual (30% weight)
        let hour = log.timestamp.hour();
        if !self.typical_login_hours.is_empty() && !self.typical_login_hours.contains(&hour) {
            score += 30.0;
        }

        // Check if source IP is unusual (30% weight)
        if let Some(ref ip) = log.source_ip {
            if !self.typical_source_ips.is_empty() && !self.typical_source_ips.contains(ip) {
                score += 30.0;
            }
        }

        // Check for unusual resource access (20% weight)
        if let Some(resource) = log.metadata.get("resource") {
            if !self.accessed_resources.contains_key(resource) {
                score += 20.0;
            }
        }

        // Check failure rate (20% weight)
        if self.total_events > 10 {
            let failure_rate = self.failed_logins as f64 / self.total_events as f64;
            if failure_rate > 0.3 {
                score += 20.0;
            }
        }

        score
    }
}

/// Behavioral analytics engine
pub struct BehavioralAnalytics {
    user_profiles: HashMap<String, UserProfile>,
    entity_profiles: HashMap<String, EntityProfile>,
    anomaly_threshold: f64,
}

/// Entity (host/service) behavior profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityProfile {
    pub entity_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub typical_event_rate: f64, // Events per hour
    pub typical_error_rate: f64, // Percentage
    pub unusual_processes: Vec<String>,
    pub network_connections: HashMap<String, usize>,
}

impl EntityProfile {
    pub fn new(entity_id: String) -> Self {
        Self {
            entity_id,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            typical_event_rate: 100.0,
            typical_error_rate: 0.05,
            unusual_processes: Vec::new(),
            network_connections: HashMap::new(),
        }
    }
}

impl BehavioralAnalytics {
    /// Create new behavioral analytics engine
    pub fn new(anomaly_threshold: f64) -> Self {
        Self {
            user_profiles: HashMap::new(),
            entity_profiles: HashMap::new(),
            anomaly_threshold,
        }
    }

    /// Analyze log for behavioral anomalies
    pub fn analyze(&mut self, log: &LogEntry) -> Option<ThreatAlert> {
        // Get or create user profile
        let user_id = log.user.clone().unwrap_or_else(|| "unknown".to_string());
        let profile = self
            .user_profiles
            .entry(user_id.clone())
            .or_insert_with(|| UserProfile::new(user_id.clone()));

        // Calculate anomaly score before updating profile
        let anomaly_score = profile.calculate_anomaly_score(log);

        // Update profile
        profile.update(log);

        // Generate alert if score exceeds threshold
        if anomaly_score >= self.anomaly_threshold {
            let severity = if anomaly_score >= 80.0 {
                ThreatSeverity::Critical
            } else if anomaly_score >= 60.0 {
                ThreatSeverity::High
            } else if anomaly_score >= 40.0 {
                ThreatSeverity::Medium
            } else {
                ThreatSeverity::Low
            };

            Some(ThreatAlert {
                alert_id: format!("UEBA-{}", chrono::Utc::now().timestamp()),
                timestamp: Utc::now(),
                severity,
                category: ThreatCategory::AnomalousActivity,
                description: format!(
                    "Anomalous behavior detected for user '{}' (score: {:.1})",
                    user_id, anomaly_score
                ),
                source_log: format!("{} - {}", log.timestamp, log.message),
                indicators: self.build_indicators(&user_id, log, anomaly_score),
                recommended_action:
                    "Review user activity, verify identity, check for compromised credentials"
                        .to_string(),
                threat_score: anomaly_score as u32,
                correlated_alerts: vec![],
            })
        } else {
            None
        }
    }

    /// Build anomaly indicators
    fn build_indicators(&self, user_id: &str, log: &LogEntry, score: f64) -> Vec<String> {
        let mut indicators = Vec::new();

        if let Some(profile) = self.user_profiles.get(user_id) {
            let hour = log.timestamp.hour();
            if !profile.typical_login_hours.is_empty()
                && !profile.typical_login_hours.contains(&hour)
            {
                indicators.push(format!("Unusual login hour: {}", hour));
            }

            if let Some(ref ip) = log.source_ip {
                if !profile.typical_source_ips.is_empty()
                    && !profile.typical_source_ips.contains(ip)
                {
                    indicators.push(format!("Unusual source IP: {}", ip));
                }
            }

            if profile.total_events > 10 {
                let failure_rate = profile.failed_logins as f64 / profile.total_events as f64;
                if failure_rate > 0.3 {
                    indicators.push(format!("High failure rate: {:.1}%", failure_rate * 100.0));
                }
            }
        }

        if indicators.is_empty() {
            indicators.push(format!("Anomaly score: {:.1}", score));
        }

        indicators
    }

    /// Get user profile
    pub fn get_user_profile(&self, user_id: &str) -> Option<&UserProfile> {
        self.user_profiles.get(user_id)
    }

    /// Get all user profiles
    pub fn get_all_profiles(&self) -> Vec<&UserProfile> {
        self.user_profiles.values().collect()
    }

    /// Get high-risk users (those with many anomalies)
    pub fn get_high_risk_users(&self, min_failed_logins: usize) -> Vec<&UserProfile> {
        self.user_profiles
            .values()
            .filter(|profile| profile.failed_logins >= min_failed_logins)
            .collect()
    }

    /// Clear old profiles to manage memory
    pub fn clear_old_profiles(&mut self, before: DateTime<Utc>) {
        self.user_profiles
            .retain(|_, profile| profile.last_seen >= before);
        self.entity_profiles
            .retain(|_, profile| profile.last_seen >= before);
    }

    /// Get statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_users".to_string(), self.user_profiles.len());
        stats.insert("total_entities".to_string(), self.entity_profiles.len());

        let active_users = self
            .user_profiles
            .values()
            .filter(|p| p.last_seen >= Utc::now() - Duration::hours(24))
            .count();
        stats.insert("active_users_24h".to_string(), active_users);

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_log(user: &str, ip: &str, hour: u32) -> LogEntry {
        let mut timestamp = Utc::now();
        timestamp = timestamp
            .date_naive()
            .and_hms_opt(hour, 0, 0)
            .unwrap()
            .and_utc();

        LogEntry {
            timestamp,
            source_ip: Some(ip.to_string()),
            user: Some(user.to_string()),
            event_type: "login".to_string(),
            message: "User login attempt".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_user_profile_creation() {
        let profile = UserProfile::new("test_user".to_string());
        assert_eq!(profile.user_id, "test_user");
        assert_eq!(profile.total_events, 0);
    }

    #[test]
    fn test_user_profile_update() {
        let mut profile = UserProfile::new("test_user".to_string());
        let log = create_log("test_user", "192.168.1.1", 9);

        profile.update(&log);

        assert_eq!(profile.total_events, 1);
        assert!(profile.typical_login_hours.contains(&9));
        assert!(profile
            .typical_source_ips
            .contains(&"192.168.1.1".to_string()));
    }

    #[test]
    fn test_anomaly_detection_unusual_hour() {
        let mut analytics = BehavioralAnalytics::new(25.0); // Low threshold for testing

        // Establish baseline - user logs in at 9 AM
        for _ in 0..5 {
            let log = create_log("alice", "192.168.1.100", 9);
            analytics.analyze(&log);
        }

        // Login at unusual hour (3 AM)
        let unusual_log = create_log("alice", "192.168.1.100", 3);
        let alert = analytics.analyze(&unusual_log);

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.category, ThreatCategory::AnomalousActivity);
        assert!(alert.threat_score >= 25);
    }

    #[test]
    fn test_anomaly_detection_unusual_ip() {
        let mut analytics = BehavioralAnalytics::new(25.0);

        // Establish baseline - user from office IP
        for _ in 0..5 {
            let log = create_log("bob", "192.168.1.50", 10);
            analytics.analyze(&log);
        }

        // Login from unusual IP
        let unusual_log = create_log("bob", "1.2.3.4", 10);
        let alert = analytics.analyze(&unusual_log);

        assert!(alert.is_some());
    }

    #[test]
    fn test_no_anomaly_normal_behavior() {
        let mut analytics = BehavioralAnalytics::new(50.0);

        // Establish baseline
        for _ in 0..10 {
            let log = create_log("carol", "192.168.1.75", 14);
            analytics.analyze(&log);
        }

        // Normal login
        let normal_log = create_log("carol", "192.168.1.75", 14);
        let alert = analytics.analyze(&normal_log);

        assert!(alert.is_none());
    }

    #[test]
    fn test_get_user_profile() {
        let mut analytics = BehavioralAnalytics::new(50.0);

        let log = create_log("dave", "192.168.1.88", 11);
        analytics.analyze(&log);

        let profile = analytics.get_user_profile("dave");
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().user_id, "dave");
    }

    #[test]
    fn test_high_risk_users() {
        let mut analytics = BehavioralAnalytics::new(50.0);

        // Create user with many failed logins
        for _ in 0..10 {
            let mut log = create_log("risky_user", "192.168.1.99", 10);
            log.message = "Failed login attempt".to_string();
            analytics.analyze(&log);
        }

        let high_risk = analytics.get_high_risk_users(5);
        assert_eq!(high_risk.len(), 1);
        assert_eq!(high_risk[0].user_id, "risky_user");
    }

    #[test]
    fn test_clear_old_profiles() {
        let mut analytics = BehavioralAnalytics::new(50.0);

        let old_time = Utc::now() - Duration::hours(25);
        let mut log = create_log("old_user", "192.168.1.1", 10);
        log.timestamp = old_time;
        analytics.analyze(&log);

        assert_eq!(analytics.user_profiles.len(), 1);

        let cutoff = Utc::now() - Duration::hours(24);
        analytics.clear_old_profiles(cutoff);

        assert_eq!(analytics.user_profiles.len(), 0);
    }

    #[test]
    fn test_stats() {
        let mut analytics = BehavioralAnalytics::new(50.0);

        let log1 = create_log("user1", "192.168.1.1", 10);
        let log2 = create_log("user2", "192.168.1.2", 11);

        analytics.analyze(&log1);
        analytics.analyze(&log2);

        let stats = analytics.get_stats();
        assert_eq!(stats.get("total_users"), Some(&2));
    }
}
