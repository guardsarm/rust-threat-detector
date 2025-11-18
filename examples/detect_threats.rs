//! Threat detection example
//!
//! This example demonstrates real-time threat detection for SIEM integration.

use chrono::Utc;
use rust_threat_detector::{LogEntry, ThreatDetector, ThreatSeverity};
use std::collections::HashMap;

fn main() {
    println!("=== SIEM Threat Detection System ===\n");

    // Create threat detector with default patterns
    let mut detector = ThreatDetector::new();

    // Simulate various security logs
    #[allow(clippy::useless_vec)]
    let logs = vec![
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.100".to_string()),
            user: Some("admin".to_string()),
            event_type: "authentication".to_string(),
            message: "Failed login attempt for user admin from 192.168.1.100".to_string(),
            metadata: HashMap::new(),
        },
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("10.0.0.50".to_string()),
            user: Some("user123".to_string()),
            event_type: "file_access".to_string(),
            message: "Malware detected in downloaded file: trojan.exe".to_string(),
            metadata: HashMap::new(),
        },
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("172.16.0.10".to_string()),
            user: Some("dbuser".to_string()),
            event_type: "database_query".to_string(),
            message: "Query: SELECT * FROM users WHERE id='1' OR '1'='1'".to_string(),
            metadata: HashMap::new(),
        },
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.200".to_string()),
            user: Some("operator".to_string()),
            event_type: "system".to_string(),
            message: "Privilege escalation attempt: unauthorized sudo command".to_string(),
            metadata: HashMap::new(),
        },
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("10.1.1.50".to_string()),
            user: Some("ftpuser".to_string()),
            event_type: "network".to_string(),
            message: "Large data transfer detected: 500GB uploaded".to_string(),
            metadata: HashMap::new(),
        },
        LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.150".to_string()),
            user: Some("john.doe".to_string()),
            event_type: "application".to_string(),
            message: "User successfully logged in to web portal".to_string(),
            metadata: HashMap::new(),
        },
    ];

    println!("Analyzing {} log entries for threats...\n", logs.len());

    let mut all_alerts = Vec::new();
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;

    for (i, log) in logs.iter().enumerate() {
        println!("Log #{}: {}", i + 1, log.message);

        let alerts = detector.analyze(log);

        if alerts.is_empty() {
            println!("   ✓ No threats detected\n");
        } else {
            for alert in &alerts {
                println!("   🚨 ALERT: {}", alert.alert_id);
                println!("      Severity: {:?}", alert.severity);
                println!("      Category: {:?}", alert.category);
                println!("      Description: {}", alert.description);
                println!("      Action: {}", alert.recommended_action);
                println!();

                match alert.severity {
                    ThreatSeverity::Critical => critical_count += 1,
                    ThreatSeverity::High => high_count += 1,
                    ThreatSeverity::Medium => medium_count += 1,
                    _ => {}
                }
            }
            all_alerts.extend(alerts);
        }
    }

    // Summary statistics
    println!("=== Detection Summary ===");
    println!("Total logs analyzed: {}", logs.len());
    println!("Total alerts generated: {}", all_alerts.len());
    println!("  Critical: {}", critical_count);
    println!("  High: {}", high_count);
    println!("  Medium: {}", medium_count);

    // Filter critical alerts
    println!("\n=== Critical Alerts (Requires Immediate Action) ===");
    let critical_alerts = detector.filter_by_severity(&all_alerts, ThreatSeverity::Critical);

    for alert in &critical_alerts {
        println!("\n{}", alert.alert_id);
        println!("  Category: {:?}", alert.category);
        println!("  Description: {}", alert.description);
        println!("  Source: {}", alert.source_log);
        println!("  Action Required: {}", alert.recommended_action);
    }

    // Export alerts as JSON for SIEM
    println!("\n=== SIEM Integration Example ===");
    if let Some(first_alert) = all_alerts.first() {
        match first_alert.to_json() {
            Ok(json) => {
                println!("Alert JSON format:");
                println!("{}", json);
            }
            Err(e) => eprintln!("JSON export error: {}", e),
        }
    }

    // Detector statistics
    println!("\n=== Detector Statistics ===");
    let stats = detector.get_stats();
    for (key, value) in stats {
        println!("  {}: {}", key, value);
    }

    println!("\n=== Security Features ===");
    println!("✓ Memory-safe threat detection (no buffer overflows)");
    println!("✓ Real-time log analysis");
    println!("✓ Pre-configured threat patterns");
    println!("✓ Severity-based alerting");
    println!("✓ SIEM integration ready (JSON export)");
    println!("✓ Custom pattern support");

    println!("\n=== Compliance Use Cases ===");
    println!("✓ NIST SP 800-92 - Security log management");
    println!("✓ PCI-DSS Requirement 10 - Log monitoring");
    println!("✓ SOX compliance - IT control monitoring");
    println!("✓ GDPR - Security incident detection");
    println!("✓ MITRE ATT&CK - Threat pattern matching");
}
