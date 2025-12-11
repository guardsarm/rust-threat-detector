//! Automated Incident Response Example
//!
//! Demonstrates the incident response capabilities including
//! playbook execution, incident lifecycle, and statistics.

use chrono::Utc;
use std::collections::HashMap;
use rust_threat_detector::{
    IncidentResponseManager, IncidentStatus, ThreatAlert,
    ThreatCategory, ThreatSeverity, ResponseAction, Playbook,
    PlaybookAction, incident_response::FailureAction,
};

fn main() {
    println!("=== Automated Incident Response Demo v2.0 ===\n");

    let mut manager = IncidentResponseManager::new();

    // Example 1: Create incident from alert
    println!("--- Example 1: Create Incident from Alert ---");
    let alert = ThreatAlert {
        alert_id: "ALERT-001".to_string(),
        timestamp: Utc::now(),
        severity: ThreatSeverity::High,
        category: ThreatCategory::BruteForce,
        description: "Multiple failed login attempts detected from external IP".to_string(),
        source_log: "auth.log - 500 failed attempts in 10 minutes".to_string(),
        indicators: vec!["203.0.113.50".to_string(), "admin".to_string()],
        recommended_action: "Block source IP and review user account".to_string(),
        threat_score: 85,
        correlated_alerts: vec![],
    };

    let incident_id = manager.create_incident(&alert);
    println!("Created incident: {}", incident_id);

    // Get and display incident details
    if let Some(incident) = manager.get_incident(&incident_id) {
        println!("  Title: {}", incident.title);
        println!("  Status: {:?}", incident.status);
        println!("  Severity: {:?}", incident.severity);
        println!("  Category: {:?}", incident.category);
    }

    // Example 2: Find and execute playbooks
    println!("\n--- Example 2: Execute Response Playbook ---");
    let playbook = {
        manager.find_playbooks(&alert).first().map(|&p| p.clone())
    };

    if let Some(playbook) = playbook {
        println!("Found applicable playbook: {}", playbook.name);
        println!("  Actions to execute: {}", playbook.actions.len());

        let mut context = HashMap::new();
        context.insert("source_ip".to_string(), "203.0.113.50".to_string());
        context.insert("username".to_string(), "admin".to_string());

        let results = manager.execute_playbook(&incident_id, &playbook, &context);
        println!("  Executed {} actions:", results.len());
        for result in &results {
            println!("    - {}: {} ({}ms)",
                result.action.name(),
                if result.success { "Success" } else { "Failed" },
                result.execution_time_ms
            );
        }
    }

    // Example 3: Incident lifecycle
    println!("\n--- Example 3: Incident Lifecycle ---");
    if let Some(incident) = manager.get_incident_mut(&incident_id) {
        // Acknowledge the incident
        incident.update_status(IncidentStatus::Acknowledged, "analyst1");
        println!("Status updated to: {:?}", incident.status);

        // Add investigation note
        incident.add_note("analyst1", "Initial triage complete. IP belongs to known malicious range.");
        println!("Added investigation note");

        // Update to investigating
        incident.update_status(IncidentStatus::Investigating, "analyst1");
        println!("Status updated to: {:?}", incident.status);

        // Update to containing
        incident.update_status(IncidentStatus::Containing, "analyst1");
        println!("Status updated to: {:?}", incident.status);

        // Show timeline
        println!("\nIncident Timeline:");
        for entry in &incident.timeline {
            println!("  [{}] {} by {}: {}",
                entry.timestamp.format("%H:%M:%S"),
                entry.event_type,
                entry.actor,
                entry.description
            );
        }

        // Show metrics
        println!("\nIncident Metrics:");
        println!("  Time to Acknowledge: {:?} seconds", incident.metrics.time_to_acknowledge_seconds);
        println!("  Time to Contain: {:?} seconds", incident.metrics.time_to_contain_seconds);
        println!("  Total Actions: {}", incident.metrics.total_actions);
        println!("  Successful Actions: {}", incident.metrics.successful_actions);
    }

    // Example 4: Create multiple incidents for statistics
    println!("\n--- Example 4: Incident Statistics ---");

    // Create a few more incidents
    for i in 2..=5 {
        let test_alert = ThreatAlert {
            alert_id: format!("ALERT-{:03}", i),
            timestamp: Utc::now(),
            severity: if i % 2 == 0 { ThreatSeverity::High } else { ThreatSeverity::Medium },
            category: if i % 3 == 0 { ThreatCategory::MalwareDetection } else { ThreatCategory::BruteForce },
            description: format!("Test alert {}", i),
            source_log: "test.log".to_string(),
            indicators: vec![],
            recommended_action: "Investigate".to_string(),
            threat_score: 60 + i * 5,
            correlated_alerts: vec![],
        };
        manager.create_incident(&test_alert);
    }

    let stats = manager.get_statistics();
    println!("Incident Statistics:");
    println!("  Total Incidents: {}", stats.total_incidents);
    println!("  Active Incidents: {}", stats.active_incidents);
    println!("  Resolved Incidents: {}", stats.resolved_incidents);
    println!("  By Severity:");
    for (severity, count) in &stats.by_severity {
        println!("    {:?}: {}", severity, count);
    }
    println!("  By Category:");
    for (category, count) in &stats.by_category {
        println!("    {:?}: {}", category, count);
    }

    // Example 5: List available playbooks
    println!("\n--- Example 5: Available Playbooks ---");
    let playbooks = manager.get_playbooks();
    println!("Available playbooks: {}", playbooks.len());
    for pb in playbooks {
        println!("\n  {} ({})", pb.name, pb.id);
        println!("    Description: {}", pb.description);
        println!("    Categories: {:?}", pb.threat_categories);
        println!("    Min Severity: {:?}", pb.min_severity);
        println!("    Requires Approval: {}", pb.requires_approval);
        println!("    Actions: {}", pb.actions.len());
    }

    // Example 6: Query active and high-severity incidents
    println!("\n--- Example 6: Query Incidents ---");

    let active = manager.get_active_incidents();
    println!("Active incidents: {}", active.len());

    let high_severity = manager.get_incidents_by_severity(ThreatSeverity::High);
    println!("High severity or above: {}", high_severity.len());

    // Example 7: Custom response action
    println!("\n--- Example 7: Response Action Types ---");
    let actions = vec![
        ResponseAction::BlockIP { ip: "1.2.3.4".to_string(), duration_hours: 24 },
        ResponseAction::DisableAccount { account: "compromised_user".to_string() },
        ResponseAction::IsolateHost { hostname: "infected-host".to_string() },
        ResponseAction::NotifyTeam { team: "SOC".to_string(), message: "Critical incident".to_string() },
        ResponseAction::EscalateToSOC { priority: "P1".to_string() },
    ];

    println!("Available response actions:");
    for action in &actions {
        println!("  - {} (reversible: {})", action.name(), action.is_reversible());
    }

    println!("\n=== Demo Complete ===");
}
