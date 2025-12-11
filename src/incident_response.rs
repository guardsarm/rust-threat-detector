//! Automated Incident Response Module v2.0
//!
//! Provides automated response playbooks, incident tracking, and
//! remediation workflows for detected threats.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{ThreatAlert, ThreatCategory, ThreatSeverity};

/// Incident status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    Acknowledged,
    Investigating,
    Containing,
    Eradicating,
    Recovering,
    Resolved,
    Closed,
}

impl IncidentStatus {
    /// Get next expected status
    pub fn next(&self) -> Option<IncidentStatus> {
        match self {
            IncidentStatus::New => Some(IncidentStatus::Acknowledged),
            IncidentStatus::Acknowledged => Some(IncidentStatus::Investigating),
            IncidentStatus::Investigating => Some(IncidentStatus::Containing),
            IncidentStatus::Containing => Some(IncidentStatus::Eradicating),
            IncidentStatus::Eradicating => Some(IncidentStatus::Recovering),
            IncidentStatus::Recovering => Some(IncidentStatus::Resolved),
            IncidentStatus::Resolved => Some(IncidentStatus::Closed),
            IncidentStatus::Closed => None,
        }
    }

    /// Check if incident is active
    pub fn is_active(&self) -> bool {
        !matches!(self, IncidentStatus::Resolved | IncidentStatus::Closed)
    }
}

/// Response action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    BlockIP { ip: String, duration_hours: u32 },
    DisableAccount { account: String },
    IsolateHost { hostname: String },
    TerminateSession { session_id: String },
    NotifyTeam { team: String, message: String },
    CreateTicket { system: String, priority: String },
    CollectEvidence { sources: Vec<String> },
    RunScan { scan_type: String, target: String },
    ResetCredentials { account: String },
    EnableMFA { account: String },
    UpdateFirewall { rule: String },
    EscalateToSOC { priority: String },
    Custom { name: String, parameters: HashMap<String, String> },
}

impl ResponseAction {
    /// Get action name
    pub fn name(&self) -> &str {
        match self {
            ResponseAction::BlockIP { .. } => "Block IP Address",
            ResponseAction::DisableAccount { .. } => "Disable Account",
            ResponseAction::IsolateHost { .. } => "Isolate Host",
            ResponseAction::TerminateSession { .. } => "Terminate Session",
            ResponseAction::NotifyTeam { .. } => "Notify Team",
            ResponseAction::CreateTicket { .. } => "Create Ticket",
            ResponseAction::CollectEvidence { .. } => "Collect Evidence",
            ResponseAction::RunScan { .. } => "Run Security Scan",
            ResponseAction::ResetCredentials { .. } => "Reset Credentials",
            ResponseAction::EnableMFA { .. } => "Enable MFA",
            ResponseAction::UpdateFirewall { .. } => "Update Firewall",
            ResponseAction::EscalateToSOC { .. } => "Escalate to SOC",
            ResponseAction::Custom { name, .. } => name,
        }
    }

    /// Check if action is reversible
    pub fn is_reversible(&self) -> bool {
        matches!(
            self,
            ResponseAction::BlockIP { .. }
            | ResponseAction::DisableAccount { .. }
            | ResponseAction::IsolateHost { .. }
        )
    }
}

/// Response action result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: ResponseAction,
    pub success: bool,
    pub executed_at: DateTime<Utc>,
    pub message: String,
    pub execution_time_ms: u64,
}

/// Response playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub threat_categories: Vec<ThreatCategory>,
    pub min_severity: ThreatSeverity,
    pub actions: Vec<PlaybookAction>,
    pub enabled: bool,
    pub requires_approval: bool,
}

/// Playbook action with conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAction {
    pub action: ResponseAction,
    pub order: u32,
    pub condition: Option<String>,
    pub timeout_seconds: u32,
    pub on_failure: FailureAction,
}

/// What to do on action failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureAction {
    Continue,
    Stop,
    Retry { max_attempts: u32 },
    Escalate,
}

/// Security incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: IncidentStatus,
    pub severity: ThreatSeverity,
    pub category: ThreatCategory,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub assigned_to: Option<String>,
    pub related_alerts: Vec<String>,
    pub affected_assets: Vec<String>,
    pub actions_taken: Vec<ActionResult>,
    pub notes: Vec<IncidentNote>,
    pub timeline: Vec<TimelineEntry>,
    pub metrics: IncidentMetrics,
}

/// Incident note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentNote {
    pub id: String,
    pub author: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

/// Timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub actor: String,
}

/// Incident metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentMetrics {
    pub time_to_detect_seconds: i64,
    pub time_to_acknowledge_seconds: Option<i64>,
    pub time_to_contain_seconds: Option<i64>,
    pub time_to_resolve_seconds: Option<i64>,
    pub total_actions: usize,
    pub successful_actions: usize,
}

impl Incident {
    /// Create new incident from alert
    pub fn from_alert(alert: &ThreatAlert) -> Self {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        Self {
            id: id.clone(),
            title: format!("{:?}: {}", alert.category, alert.description),
            description: alert.description.clone(),
            status: IncidentStatus::New,
            severity: alert.severity,
            category: alert.category.clone(),
            created_at: now,
            updated_at: now,
            acknowledged_at: None,
            resolved_at: None,
            assigned_to: None,
            related_alerts: vec![alert.alert_id.clone()],
            affected_assets: alert.indicators.clone(),
            actions_taken: Vec::new(),
            notes: Vec::new(),
            timeline: vec![TimelineEntry {
                timestamp: now,
                event_type: "Created".to_string(),
                description: "Incident created from alert".to_string(),
                actor: "System".to_string(),
            }],
            metrics: IncidentMetrics {
                time_to_detect_seconds: 0,
                time_to_acknowledge_seconds: None,
                time_to_contain_seconds: None,
                time_to_resolve_seconds: None,
                total_actions: 0,
                successful_actions: 0,
            },
        }
    }

    /// Update incident status
    pub fn update_status(&mut self, new_status: IncidentStatus, actor: &str) {
        let old_status = self.status;
        self.status = new_status;
        self.updated_at = Utc::now();

        self.timeline.push(TimelineEntry {
            timestamp: Utc::now(),
            event_type: "Status Change".to_string(),
            description: format!("{:?} -> {:?}", old_status, new_status),
            actor: actor.to_string(),
        });

        // Update metrics
        match new_status {
            IncidentStatus::Acknowledged => {
                self.acknowledged_at = Some(Utc::now());
                self.metrics.time_to_acknowledge_seconds = Some(
                    (Utc::now() - self.created_at).num_seconds()
                );
            }
            IncidentStatus::Containing => {
                self.metrics.time_to_contain_seconds = Some(
                    (Utc::now() - self.created_at).num_seconds()
                );
            }
            IncidentStatus::Resolved => {
                self.resolved_at = Some(Utc::now());
                self.metrics.time_to_resolve_seconds = Some(
                    (Utc::now() - self.created_at).num_seconds()
                );
            }
            _ => {}
        }
    }

    /// Add action result
    pub fn add_action_result(&mut self, result: ActionResult) {
        self.metrics.total_actions += 1;
        if result.success {
            self.metrics.successful_actions += 1;
        }

        self.timeline.push(TimelineEntry {
            timestamp: result.executed_at,
            event_type: "Action Executed".to_string(),
            description: format!("{}: {}", result.action.name(), result.message),
            actor: "System".to_string(),
        });

        self.actions_taken.push(result);
        self.updated_at = Utc::now();
    }

    /// Add note to incident
    pub fn add_note(&mut self, author: &str, content: &str) {
        self.notes.push(IncidentNote {
            id: Uuid::new_v4().to_string(),
            author: author.to_string(),
            content: content.to_string(),
            created_at: Utc::now(),
        });
        self.updated_at = Utc::now();
    }

    /// Calculate incident duration
    pub fn duration(&self) -> Duration {
        let end_time = self.resolved_at.unwrap_or_else(Utc::now);
        end_time - self.created_at
    }

    /// Check if incident is overdue
    pub fn is_overdue(&self, sla_hours: i64) -> bool {
        if !self.status.is_active() {
            return false;
        }
        let elapsed = Utc::now() - self.created_at;
        elapsed.num_hours() > sla_hours
    }
}

/// Incident response manager
pub struct IncidentResponseManager {
    incidents: HashMap<String, Incident>,
    playbooks: Vec<Playbook>,
    auto_response_enabled: bool,
}

impl IncidentResponseManager {
    /// Create new incident response manager
    pub fn new() -> Self {
        let mut manager = Self {
            incidents: HashMap::new(),
            playbooks: Vec::new(),
            auto_response_enabled: true,
        };
        manager.load_default_playbooks();
        manager
    }

    /// Load default response playbooks
    fn load_default_playbooks(&mut self) {
        // Brute Force Response Playbook
        self.playbooks.push(Playbook {
            id: "PB-001".to_string(),
            name: "Brute Force Attack Response".to_string(),
            description: "Automated response to brute force attacks".to_string(),
            threat_categories: vec![ThreatCategory::BruteForce],
            min_severity: ThreatSeverity::Medium,
            actions: vec![
                PlaybookAction {
                    action: ResponseAction::BlockIP {
                        ip: "{{source_ip}}".to_string(),
                        duration_hours: 24,
                    },
                    order: 1,
                    condition: None,
                    timeout_seconds: 30,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::NotifyTeam {
                        team: "Security".to_string(),
                        message: "Brute force attack detected".to_string(),
                    },
                    order: 2,
                    condition: None,
                    timeout_seconds: 10,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::CollectEvidence {
                        sources: vec!["auth_logs".to_string(), "firewall_logs".to_string()],
                    },
                    order: 3,
                    condition: None,
                    timeout_seconds: 60,
                    on_failure: FailureAction::Continue,
                },
            ],
            enabled: true,
            requires_approval: false,
        });

        // Malware Response Playbook
        self.playbooks.push(Playbook {
            id: "PB-002".to_string(),
            name: "Malware Detection Response".to_string(),
            description: "Critical response to malware detection".to_string(),
            threat_categories: vec![ThreatCategory::MalwareDetection],
            min_severity: ThreatSeverity::High,
            actions: vec![
                PlaybookAction {
                    action: ResponseAction::IsolateHost {
                        hostname: "{{hostname}}".to_string(),
                    },
                    order: 1,
                    condition: None,
                    timeout_seconds: 60,
                    on_failure: FailureAction::Escalate,
                },
                PlaybookAction {
                    action: ResponseAction::EscalateToSOC {
                        priority: "Critical".to_string(),
                    },
                    order: 2,
                    condition: None,
                    timeout_seconds: 10,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::RunScan {
                        scan_type: "full_antivirus".to_string(),
                        target: "{{hostname}}".to_string(),
                    },
                    order: 3,
                    condition: None,
                    timeout_seconds: 300,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::CollectEvidence {
                        sources: vec!["memory_dump".to_string(), "process_list".to_string(), "network_connections".to_string()],
                    },
                    order: 4,
                    condition: None,
                    timeout_seconds: 120,
                    on_failure: FailureAction::Continue,
                },
            ],
            enabled: true,
            requires_approval: false,
        });

        // Data Exfiltration Response Playbook
        self.playbooks.push(Playbook {
            id: "PB-003".to_string(),
            name: "Data Exfiltration Response".to_string(),
            description: "Response to potential data theft".to_string(),
            threat_categories: vec![ThreatCategory::DataExfiltration],
            min_severity: ThreatSeverity::High,
            actions: vec![
                PlaybookAction {
                    action: ResponseAction::BlockIP {
                        ip: "{{destination_ip}}".to_string(),
                        duration_hours: 168, // 1 week
                    },
                    order: 1,
                    condition: None,
                    timeout_seconds: 30,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::TerminateSession {
                        session_id: "{{session_id}}".to_string(),
                    },
                    order: 2,
                    condition: None,
                    timeout_seconds: 10,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::DisableAccount {
                        account: "{{username}}".to_string(),
                    },
                    order: 3,
                    condition: Some("severity >= High".to_string()),
                    timeout_seconds: 10,
                    on_failure: FailureAction::Escalate,
                },
                PlaybookAction {
                    action: ResponseAction::CreateTicket {
                        system: "ServiceNow".to_string(),
                        priority: "P1".to_string(),
                    },
                    order: 4,
                    condition: None,
                    timeout_seconds: 30,
                    on_failure: FailureAction::Continue,
                },
            ],
            enabled: true,
            requires_approval: true,
        });

        // Unauthorized Access Response Playbook
        self.playbooks.push(Playbook {
            id: "PB-004".to_string(),
            name: "Unauthorized Access Response".to_string(),
            description: "Response to privilege escalation and unauthorized access".to_string(),
            threat_categories: vec![ThreatCategory::UnauthorizedAccess],
            min_severity: ThreatSeverity::High,
            actions: vec![
                PlaybookAction {
                    action: ResponseAction::DisableAccount {
                        account: "{{username}}".to_string(),
                    },
                    order: 1,
                    condition: None,
                    timeout_seconds: 10,
                    on_failure: FailureAction::Escalate,
                },
                PlaybookAction {
                    action: ResponseAction::ResetCredentials {
                        account: "{{username}}".to_string(),
                    },
                    order: 2,
                    condition: None,
                    timeout_seconds: 30,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::EnableMFA {
                        account: "{{username}}".to_string(),
                    },
                    order: 3,
                    condition: None,
                    timeout_seconds: 30,
                    on_failure: FailureAction::Continue,
                },
                PlaybookAction {
                    action: ResponseAction::EscalateToSOC {
                        priority: "High".to_string(),
                    },
                    order: 4,
                    condition: None,
                    timeout_seconds: 10,
                    on_failure: FailureAction::Continue,
                },
            ],
            enabled: true,
            requires_approval: false,
        });
    }

    /// Create incident from alert
    pub fn create_incident(&mut self, alert: &ThreatAlert) -> String {
        let incident = Incident::from_alert(alert);
        let id = incident.id.clone();
        self.incidents.insert(id.clone(), incident);
        id
    }

    /// Get incident by ID
    pub fn get_incident(&self, id: &str) -> Option<&Incident> {
        self.incidents.get(id)
    }

    /// Get mutable incident
    pub fn get_incident_mut(&mut self, id: &str) -> Option<&mut Incident> {
        self.incidents.get_mut(id)
    }

    /// Find applicable playbooks for an alert
    pub fn find_playbooks(&self, alert: &ThreatAlert) -> Vec<&Playbook> {
        self.playbooks
            .iter()
            .filter(|pb| {
                pb.enabled
                    && pb.threat_categories.contains(&alert.category)
                    && alert.severity >= pb.min_severity
            })
            .collect()
    }

    /// Execute playbook actions (simulated)
    pub fn execute_playbook(&mut self, incident_id: &str, playbook: &Playbook, context: &HashMap<String, String>) -> Vec<ActionResult> {
        let mut results = Vec::new();

        for pb_action in &playbook.actions {
            let action = self.substitute_variables(&pb_action.action, context);

            // Simulate action execution
            let result = ActionResult {
                action,
                success: true, // In real implementation, this would be actual execution
                executed_at: Utc::now(),
                message: "Action executed successfully".to_string(),
                execution_time_ms: 100,
            };

            results.push(result.clone());

            // Update incident if it exists
            if let Some(incident) = self.incidents.get_mut(incident_id) {
                incident.add_action_result(result);
            }
        }

        results
    }

    /// Substitute variables in action
    fn substitute_variables(&self, action: &ResponseAction, context: &HashMap<String, String>) -> ResponseAction {
        match action {
            ResponseAction::BlockIP { ip, duration_hours } => {
                ResponseAction::BlockIP {
                    ip: self.substitute_var(ip, context),
                    duration_hours: *duration_hours,
                }
            }
            ResponseAction::DisableAccount { account } => {
                ResponseAction::DisableAccount {
                    account: self.substitute_var(account, context),
                }
            }
            ResponseAction::IsolateHost { hostname } => {
                ResponseAction::IsolateHost {
                    hostname: self.substitute_var(hostname, context),
                }
            }
            ResponseAction::TerminateSession { session_id } => {
                ResponseAction::TerminateSession {
                    session_id: self.substitute_var(session_id, context),
                }
            }
            ResponseAction::RunScan { scan_type, target } => {
                ResponseAction::RunScan {
                    scan_type: scan_type.clone(),
                    target: self.substitute_var(target, context),
                }
            }
            ResponseAction::ResetCredentials { account } => {
                ResponseAction::ResetCredentials {
                    account: self.substitute_var(account, context),
                }
            }
            ResponseAction::EnableMFA { account } => {
                ResponseAction::EnableMFA {
                    account: self.substitute_var(account, context),
                }
            }
            _ => action.clone(),
        }
    }

    /// Substitute variable placeholders
    fn substitute_var(&self, template: &str, context: &HashMap<String, String>) -> String {
        let mut result = template.to_string();
        for (key, value) in context {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        result
    }

    /// Get active incidents
    pub fn get_active_incidents(&self) -> Vec<&Incident> {
        self.incidents
            .values()
            .filter(|i| i.status.is_active())
            .collect()
    }

    /// Get incidents by severity
    pub fn get_incidents_by_severity(&self, min_severity: ThreatSeverity) -> Vec<&Incident> {
        self.incidents
            .values()
            .filter(|i| i.severity >= min_severity)
            .collect()
    }

    /// Get overdue incidents
    pub fn get_overdue_incidents(&self, sla_hours: i64) -> Vec<&Incident> {
        self.incidents
            .values()
            .filter(|i| i.is_overdue(sla_hours))
            .collect()
    }

    /// Get incident statistics
    pub fn get_statistics(&self) -> IncidentStatistics {
        let total = self.incidents.len();
        let active = self.incidents.values().filter(|i| i.status.is_active()).count();
        let resolved = self.incidents.values().filter(|i| matches!(i.status, IncidentStatus::Resolved | IncidentStatus::Closed)).count();

        let mut by_severity: HashMap<ThreatSeverity, usize> = HashMap::new();
        let mut by_category: HashMap<ThreatCategory, usize> = HashMap::new();

        for incident in self.incidents.values() {
            *by_severity.entry(incident.severity).or_insert(0) += 1;
            *by_category.entry(incident.category.clone()).or_insert(0) += 1;
        }

        let avg_resolution_time = self.calculate_avg_resolution_time();

        IncidentStatistics {
            total_incidents: total,
            active_incidents: active,
            resolved_incidents: resolved,
            by_severity,
            by_category,
            average_resolution_time_hours: avg_resolution_time,
        }
    }

    /// Calculate average resolution time
    fn calculate_avg_resolution_time(&self) -> f64 {
        let resolved: Vec<&Incident> = self.incidents
            .values()
            .filter(|i| i.metrics.time_to_resolve_seconds.is_some())
            .collect();

        if resolved.is_empty() {
            return 0.0;
        }

        let total_seconds: i64 = resolved
            .iter()
            .filter_map(|i| i.metrics.time_to_resolve_seconds)
            .sum();

        (total_seconds as f64 / resolved.len() as f64) / 3600.0
    }

    /// Enable/disable auto response
    pub fn set_auto_response(&mut self, enabled: bool) {
        self.auto_response_enabled = enabled;
    }

    /// Add custom playbook
    pub fn add_playbook(&mut self, playbook: Playbook) {
        self.playbooks.push(playbook);
    }

    /// Get all playbooks
    pub fn get_playbooks(&self) -> &[Playbook] {
        &self.playbooks
    }
}

impl Default for IncidentResponseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Incident statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentStatistics {
    pub total_incidents: usize,
    pub active_incidents: usize,
    pub resolved_incidents: usize,
    pub by_severity: HashMap<ThreatSeverity, usize>,
    pub by_category: HashMap<ThreatCategory, usize>,
    pub average_resolution_time_hours: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_alert() -> ThreatAlert {
        ThreatAlert {
            alert_id: "TEST-001".to_string(),
            timestamp: Utc::now(),
            severity: ThreatSeverity::High,
            category: ThreatCategory::BruteForce,
            description: "Test brute force alert".to_string(),
            source_log: "Test log".to_string(),
            indicators: vec!["192.168.1.100".to_string()],
            recommended_action: "Block IP".to_string(),
            threat_score: 80,
            correlated_alerts: vec![],
        }
    }

    #[test]
    fn test_incident_creation() {
        let alert = create_test_alert();
        let incident = Incident::from_alert(&alert);

        assert_eq!(incident.status, IncidentStatus::New);
        assert_eq!(incident.severity, ThreatSeverity::High);
        assert_eq!(incident.related_alerts.len(), 1);
    }

    #[test]
    fn test_incident_status_progression() {
        let alert = create_test_alert();
        let mut incident = Incident::from_alert(&alert);

        incident.update_status(IncidentStatus::Acknowledged, "analyst");
        assert!(incident.acknowledged_at.is_some());
        assert!(incident.metrics.time_to_acknowledge_seconds.is_some());

        incident.update_status(IncidentStatus::Resolved, "analyst");
        assert!(incident.resolved_at.is_some());
        assert!(incident.metrics.time_to_resolve_seconds.is_some());
    }

    #[test]
    fn test_incident_notes() {
        let alert = create_test_alert();
        let mut incident = Incident::from_alert(&alert);

        incident.add_note("analyst", "Initial investigation started");
        assert_eq!(incident.notes.len(), 1);
        assert_eq!(incident.notes[0].author, "analyst");
    }

    #[test]
    fn test_playbook_finding() {
        let manager = IncidentResponseManager::new();
        let alert = create_test_alert();

        let playbooks = manager.find_playbooks(&alert);
        assert!(!playbooks.is_empty());

        // Should find brute force playbook
        assert!(playbooks.iter().any(|pb| pb.name.contains("Brute Force")));
    }

    #[test]
    fn test_playbook_execution() {
        let mut manager = IncidentResponseManager::new();
        let alert = create_test_alert();

        let incident_id = manager.create_incident(&alert);

        // Clone the playbook to avoid borrow checker issues
        let playbook: Option<Playbook> = {
            manager.find_playbooks(&alert).first().map(|&p| p.clone())
        };

        let mut context = HashMap::new();
        context.insert("source_ip".to_string(), "192.168.1.100".to_string());

        if let Some(playbook) = playbook {
            let results = manager.execute_playbook(&incident_id, &playbook, &context);
            assert!(!results.is_empty());
            assert!(results[0].success);
        }
    }

    #[test]
    fn test_variable_substitution() {
        let manager = IncidentResponseManager::new();
        let mut context = HashMap::new();
        context.insert("source_ip".to_string(), "10.0.0.1".to_string());

        let action = ResponseAction::BlockIP {
            ip: "{{source_ip}}".to_string(),
            duration_hours: 24,
        };

        let substituted = manager.substitute_variables(&action, &context);
        if let ResponseAction::BlockIP { ip, .. } = substituted {
            assert_eq!(ip, "10.0.0.1");
        }
    }

    #[test]
    fn test_active_incidents() {
        let mut manager = IncidentResponseManager::new();

        let alert1 = create_test_alert();
        let id1 = manager.create_incident(&alert1);

        let alert2 = create_test_alert();
        let id2 = manager.create_incident(&alert2);

        // Resolve one incident
        if let Some(incident) = manager.get_incident_mut(&id1) {
            incident.update_status(IncidentStatus::Resolved, "analyst");
        }

        let active = manager.get_active_incidents();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_incident_statistics() {
        let mut manager = IncidentResponseManager::new();

        for _ in 0..5 {
            let alert = create_test_alert();
            manager.create_incident(&alert);
        }

        let stats = manager.get_statistics();
        assert_eq!(stats.total_incidents, 5);
        assert_eq!(stats.active_incidents, 5);
    }

    #[test]
    fn test_incident_overdue() {
        let alert = create_test_alert();
        let mut incident = Incident::from_alert(&alert);

        // New incident should not be overdue with reasonable SLA
        assert!(!incident.is_overdue(24));

        // Resolved incident should not be overdue
        incident.update_status(IncidentStatus::Resolved, "analyst");
        assert!(!incident.is_overdue(1));
    }

    #[test]
    fn test_action_reversibility() {
        let block_action = ResponseAction::BlockIP {
            ip: "10.0.0.1".to_string(),
            duration_hours: 24,
        };
        assert!(block_action.is_reversible());

        let notify_action = ResponseAction::NotifyTeam {
            team: "Security".to_string(),
            message: "Test".to_string(),
        };
        assert!(!notify_action.is_reversible());
    }

    #[test]
    fn test_status_next() {
        assert_eq!(IncidentStatus::New.next(), Some(IncidentStatus::Acknowledged));
        assert_eq!(IncidentStatus::Resolved.next(), Some(IncidentStatus::Closed));
        assert_eq!(IncidentStatus::Closed.next(), None);
    }
}
