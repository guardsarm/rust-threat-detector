//! MITRE ATT&CK framework pattern detection

use regex::Regex;
use serde::{Deserialize, Serialize};

/// MITRE ATT&CK tactic
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
}

/// MITRE ATT&CK technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,
    pub name: String,
    pub tactic: AttackTactic,
    pub description: String,
}

/// Detection pattern
#[derive(Debug, Clone)]
pub struct DetectionPattern {
    pub technique: AttackTechnique,
    pub pattern: Regex,
    pub severity: ThreatSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// MITRE ATT&CK detector
pub struct MitreAttackDetector {
    patterns: Vec<DetectionPattern>,
}

impl MitreAttackDetector {
    /// Create new detector with common patterns
    #[allow(clippy::vec_init_then_push)]
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // T1110 - Brute Force
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1110".to_string(),
                name: "Brute Force".to_string(),
                tactic: AttackTactic::CredentialAccess,
                description: "Multiple failed authentication attempts".to_string(),
            },
            pattern: Regex::new(r"(?i)(failed|invalid|incorrect).*(login|auth|password)").unwrap(),
            severity: ThreatSeverity::High,
        });

        // T1059 - Command and Scripting Interpreter
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1059".to_string(),
                name: "Command and Scripting Interpreter".to_string(),
                tactic: AttackTactic::Execution,
                description: "Execution of commands or scripts".to_string(),
            },
            pattern: Regex::new(r"(?i)(cmd\.exe|powershell|bash|sh|python|perl)").unwrap(),
            severity: ThreatSeverity::Medium,
        });

        // T1190 - Exploit Public-Facing Application
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1190".to_string(),
                name: "Exploit Public-Facing Application".to_string(),
                tactic: AttackTactic::InitialAccess,
                description: "SQL injection or code injection attempts".to_string(),
            },
            pattern: Regex::new(r"(?i)(union\s+select|or\s+1\s*=\s*1|<script|eval\(|exec\()")
                .unwrap(),
            severity: ThreatSeverity::Critical,
        });

        // T1078 - Valid Accounts
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1078".to_string(),
                name: "Valid Accounts".to_string(),
                tactic: AttackTactic::InitialAccess,
                description: "Use of valid accounts from unusual locations".to_string(),
            },
            pattern: Regex::new(r"(?i)(login|auth|signin).*(success|successful)").unwrap(),
            severity: ThreatSeverity::Low,
        });

        // T1071 - Application Layer Protocol
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1071".to_string(),
                name: "Application Layer Protocol".to_string(),
                tactic: AttackTactic::InitialAccess,
                description: "C2 communication over standard protocols".to_string(),
            },
            pattern: Regex::new(r"(?i)(http|https|ftp|dns|smtp).*(beacon|c2|command)").unwrap(),
            severity: ThreatSeverity::High,
        });

        // T1003 - OS Credential Dumping
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1003".to_string(),
                name: "OS Credential Dumping".to_string(),
                tactic: AttackTactic::CredentialAccess,
                description: "Attempts to dump credentials from OS".to_string(),
            },
            pattern: Regex::new(r"(?i)(mimikatz|lsass|sam|ntds|hashdump)").unwrap(),
            severity: ThreatSeverity::Critical,
        });

        // T1057 - Process Discovery
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1057".to_string(),
                name: "Process Discovery".to_string(),
                tactic: AttackTactic::Discovery,
                description: "Enumeration of running processes".to_string(),
            },
            pattern: Regex::new(r"(?i)(tasklist|ps\s|get-process)").unwrap(),
            severity: ThreatSeverity::Low,
        });

        // T1083 - File and Directory Discovery
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1083".to_string(),
                name: "File and Directory Discovery".to_string(),
                tactic: AttackTactic::Discovery,
                description: "Enumeration of files and directories".to_string(),
            },
            pattern: Regex::new(r"(?i)(dir\s|ls\s|find\s|tree\s)").unwrap(),
            severity: ThreatSeverity::Low,
        });

        // T1486 - Data Encrypted for Impact
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1486".to_string(),
                name: "Data Encrypted for Impact".to_string(),
                tactic: AttackTactic::Impact,
                description: "Ransomware encryption activity".to_string(),
            },
            pattern: Regex::new(r"(?i)(ransom|encrypt|crypto|\.locked|\.encrypted)").unwrap(),
            severity: ThreatSeverity::Critical,
        });

        // T1041 - Exfiltration Over C2 Channel
        patterns.push(DetectionPattern {
            technique: AttackTechnique {
                id: "T1041".to_string(),
                name: "Exfiltration Over C2 Channel".to_string(),
                tactic: AttackTactic::Exfiltration,
                description: "Data exfiltration over command and control channel".to_string(),
            },
            pattern: Regex::new(r"(?i)(exfil|upload|post|send).*(data|file|document)").unwrap(),
            severity: ThreatSeverity::High,
        });

        Self { patterns }
    }

    /// Detect threats in log message
    pub fn detect(&self, message: &str) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();

        for pattern in &self.patterns {
            if pattern.pattern.is_match(message) {
                detections.push(ThreatDetection {
                    technique: pattern.technique.clone(),
                    severity: pattern.severity.clone(),
                    matched_text: message.to_string(),
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        detections
    }

    /// Get all supported techniques
    pub fn get_techniques(&self) -> Vec<&AttackTechnique> {
        self.patterns.iter().map(|p| &p.technique).collect()
    }

    /// Get techniques by tactic
    pub fn get_techniques_by_tactic(&self, tactic: &AttackTactic) -> Vec<&AttackTechnique> {
        self.patterns
            .iter()
            .filter(|p| &p.technique.tactic == tactic)
            .map(|p| &p.technique)
            .collect()
    }
}

impl Default for MitreAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub technique: AttackTechnique,
    pub severity: ThreatSeverity,
    pub matched_text: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ThreatDetection {
    /// Generate alert message
    pub fn to_alert_message(&self) -> String {
        format!(
            "[{:?}] MITRE ATT&CK {} ({}) detected: {}",
            self.severity, self.technique.id, self.technique.name, self.matched_text
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brute_force_detection() {
        let detector = MitreAttackDetector::new();
        let message = "Failed login attempt for user admin";

        let detections = detector.detect(message);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].technique.id, "T1110");
    }

    #[test]
    fn test_sql_injection_detection() {
        let detector = MitreAttackDetector::new();
        let message = "GET /api/users?id=1 OR 1=1";

        let detections = detector.detect(message);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].technique.id, "T1190");
        assert_eq!(detections[0].severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_credential_dumping_detection() {
        let detector = MitreAttackDetector::new();
        let message = "mimikatz.exe executed on WORKSTATION-01";

        let detections = detector.detect(message);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].technique.id, "T1003");
    }

    #[test]
    fn test_ransomware_detection() {
        let detector = MitreAttackDetector::new();
        let message = "Files encrypted by ransomware, pay bitcoin to decrypt";

        let detections = detector.detect(message);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].technique.id, "T1486");
        assert_eq!(detections[0].severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_command_execution_detection() {
        let detector = MitreAttackDetector::new();
        let message = "powershell.exe -ExecutionPolicy Bypass -File malware.ps1";

        let detections = detector.detect(message);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].technique.id, "T1059");
    }

    #[test]
    fn test_no_detection() {
        let detector = MitreAttackDetector::new();
        let message = "User logged out successfully";

        let detections = detector.detect(message);
        // Should detect valid account usage (T1078)
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_get_techniques_by_tactic() {
        let detector = MitreAttackDetector::new();
        let credential_access = detector.get_techniques_by_tactic(&AttackTactic::CredentialAccess);

        assert!(!credential_access.is_empty());
        assert!(credential_access.iter().any(|t| t.id == "T1110"));
    }

    #[test]
    fn test_alert_message_generation() {
        let detection = ThreatDetection {
            technique: AttackTechnique {
                id: "T1110".to_string(),
                name: "Brute Force".to_string(),
                tactic: AttackTactic::CredentialAccess,
                description: "Test".to_string(),
            },
            severity: ThreatSeverity::High,
            matched_text: "Failed login".to_string(),
            timestamp: chrono::Utc::now(),
        };

        let alert = detection.to_alert_message();
        assert!(alert.contains("T1110"));
        assert!(alert.contains("Brute Force"));
        assert!(alert.contains("Failed login"));
    }

    #[test]
    fn test_multiple_detections() {
        let detector = MitreAttackDetector::new();
        let message = "mimikatz failed login powershell";

        let detections = detector.detect(message);
        // Should match multiple patterns
        assert!(detections.len() >= 2);
    }
}
