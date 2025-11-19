//! # SIEM Export Formats
//!
//! Provides multiple export formats for integration with various SIEM platforms.
//! Supports CEF, LEEF, JSON, Syslog, and CSV formats.

use crate::{ThreatAlert, ThreatSeverity};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// SIEM export format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SIEMFormat {
    /// Common Event Format (ArcSight)
    CEF,
    /// Log Event Extended Format (QRadar)
    LEEF,
    /// JSON format (Splunk, Elasticsearch)
    JSON,
    /// Syslog RFC 5424
    Syslog,
    /// CSV for reporting
    CSV,
}

/// SIEM export configuration
#[derive(Debug, Clone)]
pub struct SIEMExporter {
    vendor: String,
    product: String,
    version: String,
    device_hostname: String,
}

impl SIEMExporter {
    /// Create new SIEM exporter with configuration
    pub fn new(vendor: String, product: String, version: String, device_hostname: String) -> Self {
        Self {
            vendor,
            product,
            version,
            device_hostname,
        }
    }

    /// Create default exporter
    pub fn new_default() -> Self {
        Self {
            vendor: "GuardsArm".to_string(),
            product: "RustThreatDetector".to_string(),
            version: "1.0".to_string(),
            device_hostname: hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        }
    }

    /// Export alert to specified format
    pub fn export(&self, alert: &ThreatAlert, format: SIEMFormat) -> String {
        match format {
            SIEMFormat::CEF => self.to_cef(alert),
            SIEMFormat::LEEF => self.to_leef(alert),
            SIEMFormat::JSON => self.to_json(alert),
            SIEMFormat::Syslog => self.to_syslog(alert),
            SIEMFormat::CSV => self.to_csv(alert),
        }
    }

    /// Export multiple alerts to specified format
    pub fn export_batch(&self, alerts: &[ThreatAlert], format: SIEMFormat) -> Vec<String> {
        alerts.iter().map(|alert| self.export(alert, format)).collect()
    }

    /// Convert alert to CEF (Common Event Format)
    /// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    fn to_cef(&self, alert: &ThreatAlert) -> String {
        let severity = self.severity_to_cef_level(alert.severity);
        let name = self.escape_cef(&alert.description);
        let signature_id = format!("{:?}", alert.category);

        let mut extensions = Vec::new();
        extensions.push(format!("act={}", self.escape_cef(&alert.recommended_action)));
        extensions.push("cs1Label=ThreatScore".to_string());
        extensions.push(format!("cs1={}", alert.threat_score));
        extensions.push("cs2Label=AlertID".to_string());
        extensions.push(format!("cs2={}", alert.alert_id));
        extensions.push("cs3Label=SourceLog".to_string());
        extensions.push(format!("cs3={}", self.escape_cef(&alert.source_log)));

        if !alert.indicators.is_empty() {
            extensions.push("cs4Label=Indicators".to_string());
            extensions.push(format!("cs4={}", self.escape_cef(&alert.indicators.join(", "))));
        }

        if !alert.correlated_alerts.is_empty() {
            extensions.push("cs5Label=CorrelatedAlerts".to_string());
            extensions.push(format!("cs5={}", alert.correlated_alerts.len()));
        }

        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            self.vendor,
            self.product,
            self.version,
            signature_id,
            name,
            severity,
            extensions.join(" ")
        )
    }

    /// Convert alert to LEEF (Log Event Extended Format)
    /// Format: LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Key-Value Pairs
    fn to_leef(&self, alert: &ThreatAlert) -> String {
        let event_id = format!("{:?}", alert.category);
        let delimiter = "\t";

        let mut fields = Vec::new();
        fields.push(format!("devTime={}", alert.timestamp.timestamp()));
        fields.push("devTimeFormat=epoch".to_string());
        fields.push(format!("sev={}", self.severity_to_leef_level(alert.severity)));
        fields.push(format!("cat={:?}", alert.category));
        fields.push(format!("desc={}", self.escape_leef(&alert.description)));
        fields.push(format!("threatScore={}", alert.threat_score));
        fields.push(format!("alertId={}", alert.alert_id));
        fields.push(format!("recommendedAction={}", self.escape_leef(&alert.recommended_action)));
        fields.push(format!("sourceLog={}", self.escape_leef(&alert.source_log)));

        if !alert.indicators.is_empty() {
            fields.push(format!("indicators={}", self.escape_leef(&alert.indicators.join(", "))));
        }

        format!(
            "LEEF:2.0|{}|{}|{}|{}|{}{}",
            self.vendor,
            self.product,
            self.version,
            event_id,
            delimiter,
            fields.join(delimiter)
        )
    }

    /// Convert alert to JSON (for Splunk, Elasticsearch)
    fn to_json(&self, alert: &ThreatAlert) -> String {
        #[derive(Serialize)]
        struct JSONAlert<'a> {
            timestamp: DateTime<Utc>,
            alert_id: &'a str,
            severity: &'a str,
            severity_level: u8,
            category: String,
            description: &'a str,
            threat_score: u32,
            risk_assessment: &'a str,
            source_log: &'a str,
            indicators: &'a [String],
            recommended_action: &'a str,
            correlated_alerts: &'a [String],
            correlated_count: usize,
            vendor: &'a str,
            product: &'a str,
            version: &'a str,
            device_hostname: &'a str,
        }

        let json_alert = JSONAlert {
            timestamp: alert.timestamp,
            alert_id: &alert.alert_id,
            severity: &format!("{:?}", alert.severity),
            severity_level: self.severity_to_numeric(alert.severity),
            category: format!("{:?}", alert.category),
            description: &alert.description,
            threat_score: alert.threat_score,
            risk_assessment: alert.risk_assessment(),
            source_log: &alert.source_log,
            indicators: &alert.indicators,
            recommended_action: &alert.recommended_action,
            correlated_alerts: &alert.correlated_alerts,
            correlated_count: alert.correlated_alerts.len(),
            vendor: &self.vendor,
            product: &self.product,
            version: &self.version,
            device_hostname: &self.device_hostname,
        };

        serde_json::to_string(&json_alert).unwrap_or_default()
    }

    /// Convert alert to Syslog (RFC 5424)
    /// Format: <Priority>Version Timestamp Hostname App-Name ProcID MsgID SD Message
    fn to_syslog(&self, alert: &ThreatAlert) -> String {
        let priority = self.severity_to_syslog_priority(alert.severity);
        let timestamp = alert.timestamp.to_rfc3339();
        let app_name = &self.product;
        let proc_id = std::process::id();
        let msg_id = &alert.alert_id;

        // Structured data
        let sd = format!(
            "[threat@32473 category=\"{:?}\" severity=\"{:?}\" score=\"{}\" indicators=\"{}\"]",
            alert.category,
            alert.severity,
            alert.threat_score,
            alert.indicators.len()
        );

        let message = format!(
            "{} | {} | Action: {}",
            alert.description, alert.source_log, alert.recommended_action
        );

        format!(
            "<{}>1 {} {} {} {} {} {} {}",
            priority, timestamp, self.device_hostname, app_name, proc_id, msg_id, sd, message
        )
    }

    /// Convert alert to CSV format
    fn to_csv(&self, alert: &ThreatAlert) -> String {
        format!(
            "\"{}\",\"{}\",\"{:?}\",\"{:?}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\"",
            alert.timestamp.to_rfc3339(),
            alert.alert_id,
            alert.severity,
            alert.category,
            self.escape_csv(&alert.description),
            alert.threat_score,
            alert.risk_assessment(),
            self.escape_csv(&alert.indicators.join("; ")),
            self.escape_csv(&alert.recommended_action),
            alert.correlated_alerts.len()
        )
    }

    /// Get CSV header
    pub fn csv_header() -> String {
        "Timestamp,Alert ID,Severity,Category,Description,Threat Score,Risk Assessment,Indicators,Recommended Action,Correlated Count".to_string()
    }

    // Helper methods for severity conversion

    fn severity_to_cef_level(&self, severity: ThreatSeverity) -> u8 {
        match severity {
            ThreatSeverity::Info => 0,
            ThreatSeverity::Low => 3,
            ThreatSeverity::Medium => 5,
            ThreatSeverity::High => 8,
            ThreatSeverity::Critical => 10,
        }
    }

    fn severity_to_leef_level(&self, severity: ThreatSeverity) -> u8 {
        match severity {
            ThreatSeverity::Info => 1,
            ThreatSeverity::Low => 2,
            ThreatSeverity::Medium => 5,
            ThreatSeverity::High => 7,
            ThreatSeverity::Critical => 10,
        }
    }

    fn severity_to_numeric(&self, severity: ThreatSeverity) -> u8 {
        match severity {
            ThreatSeverity::Info => 1,
            ThreatSeverity::Low => 2,
            ThreatSeverity::Medium => 3,
            ThreatSeverity::High => 4,
            ThreatSeverity::Critical => 5,
        }
    }

    fn severity_to_syslog_priority(&self, severity: ThreatSeverity) -> u8 {
        // Facility: Security (13), Severity levels: 0-7
        let facility = 13 << 3;
        let level = match severity {
            ThreatSeverity::Info => 6,      // Informational
            ThreatSeverity::Low => 5,       // Notice
            ThreatSeverity::Medium => 4,    // Warning
            ThreatSeverity::High => 3,      // Error
            ThreatSeverity::Critical => 2,  // Critical
        };
        facility | level
    }

    // Escaping methods for different formats

    fn escape_cef(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace('=', "\\=")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    fn escape_leef(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    fn escape_csv(&self, s: &str) -> String {
        s.replace('"', "\"\"")
    }
}

/// Batch export utility
pub struct BatchExporter {
    exporter: SIEMExporter,
    format: SIEMFormat,
}

impl BatchExporter {
    /// Create new batch exporter
    pub fn new(format: SIEMFormat) -> Self {
        Self {
            exporter: SIEMExporter::new_default(),
            format,
        }
    }

    /// Export alerts and return as concatenated string
    pub fn export(&self, alerts: &[ThreatAlert]) -> String {
        let lines = self.exporter.export_batch(alerts, self.format);

        if self.format == SIEMFormat::CSV {
            let mut result = SIEMExporter::csv_header();
            result.push('\n');
            result.push_str(&lines.join("\n"));
            result
        } else {
            lines.join("\n")
        }
    }

    /// Export to file
    pub fn export_to_file(&self, alerts: &[ThreatAlert], path: &str) -> std::io::Result<()> {
        use std::fs::File;
        use std::io::Write;

        let content = self.export(alerts);
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ThreatCategory, ThreatSeverity};

    fn create_test_alert() -> ThreatAlert {
        ThreatAlert {
            alert_id: "ALERT-00001".to_string(),
            timestamp: Utc::now(),
            severity: ThreatSeverity::High,
            category: ThreatCategory::BruteForce,
            description: "Multiple failed login attempts detected".to_string(),
            source_log: "2025-01-15 10:30:45 - Failed login from 192.168.1.100".to_string(),
            indicators: vec!["192.168.1.100".to_string(), "user: admin".to_string()],
            recommended_action: "Block source IP, enable MFA".to_string(),
            threat_score: 75,
            correlated_alerts: vec!["ALERT-00000".to_string()],
        }
    }

    #[test]
    fn test_cef_export() {
        let exporter = SIEMExporter::new_default();
        let alert = create_test_alert();
        let cef = exporter.to_cef(&alert);

        assert!(cef.starts_with("CEF:0|"));
        assert!(cef.contains("GuardsArm"));
        assert!(cef.contains("RustThreatDetector"));
        assert!(cef.contains("BruteForce"));
        assert!(cef.contains("cs1=75")); // Threat score
    }

    #[test]
    fn test_leef_export() {
        let exporter = SIEMExporter::new_default();
        let alert = create_test_alert();
        let leef = exporter.to_leef(&alert);

        assert!(leef.starts_with("LEEF:2.0|"));
        assert!(leef.contains("GuardsArm"));
        assert!(leef.contains("threatScore=75"));
        assert!(leef.contains("alertId=ALERT-00001"));
    }

    #[test]
    fn test_json_export() {
        let exporter = SIEMExporter::new_default();
        let alert = create_test_alert();
        let json = exporter.to_json(&alert);

        assert!(json.contains("\"alert_id\":\"ALERT-00001\""));
        assert!(json.contains("\"threat_score\":75"));
        assert!(json.contains("\"severity\":\"High\""));
        assert!(json.contains("\"category\":\"BruteForce\""));
    }

    #[test]
    fn test_syslog_export() {
        let exporter = SIEMExporter::new_default();
        let alert = create_test_alert();
        let syslog = exporter.to_syslog(&alert);

        assert!(syslog.starts_with("<")); // Priority
        assert!(syslog.contains("ALERT-00001"));
        assert!(syslog.contains("[threat@32473"));
        assert!(syslog.contains("category=\"BruteForce\""));
    }

    #[test]
    fn test_csv_export() {
        let exporter = SIEMExporter::new_default();
        let alert = create_test_alert();
        let csv = exporter.to_csv(&alert);

        assert!(csv.contains("ALERT-00001"));
        assert!(csv.contains("High"));
        assert!(csv.contains("BruteForce"));
        assert!(csv.contains("75"));
    }

    #[test]
    fn test_csv_header() {
        let header = SIEMExporter::csv_header();
        assert!(header.contains("Timestamp"));
        assert!(header.contains("Alert ID"));
        assert!(header.contains("Severity"));
        assert!(header.contains("Threat Score"));
    }

    #[test]
    fn test_severity_conversions() {
        let exporter = SIEMExporter::new_default();

        assert_eq!(exporter.severity_to_cef_level(ThreatSeverity::Critical), 10);
        assert_eq!(exporter.severity_to_cef_level(ThreatSeverity::Low), 3);

        assert_eq!(exporter.severity_to_leef_level(ThreatSeverity::Critical), 10);
        assert_eq!(exporter.severity_to_leef_level(ThreatSeverity::Medium), 5);

        assert_eq!(exporter.severity_to_numeric(ThreatSeverity::Critical), 5);
        assert_eq!(exporter.severity_to_numeric(ThreatSeverity::Info), 1);
    }

    #[test]
    fn test_cef_escaping() {
        let exporter = SIEMExporter::new_default();
        let input = "test|value=with\\special\nchars";
        let escaped = exporter.escape_cef(input);

        assert!(escaped.contains("\\|"));
        assert!(escaped.contains("\\="));
        assert!(escaped.contains("\\\\"));
        assert!(escaped.contains("\\n"));
    }

    #[test]
    fn test_csv_escaping() {
        let exporter = SIEMExporter::new_default();
        let input = "test \"quoted\" value";
        let escaped = exporter.escape_csv(input);

        assert!(escaped.contains("\"\""));
    }

    #[test]
    fn test_batch_export() {
        let exporter = SIEMExporter::new_default();
        let alerts = vec![create_test_alert(), create_test_alert()];
        let batch = exporter.export_batch(&alerts, SIEMFormat::JSON);

        assert_eq!(batch.len(), 2);
        assert!(batch[0].contains("ALERT-00001"));
        assert!(batch[1].contains("ALERT-00001"));
    }

    #[test]
    fn test_batch_exporter() {
        let batch_exporter = BatchExporter::new(SIEMFormat::CSV);
        let alerts = vec![create_test_alert()];
        let output = batch_exporter.export(&alerts);

        assert!(output.contains("Timestamp,Alert ID")); // Header
        assert!(output.contains("ALERT-00001")); // Data
    }

    #[test]
    fn test_all_formats() {
        let exporter = SIEMExporter::new_default();
        let alert = create_test_alert();

        // Test that all formats produce non-empty output
        let formats = vec![
            SIEMFormat::CEF,
            SIEMFormat::LEEF,
            SIEMFormat::JSON,
            SIEMFormat::Syslog,
            SIEMFormat::CSV,
        ];

        for format in formats {
            let output = exporter.export(&alert, format);
            assert!(!output.is_empty());
        }
    }
}
