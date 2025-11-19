//! # Anomaly Detection Engine
//!
//! Statistical and time-series based anomaly detection for identifying
//! unusual patterns in security logs and metrics.

use crate::{LogEntry, ThreatAlert, ThreatCategory, ThreatSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Anomaly detection method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionMethod {
    /// Z-score based detection (standard deviations from mean)
    ZScore,
    /// Moving average with threshold
    MovingAverage,
    /// Exponential smoothing
    ExponentialSmoothing,
    /// Inter-Quartile Range (IQR)
    IQR,
}

/// Time series metric for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeries {
    pub name: String,
    pub values: VecDeque<f64>,
    pub timestamps: VecDeque<DateTime<Utc>>,
    pub max_size: usize,
}

impl TimeSeries {
    /// Create new time series with maximum history
    pub fn new(name: String, max_size: usize) -> Self {
        Self {
            name,
            values: VecDeque::with_capacity(max_size),
            timestamps: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Add value to time series
    pub fn add(&mut self, value: f64, timestamp: DateTime<Utc>) {
        if self.values.len() >= self.max_size {
            self.values.pop_front();
            self.timestamps.pop_front();
        }
        self.values.push_back(value);
        self.timestamps.push_back(timestamp);
    }

    /// Calculate mean
    pub fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.values.iter().sum::<f64>() / self.values.len() as f64
    }

    /// Calculate standard deviation
    pub fn std_dev(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance = self.values.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / (self.values.len() - 1) as f64;
        variance.sqrt()
    }

    /// Calculate moving average over window
    pub fn moving_average(&self, window_size: usize) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        let window = window_size.min(self.values.len());
        let start = self.values.len().saturating_sub(window);
        self.values.iter().skip(start).sum::<f64>() / window as f64
    }

    /// Get percentile value
    pub fn percentile(&self, p: f64) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<f64> = self.values.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let index = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[index]
    }

    /// Calculate IQR (Inter-Quartile Range)
    pub fn iqr(&self) -> (f64, f64, f64) {
        let q1 = self.percentile(25.0);
        let q3 = self.percentile(75.0);
        let iqr = q3 - q1;
        (q1, q3, iqr)
    }
}

/// Anomaly detection engine
pub struct AnomalyDetector {
    metrics: HashMap<String, TimeSeries>,
    z_score_threshold: f64,
    iqr_multiplier: f64,
    moving_avg_window: usize,
    smoothing_alpha: f64,
}

impl AnomalyDetector {
    /// Create new anomaly detector with default parameters
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            z_score_threshold: 3.0, // 3 sigma
            iqr_multiplier: 1.5,    // Standard IQR multiplier
            moving_avg_window: 10,
            smoothing_alpha: 0.3, // Exponential smoothing factor
        }
    }

    /// Create with custom parameters
    pub fn with_params(
        z_score_threshold: f64,
        iqr_multiplier: f64,
        moving_avg_window: usize,
        smoothing_alpha: f64,
    ) -> Self {
        Self {
            metrics: HashMap::new(),
            z_score_threshold,
            iqr_multiplier,
            moving_avg_window,
            smoothing_alpha,
        }
    }

    /// Track metric value
    pub fn track_metric(&mut self, name: &str, value: f64, timestamp: DateTime<Utc>) {
        let metric = self
            .metrics
            .entry(name.to_string())
            .or_insert_with(|| TimeSeries::new(name.to_string(), 1000));
        metric.add(value, timestamp);
    }

    /// Detect anomaly using specified method
    pub fn detect(
        &self,
        metric_name: &str,
        current_value: f64,
        method: DetectionMethod,
    ) -> Option<AnomalyResult> {
        let metric = self.metrics.get(metric_name)?;

        if metric.values.is_empty() {
            return None;
        }

        match method {
            DetectionMethod::ZScore => self.detect_zscore(metric, current_value),
            DetectionMethod::MovingAverage => self.detect_moving_avg(metric, current_value),
            DetectionMethod::ExponentialSmoothing => self.detect_exponential(metric, current_value),
            DetectionMethod::IQR => self.detect_iqr(metric, current_value),
        }
    }

    /// Detect using Z-score (standard deviations from mean)
    fn detect_zscore(&self, metric: &TimeSeries, value: f64) -> Option<AnomalyResult> {
        if metric.values.len() < 10 {
            return None; // Need sufficient history
        }

        let mean = metric.mean();
        let std_dev = metric.std_dev();

        if std_dev == 0.0 {
            return None; // No variation
        }

        let z_score = (value - mean).abs() / std_dev;

        if z_score > self.z_score_threshold {
            Some(AnomalyResult {
                metric_name: metric.name.clone(),
                current_value: value,
                expected_value: mean,
                deviation: z_score,
                method: DetectionMethod::ZScore,
                severity: self.calculate_severity(z_score, self.z_score_threshold),
                description: format!(
                    "Value {:.2} deviates {:.2} standard deviations from mean {:.2}",
                    value, z_score, mean
                ),
            })
        } else {
            None
        }
    }

    /// Detect using moving average
    fn detect_moving_avg(&self, metric: &TimeSeries, value: f64) -> Option<AnomalyResult> {
        if metric.values.len() < self.moving_avg_window {
            return None;
        }

        let moving_avg = metric.moving_average(self.moving_avg_window);
        let std_dev = metric.std_dev();

        if std_dev == 0.0 {
            return None;
        }

        let deviation = (value - moving_avg).abs() / std_dev;

        if deviation > self.z_score_threshold {
            Some(AnomalyResult {
                metric_name: metric.name.clone(),
                current_value: value,
                expected_value: moving_avg,
                deviation,
                method: DetectionMethod::MovingAverage,
                severity: self.calculate_severity(deviation, self.z_score_threshold),
                description: format!(
                    "Value {:.2} deviates from moving average {:.2} by {:.2} std devs",
                    value, moving_avg, deviation
                ),
            })
        } else {
            None
        }
    }

    /// Detect using exponential smoothing
    fn detect_exponential(&self, metric: &TimeSeries, value: f64) -> Option<AnomalyResult> {
        if metric.values.is_empty() {
            return None;
        }

        // Calculate exponentially weighted moving average
        let mut ewma = metric.values[0];
        for &v in metric.values.iter().skip(1) {
            ewma = self.smoothing_alpha * v + (1.0 - self.smoothing_alpha) * ewma;
        }

        let std_dev = metric.std_dev();
        if std_dev == 0.0 {
            return None;
        }

        let deviation = (value - ewma).abs() / std_dev;

        if deviation > self.z_score_threshold {
            Some(AnomalyResult {
                metric_name: metric.name.clone(),
                current_value: value,
                expected_value: ewma,
                deviation,
                method: DetectionMethod::ExponentialSmoothing,
                severity: self.calculate_severity(deviation, self.z_score_threshold),
                description: format!(
                    "Value {:.2} deviates from exponential moving average {:.2}",
                    value, ewma
                ),
            })
        } else {
            None
        }
    }

    /// Detect using IQR (Inter-Quartile Range)
    fn detect_iqr(&self, metric: &TimeSeries, value: f64) -> Option<AnomalyResult> {
        if metric.values.len() < 10 {
            return None;
        }

        let (q1, q3, iqr) = metric.iqr();
        let lower_bound = q1 - self.iqr_multiplier * iqr;
        let upper_bound = q3 + self.iqr_multiplier * iqr;

        if value < lower_bound || value > upper_bound {
            let deviation = if value < lower_bound {
                (lower_bound - value) / iqr
            } else {
                (value - upper_bound) / iqr
            };

            Some(AnomalyResult {
                metric_name: metric.name.clone(),
                current_value: value,
                expected_value: (q1 + q3) / 2.0,
                deviation,
                method: DetectionMethod::IQR,
                severity: self.calculate_severity(deviation, 1.0),
                description: format!(
                    "Value {:.2} outside IQR bounds [{:.2}, {:.2}]",
                    value, lower_bound, upper_bound
                ),
            })
        } else {
            None
        }
    }

    /// Calculate severity based on deviation
    fn calculate_severity(&self, deviation: f64, threshold: f64) -> ThreatSeverity {
        let ratio = deviation / threshold;
        if ratio > 3.0 {
            ThreatSeverity::Critical
        } else if ratio > 2.0 {
            ThreatSeverity::High
        } else if ratio > 1.5 {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        }
    }

    /// Analyze log for metric anomalies
    pub fn analyze_log(&mut self, log: &LogEntry) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        // Extract metrics from log metadata
        for (key, value_str) in &log.metadata {
            if let Ok(value) = value_str.parse::<f64>() {
                let metric_name = format!("log.{}", key);
                self.track_metric(&metric_name, value, log.timestamp);

                // Try all detection methods
                for method in &[
                    DetectionMethod::ZScore,
                    DetectionMethod::MovingAverage,
                    DetectionMethod::IQR,
                ] {
                    if let Some(anomaly) = self.detect(&metric_name, value, *method) {
                        alerts.push(anomaly.to_threat_alert(log));
                        break; // Only generate one alert per metric
                    }
                }
            }
        }

        alerts
    }

    /// Get metric statistics
    pub fn get_metric(&self, name: &str) -> Option<&TimeSeries> {
        self.metrics.get(name)
    }

    /// Get all tracked metrics
    pub fn get_all_metrics(&self) -> Vec<&str> {
        self.metrics.keys().map(|s| s.as_str()).collect()
    }

    /// Clear old data from metrics
    pub fn clear_old_data(&mut self, before: DateTime<Utc>) {
        for metric in self.metrics.values_mut() {
            while let Some(&timestamp) = metric.timestamps.front() {
                if timestamp < before {
                    metric.timestamps.pop_front();
                    metric.values.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of anomaly detection
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub metric_name: String,
    pub current_value: f64,
    pub expected_value: f64,
    pub deviation: f64,
    pub method: DetectionMethod,
    pub severity: ThreatSeverity,
    pub description: String,
}

impl AnomalyResult {
    /// Convert to ThreatAlert
    pub fn to_threat_alert(&self, source_log: &LogEntry) -> ThreatAlert {
        ThreatAlert {
            alert_id: format!("ANOMALY-{}", chrono::Utc::now().timestamp()),
            timestamp: Utc::now(),
            severity: self.severity,
            category: ThreatCategory::AnomalousActivity,
            description: format!(
                "Statistical anomaly in {}: {}",
                self.metric_name, self.description
            ),
            source_log: format!("{} - {}", source_log.timestamp, source_log.message),
            indicators: vec![
                format!("Current: {:.2}", self.current_value),
                format!("Expected: {:.2}", self.expected_value),
                format!("Deviation: {:.2}", self.deviation),
                format!("Method: {:?}", self.method),
            ],
            recommended_action:
                "Investigate metric anomaly, review related logs, check for system issues"
                    .to_string(),
            threat_score: self.calculate_threat_score(),
            correlated_alerts: vec![],
        }
    }

    fn calculate_threat_score(&self) -> u32 {
        let base_score = match self.severity {
            ThreatSeverity::Info => 10,
            ThreatSeverity::Low => 25,
            ThreatSeverity::Medium => 50,
            ThreatSeverity::High => 75,
            ThreatSeverity::Critical => 95,
        };

        // Adjust based on deviation magnitude
        let deviation_bonus = (self.deviation * 2.0).min(20.0) as u32;
        (base_score + deviation_bonus).min(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::HashMap;

    #[test]
    fn test_time_series_mean() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        ts.add(10.0, Utc::now());
        ts.add(20.0, Utc::now());
        ts.add(30.0, Utc::now());

        assert_eq!(ts.mean(), 20.0);
    }

    #[test]
    fn test_time_series_std_dev() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        for i in 1..=10 {
            ts.add(i as f64, Utc::now());
        }

        let std_dev = ts.std_dev();
        assert!(std_dev > 0.0);
        assert!(std_dev < 4.0); // Approximate std dev for 1-10
    }

    #[test]
    fn test_time_series_moving_average() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        ts.add(10.0, Utc::now());
        ts.add(20.0, Utc::now());
        ts.add(30.0, Utc::now());
        ts.add(40.0, Utc::now());

        let ma = ts.moving_average(2);
        assert_eq!(ma, 35.0); // (30 + 40) / 2
    }

    #[test]
    fn test_time_series_percentile() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        for i in 1..=100 {
            ts.add(i as f64, Utc::now());
        }

        assert_eq!(ts.percentile(0.0), 1.0);
        assert_eq!(ts.percentile(100.0), 100.0);
        let median = ts.percentile(50.0);
        assert!((49.0..=52.0).contains(&median));
    }

    #[test]
    fn test_time_series_iqr() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        for i in 1..=100 {
            ts.add(i as f64, Utc::now());
        }

        let (q1, q3, iqr) = ts.iqr();
        assert!((24.0..=27.0).contains(&q1));
        assert!((73.0..=77.0).contains(&q3));
        assert!((48.0..=52.0).contains(&iqr));
    }

    #[test]
    fn test_zscore_detection() {
        let mut detector = AnomalyDetector::new();

        // Build baseline
        for i in 0..20 {
            detector.track_metric("test_metric", 100.0 + (i as f64), Utc::now());
        }

        // Test normal value - should not detect
        let result = detector.detect("test_metric", 110.0, DetectionMethod::ZScore);
        assert!(result.is_none());

        // Test anomalous value - should detect
        let result = detector.detect("test_metric", 500.0, DetectionMethod::ZScore);
        assert!(result.is_some());
        let anomaly = result.unwrap();
        assert_eq!(anomaly.metric_name, "test_metric");
        assert_eq!(anomaly.current_value, 500.0);
    }

    #[test]
    fn test_moving_average_detection() {
        let mut detector = AnomalyDetector::new();

        for i in 0..15 {
            detector.track_metric("test_metric", 50.0 + i as f64, Utc::now());
        }

        let result = detector.detect("test_metric", 200.0, DetectionMethod::MovingAverage);
        assert!(result.is_some());
    }

    #[test]
    fn test_iqr_detection() {
        let mut detector = AnomalyDetector::new();

        // Normal distribution
        for i in 1..=20 {
            detector.track_metric("test_metric", i as f64 * 10.0, Utc::now());
        }

        // Outlier
        let result = detector.detect("test_metric", 1000.0, DetectionMethod::IQR);
        assert!(result.is_some());

        // Normal value
        let result = detector.detect("test_metric", 105.0, DetectionMethod::IQR);
        assert!(result.is_none());
    }

    #[test]
    fn test_exponential_smoothing() {
        let mut detector = AnomalyDetector::with_params(3.0, 1.5, 10, 0.3);

        for i in 0..20 {
            detector.track_metric("test_metric", 100.0 + (i as f64), Utc::now());
        }

        let result = detector.detect("test_metric", 500.0, DetectionMethod::ExponentialSmoothing);
        assert!(result.is_some());
    }

    #[test]
    fn test_severity_calculation() {
        let detector = AnomalyDetector::new();

        assert_eq!(
            detector.calculate_severity(10.0, 3.0),
            ThreatSeverity::Critical
        );
        assert_eq!(detector.calculate_severity(6.5, 3.0), ThreatSeverity::High);
        assert_eq!(
            detector.calculate_severity(4.8, 3.0),
            ThreatSeverity::Medium
        );
        assert_eq!(detector.calculate_severity(3.2, 3.0), ThreatSeverity::Low);
    }

    #[test]
    fn test_analyze_log() {
        let mut detector = AnomalyDetector::new();

        // Build baseline
        for _ in 0..20 {
            let mut metadata = HashMap::new();
            metadata.insert("request_count".to_string(), "100".to_string());
            let log = LogEntry {
                timestamp: Utc::now(),
                source_ip: Some("192.168.1.1".to_string()),
                user: Some("test".to_string()),
                event_type: "metric".to_string(),
                message: "Normal traffic".to_string(),
                metadata,
            };
            detector.analyze_log(&log);
        }

        // Anomalous log
        let mut metadata = HashMap::new();
        metadata.insert("request_count".to_string(), "10000".to_string());
        let log = LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.1".to_string()),
            user: Some("test".to_string()),
            event_type: "metric".to_string(),
            message: "Spike in traffic".to_string(),
            metadata,
        };

        let alerts = detector.analyze_log(&log);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].category, ThreatCategory::AnomalousActivity);
    }

    #[test]
    fn test_clear_old_data() {
        let mut detector = AnomalyDetector::new();

        let old_time = Utc::now() - Duration::hours(2);
        let new_time = Utc::now();

        detector.track_metric("test", 10.0, old_time);
        detector.track_metric("test", 20.0, new_time);

        let metric = detector.get_metric("test").unwrap();
        assert_eq!(metric.values.len(), 2);

        let cutoff = Utc::now() - Duration::hours(1);
        detector.clear_old_data(cutoff);

        let metric = detector.get_metric("test").unwrap();
        assert_eq!(metric.values.len(), 1);
        assert_eq!(metric.values[0], 20.0);
    }

    #[test]
    fn test_get_all_metrics() {
        let mut detector = AnomalyDetector::new();

        detector.track_metric("metric1", 10.0, Utc::now());
        detector.track_metric("metric2", 20.0, Utc::now());
        detector.track_metric("metric3", 30.0, Utc::now());

        let metrics = detector.get_all_metrics();
        assert_eq!(metrics.len(), 3);
        assert!(metrics.contains(&"metric1"));
        assert!(metrics.contains(&"metric2"));
        assert!(metrics.contains(&"metric3"));
    }

    #[test]
    fn test_anomaly_to_threat_alert() {
        let anomaly = AnomalyResult {
            metric_name: "test_metric".to_string(),
            current_value: 500.0,
            expected_value: 100.0,
            deviation: 5.0,
            method: DetectionMethod::ZScore,
            severity: ThreatSeverity::High,
            description: "Test anomaly".to_string(),
        };

        let log = LogEntry {
            timestamp: Utc::now(),
            source_ip: Some("192.168.1.1".to_string()),
            user: Some("test".to_string()),
            event_type: "test".to_string(),
            message: "test message".to_string(),
            metadata: HashMap::new(),
        };

        let alert = anomaly.to_threat_alert(&log);
        assert_eq!(alert.severity, ThreatSeverity::High);
        assert_eq!(alert.category, ThreatCategory::AnomalousActivity);
        assert!(alert.threat_score > 0);
    }
}
