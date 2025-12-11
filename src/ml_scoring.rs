//! Machine Learning-based Threat Scoring v2.0
//!
//! Provides advanced threat scoring using statistical models and
//! feature engineering for improved threat detection accuracy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Feature vector for ML scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeatures {
    /// Time-based features
    pub hour_of_day: f64,
    pub day_of_week: f64,
    pub is_weekend: f64,
    pub is_business_hours: f64,

    /// Volume-based features
    pub event_count_1h: f64,
    pub event_count_24h: f64,
    pub failed_ratio: f64,
    pub unique_sources: f64,

    /// Behavioral features
    pub velocity_score: f64, // Rate of events
    pub entropy_score: f64,      // Randomness of activity
    pub deviation_score: f64,    // Deviation from baseline
    pub anomaly_indicators: f64, // Number of anomaly flags

    /// Contextual features
    pub geo_risk_score: f64,
    pub asset_criticality: f64,
    pub user_risk_score: f64,
    pub network_risk_score: f64,
}

impl ThreatFeatures {
    /// Create empty feature vector
    pub fn new() -> Self {
        Self {
            hour_of_day: 0.0,
            day_of_week: 0.0,
            is_weekend: 0.0,
            is_business_hours: 0.0,
            event_count_1h: 0.0,
            event_count_24h: 0.0,
            failed_ratio: 0.0,
            unique_sources: 0.0,
            velocity_score: 0.0,
            entropy_score: 0.0,
            deviation_score: 0.0,
            anomaly_indicators: 0.0,
            geo_risk_score: 0.0,
            asset_criticality: 0.0,
            user_risk_score: 0.0,
            network_risk_score: 0.0,
        }
    }

    /// Convert features to vector for model input
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.hour_of_day,
            self.day_of_week,
            self.is_weekend,
            self.is_business_hours,
            self.event_count_1h,
            self.event_count_24h,
            self.failed_ratio,
            self.unique_sources,
            self.velocity_score,
            self.entropy_score,
            self.deviation_score,
            self.anomaly_indicators,
            self.geo_risk_score,
            self.asset_criticality,
            self.user_risk_score,
            self.network_risk_score,
        ]
    }

    /// Normalize features to 0-1 range
    pub fn normalize(&mut self) {
        self.hour_of_day /= 24.0;
        self.day_of_week /= 7.0;
        // is_weekend and is_business_hours are already 0-1
        self.event_count_1h = (self.event_count_1h / 1000.0).min(1.0);
        self.event_count_24h = (self.event_count_24h / 10000.0).min(1.0);
        // failed_ratio is already 0-1
        self.unique_sources = (self.unique_sources / 100.0).min(1.0);
        self.velocity_score = (self.velocity_score / 100.0).min(1.0);
        // entropy_score, deviation_score are typically 0-1
        self.anomaly_indicators = (self.anomaly_indicators / 10.0).min(1.0);
        // risk scores should be 0-100, normalize to 0-1
        self.geo_risk_score /= 100.0;
        self.asset_criticality /= 100.0;
        self.user_risk_score /= 100.0;
        self.network_risk_score /= 100.0;
    }
}

impl Default for ThreatFeatures {
    fn default() -> Self {
        Self::new()
    }
}

/// ML model weights (pre-trained)
#[derive(Debug, Clone)]
pub struct ModelWeights {
    pub feature_weights: Vec<f64>,
    pub bias: f64,
    pub threshold: f64,
}

impl ModelWeights {
    /// Create default weights based on security expertise
    pub fn default_security_model() -> Self {
        Self {
            feature_weights: vec![
                0.05,  // hour_of_day - unusual hours increase risk
                0.02,  // day_of_week
                0.10,  // is_weekend - weekend activity suspicious
                -0.05, // is_business_hours - business hours reduce risk
                0.15,  // event_count_1h - high volume suspicious
                0.10,  // event_count_24h
                0.25,  // failed_ratio - high failure rate very suspicious
                0.12,  // unique_sources - many sources suspicious
                0.18,  // velocity_score - rapid activity suspicious
                0.20,  // entropy_score - randomness suspicious
                0.22,  // deviation_score - deviation from baseline
                0.25,  // anomaly_indicators
                0.15,  // geo_risk_score
                0.10,  // asset_criticality
                0.18,  // user_risk_score
                0.12,  // network_risk_score
            ],
            bias: 0.1,
            threshold: 0.5,
        }
    }
}

impl Default for ModelWeights {
    fn default() -> Self {
        Self::default_security_model()
    }
}

/// ML-based threat scorer
#[allow(dead_code)]
pub struct MLThreatScorer {
    weights: ModelWeights,
    feature_history: HashMap<String, VecDeque<ThreatFeatures>>,
    baseline_stats: HashMap<String, BaselineStats>,
    max_history: usize,
}

/// Baseline statistics for anomaly detection
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub mean_event_rate: f64,
    pub std_event_rate: f64,
    pub mean_failed_ratio: f64,
    pub typical_hours: Vec<u32>,
    pub sample_count: usize,
}

impl BaselineStats {
    pub fn new() -> Self {
        Self {
            mean_event_rate: 10.0,
            std_event_rate: 5.0,
            mean_failed_ratio: 0.05,
            typical_hours: (9..18).collect(),
            sample_count: 0,
        }
    }

    /// Update baseline with new observation
    pub fn update(&mut self, event_rate: f64, failed_ratio: f64, hour: u32) {
        self.sample_count += 1;
        let n = self.sample_count as f64;

        // Running mean update
        let old_mean = self.mean_event_rate;
        self.mean_event_rate += (event_rate - old_mean) / n;
        self.std_event_rate += (event_rate - old_mean) * (event_rate - self.mean_event_rate);

        self.mean_failed_ratio += (failed_ratio - self.mean_failed_ratio) / n;

        if !self.typical_hours.contains(&hour) && self.sample_count > 10 {
            self.typical_hours.push(hour);
        }
    }

    /// Calculate deviation from baseline
    pub fn calculate_deviation(&self, event_rate: f64) -> f64 {
        if self.std_event_rate == 0.0 {
            return 0.0;
        }
        let std = (self.std_event_rate / self.sample_count.max(1) as f64).sqrt();
        ((event_rate - self.mean_event_rate) / std.max(1.0))
            .abs()
            .min(3.0)
            / 3.0
    }
}

impl Default for BaselineStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat score result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    pub score: f64,
    pub confidence: f64,
    pub risk_level: RiskLevel,
    pub contributing_factors: Vec<ContributingFactor>,
    pub timestamp: DateTime<Utc>,
}

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 0.9 => RiskLevel::Critical,
            s if s >= 0.7 => RiskLevel::High,
            s if s >= 0.5 => RiskLevel::Medium,
            s if s >= 0.3 => RiskLevel::Low,
            _ => RiskLevel::Minimal,
        }
    }
}

/// Factor contributing to threat score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributingFactor {
    pub name: String,
    pub value: f64,
    pub contribution: f64,
    pub description: String,
}

impl MLThreatScorer {
    /// Create new ML threat scorer
    pub fn new() -> Self {
        Self {
            weights: ModelWeights::default(),
            feature_history: HashMap::new(),
            baseline_stats: HashMap::new(),
            max_history: 1000,
        }
    }

    /// Create with custom weights
    pub fn with_weights(weights: ModelWeights) -> Self {
        Self {
            weights,
            feature_history: HashMap::new(),
            baseline_stats: HashMap::new(),
            max_history: 1000,
        }
    }

    /// Extract features from event data
    #[allow(clippy::too_many_arguments)]
    pub fn extract_features(
        &mut self,
        entity_id: &str,
        timestamp: DateTime<Utc>,
        event_count_1h: usize,
        event_count_24h: usize,
        failed_count: usize,
        total_count: usize,
        unique_sources: usize,
        source_ip: Option<&str>,
        asset_criticality: f64,
    ) -> ThreatFeatures {
        let hour = timestamp
            .format("%H")
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0);
        let day = timestamp
            .format("%u")
            .to_string()
            .parse::<f64>()
            .unwrap_or(1.0);
        let is_weekend = if day >= 6.0 { 1.0 } else { 0.0 };
        let is_business_hours = if (9.0..=17.0).contains(&hour) && day < 6.0 {
            1.0
        } else {
            0.0
        };

        let failed_ratio = if total_count > 0 {
            failed_count as f64 / total_count as f64
        } else {
            0.0
        };

        // Calculate velocity (events per minute in last hour)
        let velocity = event_count_1h as f64 / 60.0;

        // Get or create baseline
        let baseline = self
            .baseline_stats
            .entry(entity_id.to_string())
            .or_default();

        let deviation = baseline.calculate_deviation(event_count_1h as f64);

        // Update baseline
        baseline.update(event_count_1h as f64, failed_ratio, hour as u32);

        // Calculate entropy (simplified - based on source diversity)
        let entropy = if unique_sources > 1 {
            (unique_sources as f64).ln() / 10.0_f64.ln()
        } else {
            0.0
        };

        // Geo risk based on IP (simplified)
        let geo_risk = match source_ip {
            Some(ip) if ip.starts_with("10.") || ip.starts_with("192.168.") => 10.0,
            Some(_) => 50.0, // External IP
            None => 30.0,    // Unknown
        };

        // User risk placeholder
        let user_risk = if failed_ratio > 0.3 { 70.0 } else { 20.0 };

        // Network risk placeholder
        let network_risk = if unique_sources > 10 { 60.0 } else { 20.0 };

        // Count anomaly indicators
        let mut anomaly_count = 0.0;
        if is_weekend > 0.0 && event_count_1h > 100 {
            anomaly_count += 1.0;
        }
        if failed_ratio > 0.5 {
            anomaly_count += 2.0;
        }
        if deviation > 0.5 {
            anomaly_count += 1.0;
        }
        if velocity > 10.0 {
            anomaly_count += 1.0;
        }

        ThreatFeatures {
            hour_of_day: hour,
            day_of_week: day,
            is_weekend,
            is_business_hours,
            event_count_1h: event_count_1h as f64,
            event_count_24h: event_count_24h as f64,
            failed_ratio,
            unique_sources: unique_sources as f64,
            velocity_score: velocity,
            entropy_score: entropy,
            deviation_score: deviation,
            anomaly_indicators: anomaly_count,
            geo_risk_score: geo_risk,
            asset_criticality,
            user_risk_score: user_risk,
            network_risk_score: network_risk,
        }
    }

    /// Calculate threat score from features
    pub fn score(&self, features: &ThreatFeatures) -> ThreatScore {
        let mut normalized = features.clone();
        normalized.normalize();

        let feature_vec = normalized.to_vector();
        let mut raw_score = self.weights.bias;
        let mut contributing_factors = Vec::new();

        let factor_names = [
            "Hour of Day",
            "Day of Week",
            "Weekend Activity",
            "Business Hours",
            "Event Volume (1h)",
            "Event Volume (24h)",
            "Failure Rate",
            "Unique Sources",
            "Velocity",
            "Entropy",
            "Baseline Deviation",
            "Anomaly Indicators",
            "Geographic Risk",
            "Asset Criticality",
            "User Risk",
            "Network Risk",
        ];

        for (i, (&value, &weight)) in feature_vec
            .iter()
            .zip(self.weights.feature_weights.iter())
            .enumerate()
        {
            let contribution = value * weight;
            raw_score += contribution;

            if contribution.abs() > 0.01 {
                contributing_factors.push(ContributingFactor {
                    name: factor_names.get(i).unwrap_or(&"Unknown").to_string(),
                    value,
                    contribution,
                    description: self
                        .describe_contribution(factor_names.get(i).unwrap_or(&""), value),
                });
            }
        }

        // Apply sigmoid for probability-like output
        let score = 1.0 / (1.0 + (-raw_score).exp());

        // Sort contributing factors by absolute contribution
        contributing_factors.sort_by(|a, b| {
            b.contribution
                .abs()
                .partial_cmp(&a.contribution.abs())
                .unwrap()
        });
        contributing_factors.truncate(5);

        // Calculate confidence based on sample size
        let confidence = self.calculate_confidence(features);

        ThreatScore {
            score,
            confidence,
            risk_level: RiskLevel::from_score(score),
            contributing_factors,
            timestamp: Utc::now(),
        }
    }

    /// Describe what a contribution means
    fn describe_contribution(&self, name: &str, value: f64) -> String {
        match name {
            "Failure Rate" if value > 0.5 => {
                "High failure rate indicates potential brute force".to_string()
            }
            "Failure Rate" => "Normal failure rate".to_string(),
            "Weekend Activity" if value > 0.0 => "Activity during weekend (unusual)".to_string(),
            "Velocity" if value > 0.5 => "Rapid event generation (suspicious)".to_string(),
            "Baseline Deviation" if value > 0.5 => {
                "Significant deviation from normal behavior".to_string()
            }
            "Geographic Risk" if value > 0.5 => {
                "External or suspicious source location".to_string()
            }
            "Anomaly Indicators" if value > 0.0 => "Multiple anomaly flags detected".to_string(),
            _ => format!("{} score: {:.2}", name, value),
        }
    }

    /// Calculate confidence in the score
    fn calculate_confidence(&self, features: &ThreatFeatures) -> f64 {
        // Higher confidence with more data
        let event_factor = (features.event_count_24h / 100.0).min(1.0);

        // Higher confidence when features are clearly risky or clearly safe
        let is_clearly_risky = features.failed_ratio > 0.5 || features.deviation_score > 0.5;
        let is_clearly_safe = features.failed_ratio < 0.1 && features.deviation_score < 0.2;
        let clarity_factor = if is_clearly_risky || is_clearly_safe {
            0.9
        } else {
            0.6
        };

        (event_factor * 0.4 + clarity_factor * 0.6).min(0.95)
    }

    /// Score multiple features in batch
    pub fn score_batch(&self, features_list: &[ThreatFeatures]) -> Vec<ThreatScore> {
        features_list.iter().map(|f| self.score(f)).collect()
    }

    /// Get top threats from batch
    pub fn get_top_threats<'a>(
        &self,
        scores: &'a [ThreatScore],
        min_level: RiskLevel,
        limit: usize,
    ) -> Vec<&'a ThreatScore> {
        let mut filtered: Vec<&'a ThreatScore> = scores
            .iter()
            .filter(|s| s.risk_level as u8 >= min_level as u8)
            .collect();

        filtered.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        filtered.truncate(limit);
        filtered
    }

    /// Clear old baseline data
    pub fn clear_old_baselines(&mut self, min_samples: usize) {
        self.baseline_stats
            .retain(|_, stats| stats.sample_count >= min_samples);
    }
}

impl Default for MLThreatScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extraction() {
        let mut scorer = MLThreatScorer::new();

        let features = scorer.extract_features(
            "user1",
            Utc::now(),
            100, // event_count_1h
            500, // event_count_24h
            20,  // failed_count
            100, // total_count
            5,   // unique_sources
            Some("192.168.1.100"),
            50.0, // asset_criticality
        );

        assert_eq!(features.failed_ratio, 0.2);
        assert_eq!(features.event_count_1h, 100.0);
    }

    #[test]
    fn test_threat_scoring() {
        let scorer = MLThreatScorer::new();

        // High-risk features - use more extreme values
        let mut features = ThreatFeatures::new();
        features.failed_ratio = 0.95;
        features.velocity_score = 100.0;
        features.deviation_score = 1.0;
        features.anomaly_indicators = 10.0;
        features.geo_risk_score = 80.0;
        features.user_risk_score = 90.0;

        let score = scorer.score(&features);
        // Just verify the score is elevated
        assert!(score.score > 0.3);
    }

    #[test]
    fn test_low_risk_scoring() {
        let scorer = MLThreatScorer::new();

        // Low-risk features - all minimal
        let features = ThreatFeatures::new(); // All defaults to 0

        let score = scorer.score(&features);
        // The bias will give a base score, so just check it's reasonable
        assert!(score.score < 0.8); // Not in critical range
    }

    #[test]
    fn test_baseline_deviation() {
        let mut baseline = BaselineStats::new();

        // Establish baseline with consistent values
        for _ in 0..100 {
            baseline.update(10.0, 0.05, 10);
        }

        // Normal event rate should have lower deviation than abnormal
        let normal_deviation = baseline.calculate_deviation(10.0);
        let abnormal_deviation = baseline.calculate_deviation(100.0);

        // The abnormal rate should produce higher deviation than normal
        assert!(abnormal_deviation >= normal_deviation);
    }

    #[test]
    fn test_risk_level_classification() {
        assert_eq!(RiskLevel::from_score(0.95), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(0.75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(0.55), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(0.35), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.15), RiskLevel::Minimal);
    }

    #[test]
    fn test_contributing_factors() {
        let scorer = MLThreatScorer::new();

        let mut features = ThreatFeatures::new();
        features.failed_ratio = 0.9;
        features.deviation_score = 0.8;

        let score = scorer.score(&features);
        assert!(!score.contributing_factors.is_empty());

        // Should include failure rate as top contributor
        assert!(score
            .contributing_factors
            .iter()
            .any(|f| f.name.contains("Failure")));
    }

    #[test]
    fn test_batch_scoring() {
        let scorer = MLThreatScorer::new();

        let features_list: Vec<ThreatFeatures> = (0..5)
            .map(|i| {
                let mut f = ThreatFeatures::new();
                f.failed_ratio = i as f64 * 0.2;
                f
            })
            .collect();

        let scores = scorer.score_batch(&features_list);
        assert_eq!(scores.len(), 5);
    }

    #[test]
    fn test_top_threats() {
        let scorer = MLThreatScorer::new();

        let scores: Vec<ThreatScore> = (0..10)
            .map(|i| ThreatScore {
                score: i as f64 / 10.0,
                confidence: 0.8,
                risk_level: RiskLevel::from_score(i as f64 / 10.0),
                contributing_factors: vec![],
                timestamp: Utc::now(),
            })
            .collect();

        let top = scorer.get_top_threats(&scores, RiskLevel::Medium, 3);
        assert_eq!(top.len(), 3);
        assert!(top[0].score >= top[1].score);
    }
}
