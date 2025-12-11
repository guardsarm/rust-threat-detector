//! ML-Based Threat Scoring Example
//!
//! Demonstrates the machine learning-based threat scoring capabilities
//! of the rust-threat-detector v2.0.

use chrono::Utc;
use rust_threat_detector::{MLThreatScorer, RiskLevel, ThreatFeatures};

fn main() {
    println!("=== ML-Based Threat Scoring Demo v2.0 ===\n");

    let mut scorer = MLThreatScorer::new();

    // Example 1: Low-risk activity
    println!("--- Example 1: Normal Business Activity ---");
    let features = scorer.extract_features(
        "user_alice",
        Utc::now(),
        50,  // event_count_1h
        200, // event_count_24h
        2,   // failed_count
        100, // total_count
        1,   // unique_sources
        Some("192.168.1.100"),
        30.0, // asset_criticality
    );

    let score = scorer.score(&features);
    println!("Risk Level: {:?}", score.risk_level);
    println!("Score: {:.2}", score.score);
    println!("Confidence: {:.2}", score.confidence);
    println!("Top Contributing Factors:");
    for factor in &score.contributing_factors {
        println!(
            "  - {}: {:.3} ({})",
            factor.name, factor.contribution, factor.description
        );
    }

    // Example 2: Suspicious activity
    println!("\n--- Example 2: Suspicious Activity ---");
    let suspicious_features = scorer.extract_features(
        "user_bob",
        Utc::now(),
        500,             // High event count
        2000,            // Very high 24h count
        200,             // Many failures
        500,             // total_count
        15,              // Many unique sources
        Some("1.2.3.4"), // External IP
        80.0,            // High criticality asset
    );

    let suspicious_score = scorer.score(&suspicious_features);
    println!("Risk Level: {:?}", suspicious_score.risk_level);
    println!("Score: {:.2}", suspicious_score.score);
    println!("Confidence: {:.2}", suspicious_score.confidence);
    println!("Top Contributing Factors:");
    for factor in &suspicious_score.contributing_factors {
        println!(
            "  - {}: {:.3} ({})",
            factor.name, factor.contribution, factor.description
        );
    }

    // Example 3: Batch scoring
    println!("\n--- Example 3: Batch Scoring ---");
    let batch_features: Vec<ThreatFeatures> = (0..5)
        .map(|i| {
            let mut f = ThreatFeatures::new();
            f.failed_ratio = i as f64 * 0.2;
            f.velocity_score = i as f64 * 10.0;
            f.deviation_score = i as f64 * 0.15;
            f
        })
        .collect();

    let batch_scores = scorer.score_batch(&batch_features);
    for (i, score) in batch_scores.iter().enumerate() {
        println!(
            "Entity {}: {:?} (score: {:.2})",
            i, score.risk_level, score.score
        );
    }

    // Example 4: Get top threats
    println!("\n--- Example 4: Top Threats ---");
    let top_threats = scorer.get_top_threats(&batch_scores, RiskLevel::Medium, 3);
    println!("Top {} threats at Medium or higher:", top_threats.len());
    for threat in top_threats {
        println!(
            "  - Score: {:.2}, Level: {:?}",
            threat.score, threat.risk_level
        );
    }

    // Example 5: Feature analysis
    println!("\n--- Example 5: Feature Vector Analysis ---");
    let analysis_features = ThreatFeatures {
        hour_of_day: 3.0, // 3 AM
        day_of_week: 7.0, // Sunday
        is_weekend: 1.0,
        is_business_hours: 0.0,
        event_count_1h: 1000.0,
        event_count_24h: 5000.0,
        failed_ratio: 0.8,
        unique_sources: 50.0,
        velocity_score: 80.0,
        entropy_score: 0.9,
        deviation_score: 0.95,
        anomaly_indicators: 5.0,
        geo_risk_score: 70.0,
        asset_criticality: 90.0,
        user_risk_score: 80.0,
        network_risk_score: 60.0,
    };

    let analysis_score = scorer.score(&analysis_features);
    println!("Highly Suspicious Activity Analysis:");
    println!("Risk Level: {:?}", analysis_score.risk_level);
    println!("Score: {:.2}", analysis_score.score);
    println!(
        "Risk Assessment: {}",
        match analysis_score.risk_level {
            RiskLevel::Critical => "CRITICAL - Immediate investigation required",
            RiskLevel::High => "HIGH - Urgent review needed",
            RiskLevel::Medium => "MEDIUM - Schedule investigation",
            RiskLevel::Low => "LOW - Monitor and log",
            RiskLevel::Minimal => "MINIMAL - Normal activity",
        }
    );

    println!("\n=== Demo Complete ===");
}
