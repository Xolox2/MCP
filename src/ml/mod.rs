use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ndarray::{Array1, Array2};

#[derive(Debug, Deserialize)]
pub struct PredictionRequest {
    pub model_type: String, // "text_classification", "sentiment", "regression"
    pub input_data: Value,
    pub parameters: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct PredictionResult {
    pub model_type: String,
    pub prediction: Value,
    pub confidence: Option<f64>,
    pub processing_time_ms: u64,
}

pub async fn predict(Json(payload): Json<PredictionRequest>) -> Result<Json<PredictionResult>, StatusCode> {
    let start_time = std::time::Instant::now();
    
    let result = match payload.model_type.as_str() {
        "sentiment" => analyze_sentiment(&payload.input_data)?,
        "text_classification" => classify_text(&payload.input_data)?,
        "regression" => perform_regression(&payload.input_data)?,
        "feature_extraction" => extract_features(&payload.input_data)?,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    
    let processing_time = start_time.elapsed().as_millis() as u64;
    
    Ok(Json(PredictionResult {
        model_type: payload.model_type,
        prediction: result.0,
        confidence: result.1,
        processing_time_ms: processing_time,
    }))
}

fn analyze_sentiment(input: &Value) -> Result<(Value, Option<f64>), StatusCode> {
    let text = input.as_str().ok_or(StatusCode::BAD_REQUEST)?;
    
    // Análisis de sentimiento básico usando palabras clave
    let positive_words = ["good", "great", "excellent", "amazing", "wonderful", "fantastic"];
    let negative_words = ["bad", "terrible", "awful", "horrible", "disappointing", "poor"];
    
    let text_lower = text.to_lowercase();
    let positive_count = positive_words.iter().filter(|&&word| text_lower.contains(word)).count();
    let negative_count = negative_words.iter().filter(|&&word| text_lower.contains(word)).count();
    
    let (sentiment, confidence) = if positive_count > negative_count {
        ("positive", 0.7)
    } else if negative_count > positive_count {
        ("negative", 0.7)
    } else {
        ("neutral", 0.5)
    };
    
    Ok((json!({
        "sentiment": sentiment,
        "positive_score": positive_count as f64 / (positive_count + negative_count + 1) as f64,
        "negative_score": negative_count as f64 / (positive_count + negative_count + 1) as f64
    }), Some(confidence)))
}

fn classify_text(input: &Value) -> Result<(Value, Option<f64>), StatusCode> {
    let text = input.as_str().ok_or(StatusCode::BAD_REQUEST)?;
    
    // Clasificación básica por categorías
    let categories = [
        ("technology", vec!["software", "computer", "programming", "code", "tech"]),
        ("business", vec!["company", "market", "sales", "revenue", "profit"]),
        ("science", vec!["research", "study", "analysis", "data", "experiment"]),
        ("sports", vec!["game", "player", "team", "score", "match"]),
    ];
    
    let text_lower = text.to_lowercase();
    let mut best_category = "general";
    let mut best_score = 0;
    
    for (category, keywords) in &categories {
        let score = keywords.iter().filter(|&&keyword| text_lower.contains(keyword)).count();
        if score > best_score {
            best_score = score;
            best_category = category;
        }
    }
    
    let confidence = if best_score > 0 { 0.8 } else { 0.3 };
    
    Ok((json!({
        "category": best_category,
        "keywords_found": best_score
    }), Some(confidence)))
}

fn perform_regression(input: &Value) -> Result<(Value, Option<f64>), StatusCode> {
    let data = input.as_array().ok_or(StatusCode::BAD_REQUEST)?;
    
    // Regresión lineal simple
    let values: Result<Vec<f64>, _> = data.iter()
        .map(|v| v.as_f64().ok_or(StatusCode::BAD_REQUEST))
        .collect();
    let values = values?;
    
    if values.len() < 2 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let n = values.len() as f64;
    let x_values: Vec<f64> = (0..values.len()).map(|i| i as f64).collect();
    
    let sum_x: f64 = x_values.iter().sum();
    let sum_y: f64 = values.iter().sum();
    let sum_xy: f64 = x_values.iter().zip(&values).map(|(x, y)| x * y).sum();
    let sum_x_squared: f64 = x_values.iter().map(|x| x * x).sum();
    
    let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x_squared - sum_x * sum_x);
    let intercept = (sum_y - slope * sum_x) / n;
    
    // Predicción para el siguiente punto
    let next_x = values.len() as f64;
    let prediction = slope * next_x + intercept;
    
    Ok((json!({
        "slope": slope,
        "intercept": intercept,
        "next_prediction": prediction,
        "trend": if slope > 0.0 { "increasing" } else { "decreasing" }
    }), Some(0.75)))
}

fn extract_features(input: &Value) -> Result<(Value, Option<f64>), StatusCode> {
    let text = input.as_str().ok_or(StatusCode::BAD_REQUEST)?;
    
    // Extracción básica de características de texto
    let word_count = text.split_whitespace().count();
    let char_count = text.chars().count();
    let sentence_count = text.split('.').filter(|s| !s.trim().is_empty()).count();
    let avg_word_length = if word_count > 0 {
        char_count as f64 / word_count as f64
    } else {
        0.0
    };
    
    // Características adicionales
    let uppercase_count = text.chars().filter(|c| c.is_uppercase()).count();
    let digit_count = text.chars().filter(|c| c.is_numeric()).count();
    let punctuation_count = text.chars().filter(|c| c.is_ascii_punctuation()).count();
    
    Ok((json!({
        "word_count": word_count,
        "char_count": char_count,
        "sentence_count": sentence_count,
        "avg_word_length": avg_word_length,
        "uppercase_ratio": uppercase_count as f64 / char_count as f64,
        "digit_ratio": digit_count as f64 / char_count as f64,
        "punctuation_ratio": punctuation_count as f64 / char_count as f64,
        "readability_score": calculate_readability_score(word_count, sentence_count, char_count)
    }), Some(0.9)))
}

fn calculate_readability_score(words: usize, sentences: usize, chars: usize) -> f64 {
    if sentences == 0 || words == 0 {
        return 0.0;
    }
    
    let avg_sentence_length = words as f64 / sentences as f64;
    let avg_syllables = chars as f64 / words as f64; // Aproximación simple
    
    // Fórmula simplificada de legibilidad
    206.835 - (1.015 * avg_sentence_length) - (84.6 * avg_syllables / 2.0)
}
