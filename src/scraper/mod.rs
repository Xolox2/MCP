use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use scraper::{Html, Selector};
use url::Url;

#[derive(Debug, Deserialize)]
pub struct ScrapeRequest {
    pub url: String,
    pub selectors: Option<Vec<String>>, // CSS selectors opcionales
}

#[derive(Debug, Serialize)]
pub struct ScrapeResult {
    pub url: String,
    pub title: Option<String>,
    pub content: Vec<ScrapedElement>,
    pub metadata: ScrapeMetadata,
}

#[derive(Debug, Serialize)]
pub struct ScrapedElement {
    pub selector: String,
    pub text: String,
    pub html: String,
}

#[derive(Debug, Serialize)]
pub struct ScrapeMetadata {
    pub status: String,
    pub timestamp: String,
    pub processing_time_ms: u64,
}

pub async fn scrape_url(Json(payload): Json<ScrapeRequest>) -> Result<Json<ScrapeResult>, StatusCode> {
    let start_time = std::time::Instant::now();
    
    // Validar URL
    let url = Url::parse(&payload.url)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Realizar petición HTTP
    let client = reqwest::Client::new();
    let response = client
        .get(url.as_str())
        .header("User-Agent", "MCP-Scraper/1.0")
        .send()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let html_content = response
        .text()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Parsear HTML
    let document = Html::parse_document(&html_content);
    
    // Extraer título
    let title_selector = Selector::parse("title").unwrap();
    let title = document
        .select(&title_selector)
        .next()
        .map(|element| element.text().collect::<String>());
    
    // Extraer contenido según selectores especificados
    let mut content = Vec::new();
    let default_selectors = vec!["h1", "h2", "h3", "p", "a"];
    let selectors_to_use = payload.selectors.as_ref().unwrap_or(&default_selectors);
    
    for selector_str in selectors_to_use {
        if let Ok(selector) = Selector::parse(selector_str) {
            for element in document.select(&selector) {
                content.push(ScrapedElement {
                    selector: selector_str.clone(),
                    text: element.text().collect::<String>(),
                    html: element.html(),
                });
            }
        }
    }
    
    let processing_time = start_time.elapsed().as_millis() as u64;
    
    let result = ScrapeResult {
        url: payload.url,
        title,
        content,
        metadata: ScrapeMetadata {
            status: "success".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processing_time_ms: processing_time,
        },
    };
    
    Ok(Json(result))
}

pub async fn scrape_text_analysis(text: &str) -> Result<Value, StatusCode> {
    // Análisis básico de texto extraído
    let word_count = text.split_whitespace().count();
    let char_count = text.chars().count();
    let sentences = text.split('.').count();
    
    Ok(json!({
        "word_count": word_count,
        "char_count": char_count,
        "sentence_count": sentences,
        "summary": extract_key_phrases(text)
    }))
}

fn extract_key_phrases(text: &str) -> Vec<String> {
    // Implementación básica de extracción de frases clave
    // TODO: Implementar algoritmo más sofisticado de NLP
    text.split('.')
        .take(3)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
