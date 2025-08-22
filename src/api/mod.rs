use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// Módulo para rutas y controladores de la API

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: String,
    pub timestamp: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: message.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
    
    pub fn error(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: message.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

impl Default for PaginationQuery {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(10),
        }
    }
}

pub async fn get_api_info() -> Json<Value> {
    Json(json!({
        "name": "MCP Backend API",
        "version": "0.1.0",
        "description": "Backend seguro con scraping, ML y autenticación",
        "endpoints": {
            "auth": [
                "POST /api/auth/login",
                "POST /api/auth/register",
                "POST /api/auth/logout",
                "GET /api/auth/me"
            ],
            "scraping": [
                "POST /api/scrape",
                "GET /api/scrape/history",
                "POST /api/scrape/analyze"
            ],
            "machine_learning": [
                "POST /api/ml/predict",
                "GET /api/ml/models",
                "POST /api/ml/train"
            ],
            "security": [
                "POST /api/security/validate",
                "GET /api/security/audit"
            ]
        },
        "features": [
            "JWT Authentication",
            "Web Scraping",
            "Text Analysis",
            "Machine Learning",
            "Rate Limiting",
            "CORS Support",
            "Input Validation"
        ]
    }))
}

// Utilidades para validación de entrada
pub fn validate_email(email: &str) -> bool {
    email.contains('@') && email.contains('.') && email.len() > 5
}

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("La contraseña debe tener al menos 8 caracteres".to_string());
    }
    
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err("La contraseña debe contener al menos una mayúscula".to_string());
    }
    
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err("La contraseña debe contener al menos una minúscula".to_string());
    }
    
    if !password.chars().any(|c| c.is_numeric()) {
        return Err("La contraseña debe contener al menos un número".to_string());
    }
    
    Ok(())
}

pub fn sanitize_input(input: &str) -> String {
    // Sanitización básica de entrada
    input
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('&', "&amp;")
}
