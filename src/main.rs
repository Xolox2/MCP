
// Importa los componentes principales de Axum para crear rutas y manejar peticiones HTTP
use axum::{
    routing::{get, post}, // Para definir rutas GET y POST
    Router,               // El router principal de la app
    http::StatusCode,     // Códigos de estado HTTP (200, 404, etc.)
    Json,                 // Para respuestas JSON
};
// Serialización y deserialización de JSON
use serde_json::{json, Value};
// Para definir la dirección y puerto del servidor
use std::net::SocketAddr;
// Middleware para habilitar CORS (Cross-Origin Resource Sharing)
use tower_http::cors::CorsLayer;
// Para logging estructurado
use tracing_subscriber;

// Importa los módulos locales (cada uno en su carpeta)
mod auth;      // Lógica de autenticación (login, registro)
mod scraper;   // Lógica de scraping web
mod api;       // Utilidades y controladores de la API
mod security;  // Validaciones y auditoría de seguridad


// Punto de entrada principal de la app (async por el runtime Tokio)
#[tokio::main]
async fn main() {
    // Inicializa el sistema de logging para registrar eventos y errores
    tracing_subscriber::fmt::init();

    // Construye el router de la API y define las rutas/endpoints
    let app = Router::new()
        // Ruta raíz: muestra info básica de la API
        .route("/", get(root))
        // Ruta de salud: para comprobar si el servidor está vivo
        .route("/health", get(health))
        // Info extendida de la API
        .route("/api/info", get(api::get_api_info))
        // Endpoints de autenticación
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/register", post(auth::register))
        // Endpoint de scraping
        .route("/api/scrape", post(scraper::scrape_url))
        // Endpoints de seguridad
        .route("/api/security/validate", post(security::validate_security))
        .route("/api/security/audit", get(security::get_security_audit))
        // Middleware CORS: permite que la API sea accedida desde otros orígenes (útil para apps web/móvil)
        .layer(CorsLayer::permissive());

    // Define la dirección y puerto donde escuchará el servidor
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("🚀 Servidor MCP iniciado en http://{}", addr);
    
    // Inicia el servidor TCP y sirve la API
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}


// Handler para la ruta raíz: devuelve info básica de la API en JSON
async fn root() -> Json<Value> {
    Json(json!({
        "message": "MCP Backend API",
        "version": "0.1.0",
        "endpoints": [
            "/health",
            "/api/auth/login",
            "/api/auth/register", 
            "/api/scrape"
        ]
    }))
}


// Handler para la ruta /health: responde con estado OK
async fn health() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"status": "ok", "service": "mcp-backend"})))
}
