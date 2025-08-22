use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use argon2::{self, Config, Variant, Version};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub exp: usize,  // Expiration time
}

const JWT_SECRET: &[u8] = b"tu_clave_secreta_muy_segura"; // TODO: usar variable de entorno

pub async fn login(Json(payload): Json<LoginRequest>) -> Result<Json<Value>, StatusCode> {
    // TODO: Verificar credenciales en base de datos
    let is_valid = verify_password(&payload.password, "$argon2id$v=19$dummy_hash").unwrap_or(false);
    
    if is_valid {
        let token = generate_jwt(&payload.email)?;
        Ok(Json(json!({
            "message": "Login exitoso",
            "token": token,
            "user": {
                "email": payload.email
            }
        })))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn register(Json(payload): Json<RegisterRequest>) -> Result<Json<Value>, StatusCode> {
    // TODO: Verificar que el email no existe en BD
    let hashed_password = hash_password(&payload.password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user_id = Uuid::new_v4().to_string();
    // TODO: Guardar usuario en base de datos
    let token = generate_jwt(&payload.email)?;
    Ok(Json(json!({
        "message": "Usuario registrado exitosamente",
        "token": token,
        "user": {
            "id": user_id,
            "email": payload.email,
            "name": payload.name,
            "password_hash": hashed_password
        }
    })))
}

fn generate_jwt(email: &str) -> Result<String, StatusCode> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: email.to_owned(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn hash_password(password: &str) -> Result<String, argon2::Error> {
    let salt = b"mcp_salt"; // En producción, usa un salt aleatorio y único por usuario
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536, // 64 MB
        time_cost: 3,
        lanes: 4,
        ..Default::default()
    };
    argon2::hash_encoded(password.as_bytes(), salt, &config)
}

fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(hash, password.as_bytes())
}
