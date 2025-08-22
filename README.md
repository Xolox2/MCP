# MCP Backend - Rust + Axum


Backend MCP profesional y seguro desarrollado en Rust con framework Axum. Incluye módulos completos para scraping, autenticación y ciberseguridad.

## 🚀 Características

- **Autenticación segura**: JWT, Argon2id, validación robusta
- **Web Scraping**: Extracción inteligente de contenido web
- **Ciberseguridad**: Validación de entrada, detección de amenazas, auditorías
- **API REST**: Endpoints bien documentados y estructurados

## 📁 Estructura del Proyecto

```
src/
├── main.rs          # Punto de entrada principal
├── auth/            # Autenticación y autorización
├── scraper/         # Web scraping y análisis de contenido
├── api/             # Controladores y utilidades de API
└── security/        # Validación y auditoría de seguridad
```

## 🛠️ Instalación y Uso

### Prerrequisitos
- Rust 1.70+ (instalar desde https://rustup.rs/)
- Visual Studio Build Tools (Windows)

### Pasos
1. Clona o descarga el proyecto
2. Navega a la carpeta `mcp-backend`
3. Instala dependencias:
   ```bash
   cargo build
   ```
4. Ejecuta el servidor:
   ```bash
   cargo run
   ```

El servidor estará disponible en `http://localhost:8080`

## 📚 Endpoints de la API

### Información General
- `GET /` - Información de la API
- `GET /health` - Estado del servidor
- `GET /api/info` - Detalles completos de la API

### Autenticación
- `POST /api/auth/register` - Registro de usuarios
- `POST /api/auth/login` - Inicio de sesión

### Scraping
- `POST /api/scrape` - Extraer contenido de URLs


### Seguridad
- `POST /api/security/validate` - Validación de seguridad
- `GET /api/security/audit` - Auditoría del sistema

## 🔧 Configuración

### Variables de Entorno (Recomendadas)
```bash
JWT_SECRET=tu_clave_secreta_muy_segura_y_larga
DATABASE_URL=postgresql://usuario:password@localhost/mcp_db
RUST_LOG=info
```

### Dependencias Principales
- **axum**: Framework web moderno y rápido
- **tokio**: Runtime asíncrono
- **serde**: Serialización JSON
- **jsonwebtoken**: Autenticación JWT
- **argon2**: Hashing seguro de contraseñas (Argon2id)
- **scraper**: Parsing HTML
- **reqwest**: Cliente HTTP
- **ndarray**: Operaciones matemáticas
- **tracing**: Logging estructurado

## 🛡️ Características de Seguridad

- Validación estricta de entrada
- Protección contra XSS y SQL injection
- Hashing seguro de contraseñas con Argon2id
- Tokens JWT con expiración
- Sanitización automática de datos
- Auditorías de seguridad en tiempo real


## 🌐 Scraping Inteligente

- Extracción de contenido web
- Selectores CSS personalizables
- Análisis de metadatos
- Medición de tiempo de procesamiento
- Manejo de errores robusto

## 📝 Ejemplo de Uso

### Registro de Usuario
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@ejemplo.com","password":"MiPassword123","name":"Usuario"}'
```

### Scraping de Página Web
```bash
curl -X POST http://localhost:8080/api/scrape \
  -H "Content-Type: application/json" \
  -d '{"url":"https://ejemplo.com","selectors":["h1","p"]}'
```


### Validación de Seguridad
```bash
curl -X POST http://localhost:8080/api/security/validate \
  -H "Content-Type: application/json" \
  -d '{"input_type":"text","content":"<script>alert(1)</script>","security_level":"strict"}'
```

## 🚀 Próximos Pasos

Para expandir el backend, considera:

1. **Base de Datos**: Integrar PostgreSQL o SQLite con SQLx
2. **Rate Limiting**: Limitar peticiones por usuario/IP
3. **Caching**: Redis para optimizar rendimiento
4. **WebSockets**: Comunicación en tiempo real
5. **Documentación**: OpenAPI/Swagger
6. **Testing**: Tests unitarios e integración
7. **Docker**: Containerización para despliegue
8. **CI/CD**: Automatización de builds y despliegues

## 🤝 Contribución

Este backend está diseñado para ser modular y extensible. Cada módulo puede expandirse independientemente según las necesidades específicas de tu aplicación.

---

**¡Backend MCP listo para usar en producción!** 🎉
