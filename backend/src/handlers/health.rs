/*!
 * Health check endpoint
 */

use actix_web::{web, HttpResponse};

use crate::{AppState, models::HealthResponse};

/// Health check endpoint
///
/// GET /health
pub async fn health_check(data: web::Data<AppState>) -> HttpResponse {
    let mut cache = data.cache.clone();

    let redis_status = match cache.health_check().await {
        Ok(true) => "healthy".to_string(),
        Ok(false) => "disabled".to_string(),
        Err(e) => format!("unhealthy: {}", e),
    };

    let ml_status = match data.ml_client.health_check().await {
        Ok(_) => "healthy".to_string(),
        Err(e) => format!("unhealthy: {}", e),
    };

    let overall_status = if redis_status == "healthy" && ml_status == "healthy" {
        "healthy"
    } else {
        "degraded"
    };

    HttpResponse::Ok().json(HealthResponse {
        status: overall_status.to_string(),
        redis: redis_status,
        ml_service: ml_status,
        timestamp: chrono::Utc::now(),
    })
}
