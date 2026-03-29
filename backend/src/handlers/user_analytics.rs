// 📊 USER PERSONAL ANALYTICS API
// Simplified working version for production

use actix_web::{web, HttpResponse, Result as ActixResult};
use diesel::prelude::*;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::env;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::db::DbPool;
use crate::db::models_analytics::*;
use crate::db::schema_analytics::*;

// ==========================================
// REQUEST/RESPONSE MODELS
// ==========================================

#[derive(Debug, Serialize)]
pub struct UserAnalyticsResponse {
    pub user_id: String,
    pub total_threats_blocked: i64,
    pub recent_activities: Vec<ActivityResponse>,
    pub threat_breakdown: ThreatBreakdownResponse,
}

#[derive(Debug, Serialize)]
pub struct ActivityResponse {
    pub activity_id: String,
    pub encrypted_url: String,
    pub domain: String,
    pub is_phishing: bool,
    pub threat_type: Option<String>,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ThreatBreakdownResponse {
    pub phishing_count: i32,
    pub malware_count: i32,
    pub cryptojacking_count: i32,
    pub total_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct LogActivityRequest {
    pub encrypted_url: String,
    pub encrypted_url_hash: String,
    pub domain: String,
    pub is_phishing: bool,
    pub threat_type: Option<String>,
    pub threat_level: Option<String>,
    pub confidence: f64,
    pub action_taken: String,
    pub client_ip: Option<String>,
    pub request_nonce: String,
    pub client_timestamp: i64,
}

#[derive(Debug, Deserialize)]
pub struct UserAnalyticsQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LogActivityResponse {
    pub success: bool,
    pub activity_id: String,
}

const REPLAY_WINDOW_SECONDS: i64 = 300;
static RECENT_NONCES: Lazy<Mutex<HashMap<String, i64>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn validate_activity_request(req: &LogActivityRequest) -> Result<(), String> {
    if req.encrypted_url.trim().is_empty() || req.encrypted_url.len() > 8192 {
        return Err("Invalid encrypted_url payload size".to_string());
    }
    if req.encrypted_url_hash.len() != 64 {
        return Err("encrypted_url_hash must be 64 hex chars".to_string());
    }
    if req.domain.trim().is_empty() || req.domain.len() > 255 {
        return Err("Invalid domain value".to_string());
    }
    if !(0.0..=1.0).contains(&req.confidence) {
        return Err("confidence must be between 0.0 and 1.0".to_string());
    }
    if !req
        .encrypted_url_hash
        .chars()
        .all(|c| c.is_ascii_hexdigit())
    {
        return Err("encrypted_url_hash must be hex".to_string());
    }
    if req.request_nonce.trim().len() < 16 || req.request_nonce.len() > 128 {
        return Err("request_nonce length must be between 16 and 128".to_string());
    }
    if !matches!(req.action_taken.as_str(), "blocked" | "warned" | "allowed") {
        return Err("action_taken must be one of blocked, warned, allowed".to_string());
    }

    let now = Utc::now().timestamp();
    if (now - req.client_timestamp).abs() > REPLAY_WINDOW_SECONDS {
        return Err("client_timestamp outside allowed replay window".to_string());
    }

    Ok(())
}

// ==========================================
// HANDLERS
// ==========================================

/// GET /api/user/{user_id}/analytics
/// Returns user's personal analytics
pub async fn get_user_analytics(
    pool: web::Data<DbPool>,
    user_id_path: web::Path<Uuid>,
    query: web::Query<UserAnalyticsQuery>,
) -> ActixResult<HttpResponse> {
    let user_id = user_id_path.to_string(); // Convert Uuid to String for SQLite
    let user_id_for_response = user_id.clone(); // Clone for use outside closure
    let requested_limit = query.limit.unwrap_or(100);
    let activity_limit = requested_limit.clamp(20, 500);

    let result = web::block(move || {
        let mut conn = pool.get().map_err(|e| {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(format!("{}", e)),
            )
        })?;

        // Get recent activities
        let activities: Vec<UserActivity> = user_activity::table
            .filter(user_activity::user_id.eq(&user_id))
            .order(user_activity::timestamp.desc())
            .limit(activity_limit)
            .select(UserActivity::as_select())
            .load(&mut conn)?;

        // Get threat stats
        let threat_stats = user_threat_stats::table
            .filter(user_threat_stats::user_id.eq(&user_id))
            .select(UserThreatStats::as_select())
            .first(&mut conn)
            .optional()?;

        // Count total threats
        let total_threats: i64 = user_activity::table
            .filter(user_activity::user_id.eq(&user_id))
            .filter(user_activity::is_phishing.eq(1)) // SQLite uses 1 for true
            .count()
            .get_result(&mut conn)?;

        Ok::<_, diesel::result::Error>((activities, threat_stats, total_threats))
    })
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let (activities, threat_stats, total_threats) = result
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Query error: {}", e)))?;

    // Build response
    let recent_activities: Vec<ActivityResponse> = activities
        .into_iter()
        .map(|a| ActivityResponse {
            activity_id: a.activity_id.to_string(),
            encrypted_url: a.encrypted_url.clone(),
            domain: a.encrypted_domain.clone(),
            is_phishing: a.is_phishing != 0, // Convert i32 to bool
            threat_type: a.threat_type.clone(),
            confidence: a.confidence.unwrap_or(0.0),
            timestamp: chrono::DateTime::from_timestamp(a.timestamp, 0).unwrap_or_else(|| Utc::now()), // Convert Unix timestamp to DateTime
        })
        .collect();

    let threat_breakdown = if let Some(stats) = threat_stats {
        ThreatBreakdownResponse {
            phishing_count: stats.phishing_count,
            malware_count: stats.malware_count,
            cryptojacking_count: stats.cryptojacking_count,
            total_count: stats.phishing_count + stats.malware_count + stats.cryptojacking_count,
        }
    } else {
        ThreatBreakdownResponse {
            phishing_count: 0,
            malware_count: 0,
            cryptojacking_count: 0,
            total_count: 0,
        }
    };

    let response = UserAnalyticsResponse {
        user_id: user_id_for_response,
        total_threats_blocked: total_threats,
        recent_activities,
        threat_breakdown,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/user/{user_id}/activity
/// Logs a new activity (URL check)
pub async fn log_activity(
    app_state: web::Data<crate::AppState>,
    pool: web::Data<DbPool>,
    user_id_path: web::Path<Uuid>,
    request: web::Json<LogActivityRequest>,
) -> ActixResult<HttpResponse> {
    let user_id = user_id_path.to_string(); // Convert to String for SQLite
    let req = request.into_inner();

    if let Err(message) = validate_activity_request(&req) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": message
        })));
    }

    {
        let now = Utc::now().timestamp();
        let replay_key = format!("{}:{}", user_id, req.request_nonce);
        let mut nonce_store = RECENT_NONCES.lock().expect("nonce mutex poisoned");

        nonce_store.retain(|_, ts| now - *ts <= REPLAY_WINDOW_SECONDS);

        if nonce_store.contains_key(&replay_key) {
            return Ok(HttpResponse::Conflict().json(serde_json::json!({
                "error": "duplicate_request_nonce"
            })));
        }

        nonce_store.insert(replay_key, now);
    }

    let allow_client_ip = env::var("ALLOW_CLIENT_IP_ANALYTICS")
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);

    let client_ip_for_lookup = if allow_client_ip { req.client_ip.clone() } else { None };

    // 🌍 GeoIP Lookup (if IP provided and GeoIP available)
    let country_info = if let (Some(ip_str), Some(geoip)) = (&client_ip_for_lookup, &app_state.geoip) {
        if let Ok(ip) = ip_str.parse() {
            geoip.lookup_country(ip)
        } else {
            None
        }
    } else {
        None
    };

    let is_threat = req.is_phishing;
    let threat_type_clone = req.threat_type.clone();

    let result = web::block(move || {
        let mut conn = pool.get().map_err(|e| {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(format!("{}", e)),
            )
        })?;

        // Insert activity
        let new_activity = NewUserActivity {
            user_id: user_id.clone(),
            encrypted_url: req.encrypted_url,
            url_hash: req.encrypted_url_hash.clone(),
            encrypted_domain: req.domain.clone(),
            domain_hash: req.encrypted_url_hash,
            is_phishing: if req.is_phishing { 1 } else { 0 }, // Convert bool to i32
            threat_type: req.threat_type.clone(),
            threat_level: req.threat_level.clone().unwrap_or_else(|| "unknown".to_string()),
            confidence: Some(req.confidence),
            action_taken: req.action_taken,
            encryption_nonce: req.request_nonce,
        };

        let activity: UserActivity = diesel::insert_into(user_activity::table)
            .values(&new_activity)
            .returning(UserActivity::as_returning())
            .get_result(&mut conn)?;

        // Update threat stats if it's a threat
        if req.is_phishing {
            // Try to get existing stats
            let stats_opt = user_threat_stats::table
                .filter(user_threat_stats::user_id.eq(&user_id))
                .select(UserThreatStats::as_select())
                .first(&mut conn)
                .optional()?;

            if let Some(mut stats) = stats_opt {
                // Update existing stats
                match req.threat_type.as_deref() {
                    Some("phishing") => stats.phishing_count += 1,
                    Some("malware") => stats.malware_count += 1,
                    Some("cryptojacking") => stats.cryptojacking_count += 1,
                    _ => {}
                }

                // TODO: Add timestamp update when we figure out diesel SQLite timestamp handling
                diesel::update(user_threat_stats::table)
                    .filter(user_threat_stats::user_id.eq(&user_id))
                    .set((
                        user_threat_stats::phishing_count.eq(stats.phishing_count),
                        user_threat_stats::malware_count.eq(stats.malware_count),
                        user_threat_stats::cryptojacking_count.eq(stats.cryptojacking_count),
                    ))
                    .execute(&mut conn)?;
            } else {
                // Create new stats
                let new_stats = NewUserThreatStats::new(user_id.clone());
                diesel::insert_into(user_threat_stats::table)
                    .values(&new_stats)
                    .execute(&mut conn)?;
            }
        }

        // 🌍 Update geographic threat sources (if country identified and it's a threat)
        if is_threat {
            if let Some(ref country) = country_info {
                // Check if country already exists
                let existing = user_threat_sources::table
                    .filter(user_threat_sources::user_id.eq(&user_id))
                    .filter(user_threat_sources::country_code.eq(&country.code))
                    .select(UserThreatSource::as_select())
                    .first(&mut conn)
                    .optional()?;

                if let Some(mut source) = existing {
                    // Update count (TODO: Add last_seen timestamp)
                    source.threat_count += 1;
                    diesel::update(user_threat_sources::table)
                        .filter(user_threat_sources::source_id.eq(source.source_id))
                        .set(user_threat_sources::threat_count.eq(source.threat_count))
                        .execute(&mut conn)?;
                } else {
                    // Insert new country source
                    let phishing_count = if threat_type_clone.as_deref() == Some("phishing") { 1 } else { 0 };
                    let new_source = NewUserThreatSource {
                        user_id,
                        country_code: Some(country.code.clone()),
                        country_name: Some(country.name.clone()),
                        threat_count: 1,
                        phishing_count,
                    };
                    diesel::insert_into(user_threat_sources::table)
                        .values(&new_source)
                        .execute(&mut conn)?;
                }

                log::info!("🌍 Threat from {} ({})", country.name, country.code);
            }
        }        Ok::<_, diesel::result::Error>(activity.activity_id)
    })
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Database error: {}", e)))?;

    let activity_id = result
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Query error: {}", e)))?;

    Ok(HttpResponse::Ok().json(LogActivityResponse {
        success: true,
        activity_id: activity_id.to_string(),
    }))
}

/// GET /api/user/{user_id}/threats/live
/// Server-Sent Events (SSE) endpoint for live threat updates
pub async fn live_threats(
    pool: web::Data<DbPool>,
    user_id_path: web::Path<Uuid>,
) -> ActixResult<HttpResponse> {
    use std::time::Duration;
    use actix_web::rt::time::interval;

    let user_id = user_id_path.to_string(); // Convert to String for SQLite

    // Create SSE stream
    let stream = async_stream::stream! {
        let mut interval = interval(Duration::from_secs(2));
        let mut last_activity_id: Option<String> = None;

        loop {
            interval.tick().await;

            // Check for new activities
            let pool_clone = pool.clone();
            let last_id = last_activity_id.clone();
            let user_id_clone = user_id.clone();
            let result = web::block(move || {
                let mut conn = pool_clone.get().map_err(|e| {
                    diesel::result::Error::DatabaseError(
                        diesel::result::DatabaseErrorKind::UnableToSendCommand,
                        Box::new(format!("{}", e)),
                    )
                })?;

                let activity: Option<UserActivity> = if let Some(lid) = last_id {
                    user_activity::table
                        .filter(user_activity::user_id.eq(&user_id_clone))
                        .filter(user_activity::is_phishing.eq(1)) // SQLite uses 1 for true
                        .filter(user_activity::activity_id.ne(lid))
                        .order(user_activity::timestamp.desc())
                        .limit(1)
                        .select(UserActivity::as_select())
                        .first(&mut conn)
                        .optional()?
                } else {
                    user_activity::table
                        .filter(user_activity::user_id.eq(&user_id_clone))
                        .filter(user_activity::is_phishing.eq(1)) // SQLite uses 1 for true
                        .order(user_activity::timestamp.desc())
                        .limit(1)
                        .select(UserActivity::as_select())
                        .first(&mut conn)
                        .optional()?
                };

                Ok::<_, diesel::result::Error>(activity)
            }).await;

            match result {
                Ok(Ok(Some(activity))) => {
                    last_activity_id = Some(activity.activity_id.clone());

                    let alert = serde_json::json!({
                        "type": "new_threat",
                        "activity_id": activity.activity_id,
                        "encrypted_url": activity.encrypted_url,
                        "domain": activity.encrypted_domain,
                        "threat_type": activity.threat_type,
                        "threat_level": activity.threat_level,
                        "confidence": activity.confidence,
                        "timestamp": activity.timestamp,
                    });

                    yield Ok::<_, actix_web::Error>(
                        web::Bytes::from(format!("data: {}\n\n", alert))
                    );
                }
                _ => {
                    // Send keepalive
                    yield Ok::<_, actix_web::Error>(
                        web::Bytes::from(": keepalive\n\n")
                    );
                }
            }
        }
    };

    Ok(HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream))
}
