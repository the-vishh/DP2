/*!
 * Global and user statistics endpoints
 */

use actix_web::{web, HttpResponse};
use chrono::{DateTime, Utc};
use diesel::dsl::avg;
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Text};
use serde::Serialize;
use uuid::Uuid;

use crate::db::schema::{user_activity, users};
use crate::db::DbPool;

#[derive(Debug, Serialize)]
pub struct GlobalStatsResponse {
    pub total_users: i32,
    pub active_users: i32,
    pub total_scans: i32,
    pub threats_blocked: i32,
    pub scans_last_hour: i32,
    pub scans_last_24h: i32,
    pub threats_last_24h: i32,
    pub avg_confidence: f64,
    pub avg_latency_ms: f64,
    pub model_accuracy: Option<f64>,
    pub model_precision: Option<f64>,
    pub model_recall: Option<f64>,
    pub sensitivity_breakdown: SensitivityBreakdown,
    pub threat_breakdown: ThreatBreakdown,
    pub top_phishing_domains: Vec<DomainCount>,
}

#[derive(Debug, Serialize)]
pub struct SensitivityBreakdown {
    pub conservative: i32,
    pub balanced: i32,
    pub aggressive: i32,
}

#[derive(Debug, Serialize)]
pub struct ThreatBreakdown {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub safe: i32,
}

#[derive(Debug, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct UserStatsResponse {
    pub user_id: Uuid,
    pub total_scans: i32,
    pub threats_blocked: i32,
    pub last_scan: Option<DateTime<Utc>>,
    pub sensitivity_mode: String,
    pub avg_latency_ms: f64,
    pub scans_today: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct TopDomainRow {
    #[diesel(sql_type = Text)]
    domain: String,
    #[diesel(sql_type = BigInt)]
    count: i64,
}

/// GET /api/stats/global
/// Returns aggregated statistics across all users.
pub async fn get_global_stats(pool: web::Data<DbPool>) -> HttpResponse {
    let now = Utc::now().timestamp();
    let one_hour_ago = now - 3600;
    let one_day_ago = now - 86400;
    let one_day_ago_i32 = one_day_ago as i32;

    let stats = web::block(move || {
        let mut conn = pool.get().map_err(|e| {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(format!("{}", e)),
            )
        })?;

        let total_users: i64 = users::table
            .filter(users::is_active.eq(1))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let active_users: i64 = users::table
            .filter(users::is_active.eq(1))
            .filter(users::last_active_at.gt(one_day_ago_i32))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let total_scans: i64 = user_activity::table
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let threats_blocked: i64 = user_activity::table
            .filter(user_activity::is_phishing.eq(1))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let scans_last_hour: i64 = user_activity::table
            .filter(user_activity::timestamp.gt(one_hour_ago))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let scans_last_24h: i64 = user_activity::table
            .filter(user_activity::timestamp.gt(one_day_ago))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let threats_last_24h: i64 = user_activity::table
            .filter(user_activity::is_phishing.eq(1))
            .filter(user_activity::timestamp.gt(one_day_ago))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let avg_confidence = user_activity::table
            .select(avg(user_activity::confidence))
            .first::<Option<f64>>(&mut conn)
            .unwrap_or(None)
            .unwrap_or(0.0);

        let avg_latency_ms = users::table
            .filter(users::is_active.eq(1))
            .select(avg(users::average_response_time_ms))
            .first::<Option<f64>>(&mut conn)
            .unwrap_or(None)
            .unwrap_or(0.0);

        let conservative: i64 = users::table
            .filter(users::sensitivity_mode.eq("conservative"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let balanced: i64 = users::table
            .filter(users::sensitivity_mode.eq("balanced"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let aggressive: i64 = users::table
            .filter(users::sensitivity_mode.eq("aggressive"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let critical: i64 = user_activity::table
            .filter(user_activity::threat_level.eq("CRITICAL"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let high: i64 = user_activity::table
            .filter(user_activity::threat_level.eq("HIGH"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let medium: i64 = user_activity::table
            .filter(user_activity::threat_level.eq("MEDIUM"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let low: i64 = user_activity::table
            .filter(user_activity::threat_level.eq("LOW"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let safe: i64 = user_activity::table
            .filter(user_activity::threat_level.eq("SAFE"))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let top_domains_raw = diesel::sql_query(
            "SELECT encrypted_domain AS domain, COUNT(*) AS count
             FROM user_activity
             WHERE is_phishing = 1
             GROUP BY encrypted_domain
             ORDER BY count DESC
             LIMIT 5",
        )
        .load::<TopDomainRow>(&mut conn)
        .unwrap_or_default();

        let top_phishing_domains = top_domains_raw
            .into_iter()
            .map(|row| DomainCount {
                domain: row.domain,
                count: row.count,
            })
            .collect::<Vec<_>>();

        Ok::<GlobalStatsResponse, diesel::result::Error>(GlobalStatsResponse {
            total_users: total_users as i32,
            active_users: active_users as i32,
            total_scans: total_scans as i32,
            threats_blocked: threats_blocked as i32,
            scans_last_hour: scans_last_hour as i32,
            scans_last_24h: scans_last_24h as i32,
            threats_last_24h: threats_last_24h as i32,
            avg_confidence,
            avg_latency_ms,
            model_accuracy: None,
            model_precision: None,
            model_recall: None,
            sensitivity_breakdown: SensitivityBreakdown {
                conservative: conservative as i32,
                balanced: balanced as i32,
                aggressive: aggressive as i32,
            },
            threat_breakdown: ThreatBreakdown {
                critical: critical as i32,
                high: high as i32,
                medium: medium as i32,
                low: low as i32,
                safe: safe as i32,
            },
            top_phishing_domains,
        })
    })
    .await;

    match stats {
        Ok(Ok(stats)) => HttpResponse::Ok().json(stats),
        Ok(Err(e)) => {
            log::error!("❌ Global stats query failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to query statistics"
            }))
        }
        Err(e) => {
            log::error!("❌ Global stats blocking error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }))
        }
    }
}

/// GET /api/stats/user/{user_id}
/// Returns statistics for a specific user.
pub async fn get_user_stats(
    pool: web::Data<DbPool>,
    user_id: web::Path<Uuid>,
) -> HttpResponse {
    let uid = user_id.into_inner();
    let uid_string = uid.to_string();
    let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();

    let stats = web::block(move || {
        let mut conn = pool.get().map_err(|e| {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(format!("{}", e)),
            )
        })?;

        let user_row = users::table
            .filter(users::user_id.eq(&uid_string))
            .select((
                users::sensitivity_mode,
                users::average_response_time_ms,
                users::created_at,
            ))
            .first::<(String, f64, i32)>(&mut conn)
            .optional()?;

        let Some((sensitivity_mode, avg_latency_ms, created_at_ts)) = user_row else {
            return Ok::<Option<UserStatsResponse>, diesel::result::Error>(None);
        };

        let total_scans: i64 = user_activity::table
            .filter(user_activity::user_id.eq(&uid_string))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let threats_blocked: i64 = user_activity::table
            .filter(user_activity::user_id.eq(&uid_string))
            .filter(user_activity::is_phishing.eq(1))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let scans_today: i64 = user_activity::table
            .filter(user_activity::user_id.eq(&uid_string))
            .filter(user_activity::timestamp.ge(today_start))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0);

        let last_scan_ts = user_activity::table
            .filter(user_activity::user_id.eq(&uid_string))
            .select(user_activity::timestamp)
            .order(user_activity::timestamp.desc())
            .first::<i64>(&mut conn)
            .optional()
            .unwrap_or(None);

        let last_scan = last_scan_ts.and_then(|ts| DateTime::from_timestamp(ts, 0));
        let created_at =
            DateTime::from_timestamp(created_at_ts as i64, 0).unwrap_or_else(Utc::now);

        Ok::<Option<UserStatsResponse>, diesel::result::Error>(Some(UserStatsResponse {
            user_id: uid,
            total_scans: total_scans as i32,
            threats_blocked: threats_blocked as i32,
            last_scan,
            sensitivity_mode,
            avg_latency_ms,
            scans_today: scans_today as i32,
            created_at,
        }))
    })
    .await;

    match stats {
        Ok(Ok(Some(stats))) => HttpResponse::Ok().json(stats),
        Ok(Ok(None)) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        })),
        Ok(Err(e)) => {
            log::error!("❌ User stats query failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to query user statistics"
            }))
        }
        Err(e) => {
            log::error!("❌ User stats blocking error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }))
        }
    }
}
