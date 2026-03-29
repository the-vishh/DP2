use actix_web::{web, HttpRequest, HttpResponse};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{AppState, ControlPlaneCredential};
use crate::services::control_plane_store;

#[derive(Debug, Deserialize)]
pub struct ControlPlaneBootstrapRequest {
    pub install_id: String,
    pub extension_id: String,
}

#[derive(Debug, Serialize)]
pub struct ControlPlaneTokenResponse {
    pub token: String,
    pub install_id: String,
    pub issued_at: i64,
}

fn is_valid_identifier(value: &str) -> bool {
    let len = value.trim().len();
    (8..=128).contains(&len)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn request_origin(req: &HttpRequest) -> String {
    req.headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn extension_origin_matches(origin: &str, extension_id: &str) -> bool {
    origin == format!("chrome-extension://{}", extension_id)
}

pub async fn bootstrap_control_plane(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    payload: web::Json<ControlPlaneBootstrapRequest>,
) -> HttpResponse {
    let payload = payload.into_inner();

    if !is_valid_identifier(&payload.install_id) || !is_valid_identifier(&payload.extension_id) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_install_or_extension_identifier"
        }));
    }

    let origin = request_origin(&req);
    if !extension_origin_matches(&origin, &payload.extension_id) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "bootstrap_origin_mismatch"
        }));
    }

    let issued_at = chrono::Utc::now().timestamp();
    let token = generate_token();
    let extension_id = payload.extension_id.clone();

    {
        let mut credentials = app_state
            .control_plane_credentials
            .lock()
            .expect("control plane mutex poisoned");

        credentials.insert(
            payload.install_id.clone(),
            ControlPlaneCredential {
                token: token.clone(),
                extension_id: extension_id.clone(),
                issued_at,
            },
        );
    }

    if let Err(e) = control_plane_store::upsert_control_plane_credential(
        &app_state.db_pool,
        &payload.install_id,
        &ControlPlaneCredential {
            token: token.clone(),
            extension_id,
            issued_at,
        },
    ) {
        log::warn!(
            "Control-plane bootstrap token was issued but could not be persisted: {}",
            e
        );
    }

    HttpResponse::Ok().json(ControlPlaneTokenResponse {
        token,
        install_id: payload.install_id,
        issued_at,
    })
}

pub async fn rotate_control_plane_token(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    payload: web::Json<ControlPlaneBootstrapRequest>,
) -> HttpResponse {
    let payload = payload.into_inner();

    if !is_valid_identifier(&payload.install_id) || !is_valid_identifier(&payload.extension_id) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_install_or_extension_identifier"
        }));
    }

    let origin = request_origin(&req);
    if !extension_origin_matches(&origin, &payload.extension_id) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "rotate_origin_mismatch"
        }));
    }

    let provided_token = req
        .headers()
        .get("X-PhishGuard-Token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    let issued_at = chrono::Utc::now().timestamp();
    let new_token = generate_token();
    let extension_id = payload.extension_id.clone();

    let mut credentials = app_state
        .control_plane_credentials
        .lock()
        .expect("control plane mutex poisoned");

    let existing = if let Some(existing) = credentials.get(&payload.install_id) {
        Some(existing.clone())
    } else {
        match control_plane_store::get_control_plane_by_install_id(&app_state.db_pool, &payload.install_id)
        {
            Ok(Some(persisted)) => {
                credentials.insert(payload.install_id.clone(), persisted.clone());
                Some(persisted)
            }
            Ok(None) => None,
            Err(e) => {
                log::warn!("Failed to read persisted control-plane credential: {}", e);
                None
            }
        }
    };

    let Some(existing) = existing else {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "install_not_bootstrapped"
        }));
    };

    if existing.extension_id != payload.extension_id || existing.token != provided_token {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "invalid_rotation_credentials"
        }));
    }

    credentials.insert(
        payload.install_id.clone(),
        ControlPlaneCredential {
            token: new_token.clone(),
            extension_id: extension_id.clone(),
            issued_at,
        },
    );

    if let Err(e) = control_plane_store::upsert_control_plane_credential(
        &app_state.db_pool,
        &payload.install_id,
        &ControlPlaneCredential {
            token: new_token.clone(),
            extension_id,
            issued_at,
        },
    ) {
        log::warn!(
            "Control-plane token rotated in-memory but persistence failed: {}",
            e
        );
    }

    HttpResponse::Ok().json(ControlPlaneTokenResponse {
        token: new_token,
        install_id: payload.install_id,
        issued_at,
    })
}
