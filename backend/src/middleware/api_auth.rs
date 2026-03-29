use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use crate::services::control_plane_store;

fn token_from_query(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("token"), Some(value)) if !value.is_empty() => Some(value.to_string()),
                _ => None,
            }
        })
}

#[derive(Clone)]
pub struct ApiAuthMiddleware;

impl ApiAuthMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for ApiAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = ApiAuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ApiAuthMiddlewareService { service })
    }
}

pub struct ApiAuthMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ApiAuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.path().ends_with("/api/control-plane/bootstrap") {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        if req.method() == actix_web::http::Method::OPTIONS {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        let header_token = req
            .headers()
            .get("X-PhishGuard-Token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let query_token = token_from_query(req.query_string()).unwrap_or_default();
        let provided_token = if !header_token.is_empty() {
            header_token
        } else {
            query_token.as_str()
        };

        let Some(app_state) = req.app_data::<actix_web::web::Data<crate::AppState>>() else {
            let response = HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "missing_app_state"
            }));
            return Box::pin(async move {
                Ok(req.into_response(response).map_into_right_body())
            });
        };

        let token_is_valid = {
            let credentials = app_state
                .control_plane_credentials
                .lock()
                .expect("control plane mutex poisoned");

            credentials
                .values()
                .any(|credential| credential.token == provided_token)
        };

        let token_is_valid = if token_is_valid {
            true
        } else if provided_token.is_empty() {
            false
        } else {
            match control_plane_store::get_control_plane_by_token(&app_state.db_pool, provided_token) {
                Ok(Some((install_id, credential))) => {
                    let mut credentials = app_state
                        .control_plane_credentials
                        .lock()
                        .expect("control plane mutex poisoned");
                    credentials.insert(install_id, credential);
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    log::warn!("Control-plane token DB lookup failed: {}", e);
                    false
                }
            }
        };

        if !token_is_valid {
            let response = HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized local API access"
            }));
            return Box::pin(async move {
                Ok(req.into_response(response).map_into_right_body())
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
