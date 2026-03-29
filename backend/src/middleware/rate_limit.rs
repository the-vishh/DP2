/*!
 * Rate limiting middleware
 */

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::future::{ready, Ready};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_REQUESTS_PER_MINUTE: usize = 120;
const CHECK_URL_REQUESTS_PER_MINUTE: usize = 90;
const USER_ACTIVITY_REQUESTS_PER_MINUTE: usize = 60;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const WINDOW: Duration = Duration::from_secs(60);

static RATE_LIMIT_STATE: Lazy<Mutex<HashMap<String, VecDeque<Instant>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Rate limit middleware
pub struct RateLimitMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddlewareService { service }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(content_length) = req
            .headers()
            .get(actix_web::http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
        {
            if content_length > MAX_REQUEST_BYTES {
                return Box::pin(async move {
                    Err(actix_web::error::ErrorPayloadTooLarge(
                        "Payload too large. Max request size is 64KB.",
                    ))
                });
            }
        }

        let path = req.path().to_string();
        let method = req.method().clone();
        let client_key = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        let user_id_segment = path
            .split('/')
            .collect::<Vec<_>>()
            .windows(2)
            .find_map(|pair| {
                if pair[0] == "user" {
                    Some(pair[1].to_string())
                } else {
                    None
                }
            });

        let (bucket, per_minute_limit) = if path.ends_with("/api/check-url") {
            ("check-url", CHECK_URL_REQUESTS_PER_MINUTE)
        } else if method == actix_web::http::Method::POST
            && path.contains("/api/user/")
            && path.ends_with("/activity")
        {
            ("user-activity", USER_ACTIVITY_REQUESTS_PER_MINUTE)
        } else {
            ("default", DEFAULT_REQUESTS_PER_MINUTE)
        };

        let scoped_key = if let Some(user_id) = user_id_segment {
            format!("{}:{}:{}", bucket, client_key, user_id)
        } else {
            format!("{}:{}", bucket, client_key)
        };

        let now = Instant::now();
        let limited = {
            let mut state = RATE_LIMIT_STATE
                .lock()
                .expect("rate limit mutex poisoned");

            let events = state.entry(scoped_key).or_default();
            while let Some(front) = events.front() {
                if now.duration_since(*front) > WINDOW {
                    events.pop_front();
                } else {
                    break;
                }
            }

            if events.len() >= per_minute_limit {
                true
            } else {
                events.push_back(now);
                false
            }
        };

        if limited {
            return Box::pin(async move {
                Err(actix_web::error::ErrorTooManyRequests(
                    "Too many requests. Try again in a minute.",
                ))
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
