/*!
 * Redis caching service
 */

use redis::{Client, AsyncCommands};
use redis::aio::ConnectionManager;
use sha2::{Sha256, Digest};
use anyhow::Result;

use crate::models::URLCheckResponse;

/// Redis cache service for storing URL check results
#[derive(Clone)]
pub struct CacheService {
    client: Option<ConnectionManager>,
}

impl CacheService {
    /// Create new cache service
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = match Client::open(redis_url) {
            Ok(client) => client,
            Err(e) => {
                log::warn!("⚠️ Redis client init failed, running without cache: {}", e);
                return Ok(Self { client: None });
            }
        };

        match ConnectionManager::new(client).await {
            Ok(manager) => Ok(Self {
                client: Some(manager),
            }),
            Err(e) => {
                log::warn!("⚠️ Redis connection failed, running without cache: {}", e);
                Ok(Self { client: None })
            }
        }
    }

    /// Whether Redis caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.client.is_some()
    }

    /// Generate cache key from URL
    fn cache_key(url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        let hash = hasher.finalize();
        format!("phishing:v1:{}", hex::encode(hash))
    }

    /// Get cached result for URL
    pub async fn get(&mut self, url: &str) -> Result<Option<URLCheckResponse>> {
        let Some(client) = self.client.as_mut() else {
            return Ok(None);
        };

        let key = Self::cache_key(url);

        let result: Option<String> = client.get(&key).await?;

        match result {
            Some(json) => {
                let response: URLCheckResponse = serde_json::from_str(&json)?;
                log::debug!("✅ Cache HIT for URL: {}", url);
                Ok(Some(response))
            }
            None => {
                log::debug!("❌ Cache MISS for URL: {}", url);
                Ok(None)
            }
        }
    }

    /// Store result in cache
    pub async fn set(&mut self, url: &str, response: &URLCheckResponse, ttl_seconds: usize) -> Result<()> {
        let Some(client) = self.client.as_mut() else {
            return Ok(());
        };

        let key = Self::cache_key(url);
        let json = serde_json::to_string(response)?;

        let _: () = client.set_ex(&key, json, ttl_seconds as u64).await?;

        log::debug!("💾 Cached result for URL: {} (TTL: {}s)", url, ttl_seconds);
        Ok(())
    }

    /// Check if Redis is healthy
    pub async fn health_check(&mut self) -> Result<bool> {
        let Some(client) = self.client.as_mut() else {
            return Ok(false);
        };

        // Try a simple GET operation instead of PING
        let _: Option<String> = client.get("__health_check__").await?;
        Ok(true)
    }

    /// Get cache statistics
    pub async fn get_stats(&mut self) -> Result<(usize, usize)> {
        // Redis INFO command requires using redis::cmd
        // For now, return default values
        Ok((0, 0))
    }
}
