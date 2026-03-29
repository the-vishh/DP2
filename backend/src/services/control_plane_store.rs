use diesel::prelude::*;
use diesel::sql_types::{BigInt, Text};

use crate::{ControlPlaneCredential, db::DbPool};

#[derive(QueryableByName, Debug, Clone)]
pub struct ControlPlaneCredentialRow {
    #[diesel(sql_type = Text)]
    pub install_id: String,
    #[diesel(sql_type = Text)]
    pub extension_id: String,
    #[diesel(sql_type = Text)]
    pub token: String,
    #[diesel(sql_type = BigInt)]
    pub issued_at: i64,
}

pub fn ensure_control_plane_table(pool: &DbPool) -> Result<(), String> {
    let mut conn = pool.get().map_err(|e| e.to_string())?;

    diesel::sql_query(
        "CREATE TABLE IF NOT EXISTS control_plane_credentials (
            install_id TEXT PRIMARY KEY NOT NULL,
            extension_id TEXT NOT NULL,
            token TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );",
    )
    .execute(&mut conn)
    .map_err(|e| e.to_string())?;

    diesel::sql_query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_control_plane_token
         ON control_plane_credentials(token);",
    )
    .execute(&mut conn)
    .map_err(|e| e.to_string())?;

    Ok(())
}

pub fn upsert_control_plane_credential(
    pool: &DbPool,
    install_id: &str,
    credential: &ControlPlaneCredential,
) -> Result<(), String> {
    let mut conn = pool.get().map_err(|e| e.to_string())?;

    diesel::sql_query(
        "INSERT INTO control_plane_credentials (install_id, extension_id, token, issued_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, strftime('%s','now'))
         ON CONFLICT(install_id)
         DO UPDATE SET
            extension_id = excluded.extension_id,
            token = excluded.token,
            issued_at = excluded.issued_at,
            updated_at = strftime('%s','now');",
    )
    .bind::<Text, _>(install_id)
    .bind::<Text, _>(&credential.extension_id)
    .bind::<Text, _>(&credential.token)
    .bind::<BigInt, _>(credential.issued_at)
    .execute(&mut conn)
    .map_err(|e| e.to_string())?;

    Ok(())
}

pub fn get_control_plane_by_install_id(
    pool: &DbPool,
    install_id: &str,
) -> Result<Option<ControlPlaneCredential>, String> {
    let mut conn = pool.get().map_err(|e| e.to_string())?;

    let mut rows = diesel::sql_query(
        "SELECT install_id, extension_id, token, issued_at
         FROM control_plane_credentials
         WHERE install_id = ?1
         LIMIT 1;",
    )
    .bind::<Text, _>(install_id)
    .load::<ControlPlaneCredentialRow>(&mut conn)
    .map_err(|e| e.to_string())?;

    Ok(rows.pop().map(|row| ControlPlaneCredential {
        token: row.token,
        extension_id: row.extension_id,
        issued_at: row.issued_at,
    }))
}

pub fn get_control_plane_by_token(
    pool: &DbPool,
    token: &str,
) -> Result<Option<(String, ControlPlaneCredential)>, String> {
    let mut conn = pool.get().map_err(|e| e.to_string())?;

    let mut rows = diesel::sql_query(
        "SELECT install_id, extension_id, token, issued_at
         FROM control_plane_credentials
         WHERE token = ?1
         LIMIT 1;",
    )
    .bind::<Text, _>(token)
    .load::<ControlPlaneCredentialRow>(&mut conn)
    .map_err(|e| e.to_string())?;

    Ok(rows.pop().map(|row| {
        (
            row.install_id,
            ControlPlaneCredential {
                token: row.token,
                extension_id: row.extension_id,
                issued_at: row.issued_at,
            },
        )
    }))
}
