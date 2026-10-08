//! Key/value settings stored as JSON. Typed access lives with each feature.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};

pub fn get<T: DeserializeOwned>(conn: &Connection, key: &str) -> rusqlite::Result<Option<T>> {
    let raw: Option<String> = conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0)).optional()?;
    // A value that no longer parses (e.g. after a downgrade) falls back to the default.
    Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
}

pub fn set<T: Serialize>(conn: &Connection, key: &str, value: &T) -> rusqlite::Result<()> {
    let json = serde_json::to_string(value).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, json],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let conn = super::super::open_in_memory().unwrap();
        assert_eq!(super::get::<u32>(&conn, "x").unwrap(), None);
        super::set(&conn, "x", &30u32).unwrap();
        super::set(&conn, "x", &60u32).unwrap();
        assert_eq!(super::get::<u32>(&conn, "x").unwrap(), Some(60));
    }
}
