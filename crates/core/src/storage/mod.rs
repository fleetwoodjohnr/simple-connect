//! SQLite storage with forward-only migrations tracked in `PRAGMA user_version`.

pub mod settings;

use std::path::Path;

use rusqlite::Connection;

pub use rusqlite;

/// Append-only: never edit a shipped migration, add a new one.
const MIGRATIONS: &[&str] = &[include_str!("001_init.sql"), include_str!("002_devices.sql"), include_str!("003_remote_desktop.sql")];

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("The application database could not be opened.")]
    Sqlite(#[from] rusqlite::Error),
    #[error("The application database could not be created.")]
    Io(#[from] std::io::Error),
    #[error("The database was created by a newer version of Simple Connect (schema {0}). Update the app to open it.")]
    TooNew(usize),
}

pub fn open(path: &Path) -> Result<Connection, DbError> {
    crate::paths::ensure_private_file(path)?;
    let mut conn = Connection::open(path)?;
    configure(&mut conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> Result<Connection, DbError> {
    let mut conn = Connection::open_in_memory()?;
    configure(&mut conn)?;
    Ok(conn)
}

fn configure(conn: &mut Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 2000;",
    )?;
    migrate(conn)
}

fn migrate(conn: &mut Connection) -> Result<(), DbError> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let current = usize::try_from(current).unwrap_or(usize::MAX);
    if current > MIGRATIONS.len() {
        return Err(DbError::TooNew(current));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_once_and_rejects_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        drop(open(&path).unwrap());
        let conn = open(&path).unwrap(); // re-open: no migration re-run
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v as usize, MIGRATIONS.len());
        conn.pragma_update(None, "user_version", 999).unwrap();
        drop(conn);
        assert!(matches!(open(&path), Err(DbError::TooNew(999))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
