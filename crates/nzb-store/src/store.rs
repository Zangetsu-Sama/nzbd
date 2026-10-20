//! The configured backend as one value (ARCHITECTURE v3 13.1, T122). Production code (`nzb-web`,
//! `nzb-ingest`, `nzbd` outside its wiring) holds a [`Store`] and calls the repository traits of
//! [`crate::repo`]; only `nzbd`'s open/migrate/CLI wiring matches on the variants for operations that exist on
//! one backend only.

use std::fmt;
use std::str::FromStr;

use crate::SqliteDb;
use crate::pg::PgDb;

/// `db.backend`: a **closed** enum (review 34 I2 d). Only the two exact lower-case names parse; `"postgresql"`,
/// `"pg"`, `"SQLite"` or anything else is refused, never defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbBackend {
    /// The SQLite file of `db.path` (default for new installs, D35 b).
    Sqlite,
    /// PostgreSQL over a socket or an internal network (D33 d, D35 b).
    Postgres,
}

impl DbBackend {
    /// The stable config / `db_state.backend` / anchor name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

impl fmt::Display for DbBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `db.backend` value that is not exactly `sqlite` or `postgres`. Carries no input (the value may be
/// anything an operator or the environment typed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("UNKNOWN_DB_BACKEND: db.backend must be \"sqlite\" or \"postgres\"")]
pub struct UnknownBackend;

impl FromStr for DbBackend {
    type Err = UnknownBackend;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" => Ok(Self::Postgres),
            _ => Err(UnknownBackend),
        }
    }
}

/// The open database of the configured backend. Cheap to clone (both handles are pools behind `Arc`s);
/// one `match` per repository call.
#[derive(Clone, Debug)]
pub enum Store {
    /// `db.backend = "sqlite"`.
    Sqlite(SqliteDb),
    /// `db.backend = "postgres"`.
    Postgres(PgDb),
}

impl Store {
    /// Which backend this is.
    #[must_use]
    pub const fn backend(&self) -> DbBackend {
        match self {
            Self::Sqlite(_) => DbBackend::Sqlite,
            Self::Postgres(_) => DbBackend::Postgres,
        }
    }

    /// The SQLite handle, for `nzbd`'s backend-specific wiring only.
    #[must_use]
    pub const fn as_sqlite(&self) -> Option<&SqliteDb> {
        match self {
            Self::Sqlite(db) => Some(db),
            Self::Postgres(_) => None,
        }
    }

    /// The Postgres handle, for `nzbd`'s backend-specific wiring only.
    #[must_use]
    pub const fn as_postgres(&self) -> Option<&PgDb> {
        match self {
            Self::Sqlite(_) => None,
            Self::Postgres(db) => Some(db),
        }
    }

    /// Opens (creating and migrating) the SQLite library of `cfg` (see [`SqliteDb::open`]).
    ///
    /// # Errors
    /// As [`SqliteDb::open`].
    pub async fn open_sqlite(cfg: &crate::DbConfig) -> Result<Self, crate::StoreError> {
        SqliteDb::open(cfg).await.map(Self::Sqlite)
    }

    /// Connection pool facts for health pages.
    #[must_use]
    pub fn pool_info(&self) -> crate::PoolInfo {
        match self {
            Self::Sqlite(db) => db.pool_info(),
            Self::Postgres(db) => db.pool_info(),
        }
    }

    /// Writes a backup of the library into `dir` and keeps the newest `keep` (0600, sealed with `key` when given):
    /// the SQLite `VACUUM INTO` copy or the Postgres snapshot export. Backup files are backend-specific.
    ///
    /// # Errors
    /// Database, filesystem or encryption errors.
    pub async fn backup(
        &self,
        dir: &std::path::Path,
        now: i64,
        keep: usize,
        key: Option<&crate::BackupKey>,
    ) -> Result<crate::BackupReport, crate::StoreError> {
        match self {
            Self::Sqlite(db) => db.backup_with(dir, now, keep, key).await,
            Self::Postgres(db) => {
                let r = db.snapshot_backup(dir, now, keep, key).await?;
                Ok(crate::BackupReport {
                    path: r.path,
                    rotated: r.rotated,
                })
            }
        }
    }

    /// Closes the pools.
    pub async fn close(&self) {
        match self {
            Self::Sqlite(db) => db.close().await,
            Self::Postgres(db) => db.close().await,
        }
    }
}

impl From<SqliteDb> for Store {
    fn from(db: SqliteDb) -> Self {
        Self::Sqlite(db)
    }
}

impl From<PgDb> for Store {
    fn from(db: PgDb) -> Self {
        Self::Postgres(db)
    }
}

#[cfg(test)]
mod tests {
    use super::{DbBackend, UnknownBackend};

    #[test]
    fn backend_names_are_a_closed_set() {
        assert_eq!("sqlite".parse(), Ok(DbBackend::Sqlite));
        assert_eq!("postgres".parse(), Ok(DbBackend::Postgres));
        for bad in [
            "",
            "pg",
            "postgresql",
            "Postgres",
            "SQLite",
            "sqlite3",
            " sqlite",
            "sqlite ",
            "mysql",
        ] {
            assert_eq!(bad.parse::<DbBackend>(), Err(UnknownBackend), "{bad:?}");
        }
        for b in [DbBackend::Sqlite, DbBackend::Postgres] {
            assert_eq!(b.as_str().parse(), Ok(b));
            assert_eq!(b.to_string(), b.as_str());
        }
    }
}
