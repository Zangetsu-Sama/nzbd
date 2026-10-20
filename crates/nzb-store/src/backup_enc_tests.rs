//! T104: encrypted backups (SEC-052) and atomic TOTP re-seal (SEC-053).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::{
    BackupCryptoError, BackupKey, DbConfig, ENC_SUFFIX, Reseal, SqliteDb, backup_file_with,
    decrypt_file, looks_encrypted,
};

async fn open(dir: &tempfile::TempDir) -> SqliteDb {
    SqliteDb::open(&DbConfig {
        path: dir.path().join("nzbd.sqlite"),
    })
    .await
    .unwrap()
}

fn key(b: u8) -> BackupKey {
    BackupKey::from_slice(&[b; 32]).unwrap()
}

#[tokio::test]
async fn sec_052_encrypted_backup_is_ciphertext_and_restores_with_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    sqlx::query("INSERT INTO audit_log (ts, event) VALUES (1, 'plaintext-marker-xyzzy')")
        .execute(db.writer())
        .await
        .unwrap();
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let k = key(7);
    let rep = db
        .backup_with(&backups, 1_700_000_000, 14, Some(&k))
        .await
        .unwrap();
    db.close().await;

    let name = rep.path.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(name.ends_with(&format!("Z.sqlite{ENC_SUFFIX}")), "{name}");
    assert_eq!(
        fs::metadata(&rep.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(looks_encrypted(&rep.path));
    // Only the encrypted file remains: the plaintext snapshot and temp files are gone.
    assert_eq!(fs::read_dir(&backups).unwrap().count(), 1);
    let raw = fs::read(&rep.path).unwrap();
    assert!(
        !raw.windows(22).any(|w| w == b"plaintext-marker-xyzzy"),
        "the audit text must not appear in the ciphertext"
    );
    assert!(
        !raw.starts_with(b"SQLite format 3"),
        "no plaintext SQLite header"
    );

    // Restore drill: decrypt, open through the normal bootstrap, query.
    let restored = dir.path().join("restored.sqlite");
    decrypt_file(&k, &rep.path, &restored).unwrap();
    assert_eq!(
        fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let r = SqliteDb::open(&DbConfig { path: restored }).await.unwrap();
    r.integrity_check().await.unwrap();
    let ev: String = sqlx::query_scalar("SELECT event FROM audit_log")
        .fetch_one(r.readers())
        .await
        .unwrap();
    assert_eq!(ev, "plaintext-marker-xyzzy");
}

#[tokio::test]
async fn sec_052_wrong_key_and_tampering_fail_closed_and_publish_nothing() {
    let dir = tempfile::tempdir().unwrap();
    open(&dir).await.close().await;
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let rep = backup_file_with(
        &dir.path().join("nzbd.sqlite"),
        &backups,
        10,
        14,
        Some(&key(1)),
    )
    .await
    .unwrap();

    let out = dir.path().join("out.sqlite");
    assert!(matches!(
        decrypt_file(&key(2), &rep.path, &out),
        Err(BackupCryptoError::WrongKey)
    ));
    assert!(!out.exists());

    // Flip one byte in the middle of the body.
    let mut raw = fs::read(&rep.path).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0x80;
    let bad = dir.path().join("bad.enc");
    fs::write(&bad, &raw).unwrap();
    assert!(matches!(
        decrypt_file(&key(1), &bad, &out),
        Err(BackupCryptoError::Tampered)
    ));
    assert!(!out.exists());
    // No hidden temp file left next to the target.
    assert!(fs::read_dir(dir.path()).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".decrypt.tmp")
    }));
}

#[tokio::test]
async fn sec_052_plain_and_encrypted_backups_rotate_together_and_stale_temps_are_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let k = key(3);
    // A crashed run left a plaintext snapshot temp file and an encrypted temp file behind.
    let n = crate::backup_name(50);
    fs::write(backups.join(format!(".{n}.tmp")), b"SQLite format 3 stale").unwrap();
    fs::write(backups.join(format!(".{n}{ENC_SUFFIX}.tmp")), b"stale").unwrap();
    db.backup(&backups, 100, 2).await.unwrap();
    db.backup_with(&backups, 200, 2, Some(&k)).await.unwrap();
    db.backup_with(&backups, 300, 2, Some(&k)).await.unwrap();
    let mut names: Vec<String> = fs::read_dir(&backups)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.iter().all(|n| n.ends_with(ENC_SUFFIX)), "{names:?}");
}

#[tokio::test]
async fn sec_052_an_encrypted_backup_never_overwrites_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let k = key(4);
    db.backup_with(&backups, 100, 14, Some(&k)).await.unwrap();
    assert!(db.backup_with(&backups, 100, 14, Some(&k)).await.is_err());
}

// ---------------------------------------------------------------- TOTP re-seal

async fn db_with_users(dir: &tempfile::TempDir, blobs: &[Option<&[u8]>]) -> SqliteDb {
    let db = open(dir).await;
    for (i, b) in blobs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO account (id, username, password_hash, totp_secret_enc, totp_enabled, \
             created_at, password_changed_at) VALUES (?1, ?2, 'h', ?3, ?4, 1, 1)",
        )
        .bind(i64::try_from(i).unwrap() + 1)
        .bind(format!("u{i}"))
        .bind(*b)
        .bind(i64::from(b.is_some()))
        .execute(db.writer())
        .await
        .unwrap();
    }
    db
}

async fn blobs(db: &SqliteDb) -> Vec<Option<Vec<u8>>> {
    sqlx::query_scalar("SELECT totp_secret_enc FROM account ORDER BY id")
        .fetch_all(db.readers())
        .await
        .unwrap()
}

/// Toy "crypto": a blob is `[key_tag, user_id]`; opening under `from` yields a resealed `[to, id]`.
fn toy(from: u8, to: u8) -> impl FnMut(i64, &[u8]) -> Reseal {
    move |id, blob| {
        let want = |tag: u8| blob == [tag, u8::try_from(id).unwrap()];
        if want(from) {
            Reseal::Sealed(vec![to, u8::try_from(id).unwrap()])
        } else if want(to) {
            Reseal::AlreadyCurrent
        } else {
            Reseal::Undecryptable
        }
    }
}

#[tokio::test]
async fn sec_053_reseal_changes_every_secret_and_audits_counts_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = db_with_users(&dir, &[Some(&[1, 1]), None, Some(&[1, 3])]).await;
    let rep = db.reseal_totp_secrets(500, false, toy(1, 2)).await.unwrap();
    assert_eq!(
        (rep.resealed, rep.already_current, rep.without_secret),
        (2, 0, 1)
    );
    assert_eq!(
        blobs(&db).await,
        vec![Some(vec![2, 1]), None, Some(vec![2, 3])]
    );
    let (ev, detail): (String, String) =
        sqlx::query_as("SELECT event, detail FROM audit_log WHERE event = 'totp_key_rotated'")
            .fetch_one(db.readers())
            .await
            .unwrap();
    assert_eq!(ev, "totp_key_rotated");
    assert_eq!(detail, "resealed=2 already_current=0 staging=0");
    // A re-run (crash after commit, before the key file was swapped) is a no-op.
    let again = db.reseal_totp_secrets(501, false, toy(1, 2)).await.unwrap();
    assert_eq!((again.resealed, again.already_current), (0, 2));
}

#[tokio::test]
async fn sec_053_one_undecryptable_secret_aborts_everything() {
    let dir = tempfile::tempdir().unwrap();
    let db = db_with_users(&dir, &[Some(&[1, 1]), Some(&[9, 9]), Some(&[1, 3])]).await;
    let before = blobs(&db).await;
    let err = db
        .reseal_totp_secrets(500, false, toy(1, 2))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains('2'), "names the user id: {err}");
    assert_eq!(blobs(&db).await, before, "nothing changed");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE event = 'totp_key_rotated'")
            .fetch_one(db.readers())
            .await
            .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn sec_053_dry_run_and_a_failure_midway_leave_the_database_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let db = db_with_users(&dir, &[Some(&[1, 1]), Some(&[1, 2]), Some(&[1, 3])]).await;
    let before = blobs(&db).await;
    let rep = db.reseal_totp_secrets(500, true, toy(1, 2)).await.unwrap();
    assert_eq!(rep.resealed, 3);
    assert_eq!(blobs(&db).await, before);

    // Fault injection: the UPDATE of the LAST user fails after users 1 and 2 were already updated
    // inside the transaction (the nearest thing to a crash mid-rotation). Nothing may persist.
    sqlx::query(
        "CREATE TRIGGER inject BEFORE UPDATE OF totp_secret_enc ON account WHEN NEW.id = 3 \
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .execute(db.writer())
    .await
    .unwrap();
    assert!(db.reseal_totp_secrets(500, false, toy(1, 2)).await.is_err());
    assert_eq!(blobs(&db).await, before, "rolled back as a whole");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE event = 'totp_key_rotated'")
            .fetch_one(db.readers())
            .await
            .unwrap();
    assert_eq!(n, 0);
    // Once the fault is gone the same run completes.
    sqlx::query("DROP TRIGGER inject")
        .execute(db.writer())
        .await
        .unwrap();
    db.reseal_totp_secrets(501, false, toy(1, 2)).await.unwrap();
    assert_eq!(
        blobs(&db).await,
        vec![Some(vec![2, 1]), Some(vec![2, 2]), Some(vec![2, 3])]
    );
}

#[tokio::test]
async fn sec_053_reseal_also_moves_the_secret_parked_in_credential_staging() {
    let dir = tempfile::tempdir().unwrap();
    let db = db_with_users(&dir, &[Some(&[1, 1]), Some(&[1, 2])]).await;
    sqlx::query(
        "INSERT INTO invite (purpose, token_hash, account_id, created_via, created_at, expires_at) \
         VALUES ('recover', ?1, 2, 'cli', 1, 100)",
    )
    .bind([5u8; 32].as_slice())
    .execute(db.writer())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO credential_staging (account_id, session_hash, invite_id, password_hash, \
         totp_secret_enc, created_at, expires_at) VALUES (2, ?1, 1, 'x', ?2, 1, 100)",
    )
    .bind([9u8; 32].as_slice())
    .bind([1u8, 2].as_slice())
    .execute(db.writer())
    .await
    .unwrap();
    let rep = db.reseal_totp_secrets(500, false, toy(1, 2)).await.unwrap();
    assert_eq!((rep.resealed, rep.staging_resealed), (2, 1));
    let staged: Vec<u8> = sqlx::query_scalar("SELECT totp_secret_enc FROM credential_staging")
        .fetch_one(db.readers())
        .await
        .unwrap();
    assert_eq!(staged, vec![2, 2]);
    // An undecryptable staged secret aborts the whole run like a user row does.
    sqlx::query("UPDATE credential_staging SET totp_secret_enc = x'0909'")
        .execute(db.writer())
        .await
        .unwrap();
    let before = blobs(&db).await;
    assert!(db.reseal_totp_secrets(501, false, toy(2, 3)).await.is_err());
    assert_eq!(blobs(&db).await, before);
}

#[tokio::test]
async fn sec_052_clock_rollback_keeps_latest_encrypted_backup() {
    crate::backup_tests::clock_rollback_retains_latest_backup(Some(&key(8))).await;
}

/// Capture real pre-update pages before rollback, then close the fixture cleanly. Copying them
/// into the backup directory simulates a crash leaving its plaintext copy and rollback journal.
async fn abandoned_rollback_files(dir: &std::path::Path) -> (Vec<u8>, Vec<u8>) {
    use sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };

    let path = dir.join("journal-source.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Delete)
                .synchronous(SqliteSynchronous::Full)
                .pragma("secure_delete", "ON"),
        )
        .await
        .unwrap();
    sqlx::query("CREATE TABLE credential (value TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO credential VALUES ('CANARY-PLAINTEXT-ROLLBACK-CREDENTIAL')")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM credential")
        .execute(&mut *tx)
        .await
        .unwrap();
    let journal_path = dir.join("journal-source.sqlite-journal");
    let database = fs::read(&path).unwrap();
    let journal = fs::read(&journal_path).unwrap();
    let marker = b"CANARY-PLAINTEXT-ROLLBACK-CREDENTIAL";
    assert!(journal.len() > 512, "SQLite did not write rollback pages");
    assert!(journal.windows(marker.len()).any(|page| page == marker));
    tx.rollback().await.unwrap();
    pool.close().await;
    assert!(!journal_path.exists());
    (database, journal)
}

#[tokio::test]
async fn encrypted_backup_cleans_abandoned_plaintext_rollback_journals() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir).await;
    let (database, journal) = abandoned_rollback_files(dir.path()).await;
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let name = crate::backup_name(50);
    let stale = backups.join(format!(".{name}.tmp"));
    let stale_journal = backups.join(format!(".{name}.tmp-journal"));
    fs::write(&stale, &database).unwrap();
    fs::write(&stale_journal, &journal).unwrap();
    // Cleanup must also remove an orphan whose .tmp was already deleted by a previous run.
    let orphan = backups.join(format!(".{}.tmp-journal", crate::backup_name(51)));
    fs::write(&orphan, &journal).unwrap();
    let foreign = [
        ".other.tmp-journal".to_owned(),
        format!("{name}.tmp-journal"),
        format!(".{name}{ENC_SUFFIX}.tmp-journal"),
        format!(".{name}.tmp-journal.bak"),
    ];
    for name in &foreign {
        fs::write(backups.join(name), b"foreign").unwrap();
    }
    let directory = backups.join(format!(".{}.tmp-journal", crate::backup_name(52)));
    fs::create_dir(&directory).unwrap();
    let target = dir.path().join("foreign-journal");
    fs::write(&target, b"foreign link target").unwrap();
    let symlink = backups.join(format!(".{}.tmp-journal", crate::backup_name(53)));
    std::os::unix::fs::symlink(&target, &symlink).unwrap();

    // The same directory lock protects live temporary files and their journals from cleanup.
    let lock = fs::File::open(&backups).unwrap();
    lock.try_lock().unwrap();
    let k = key(9);
    let err = db
        .backup_with(&backups, 100, 1, Some(&k))
        .await
        .unwrap_err();
    assert!(matches!(err, crate::StoreError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(fs::read(&stale_journal).unwrap(), journal);
    drop(lock);

    let rep = db.backup_with(&backups, 100, 1, Some(&k)).await.unwrap();
    assert!(looks_encrypted(&rep.path));
    assert!(!stale.exists());
    assert!(
        !stale_journal.exists() && !orphan.exists(),
        "plaintext rollback journal survived the next encrypted backup"
    );
    for name in &foreign {
        assert_eq!(fs::read(backups.join(name)).unwrap(), b"foreign");
    }
    assert!(directory.is_dir());
    assert!(
        fs::symlink_metadata(&symlink)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&target).unwrap(), b"foreign link target");
    assert_eq!(fs::read_dir(&backups).unwrap().count(), foreign.len() + 3);
    db.close().await;
}
