//! T104 on the v3 Postgres store (T112, `SECURITY_REVIEW` 31 L4): sealed snapshot backups (SEC-052) and the atomic
//! TOTP re-seal (SEC-053), the 2.x `backup_enc_tests` re-proven against Postgres.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::pg::testing::TestDb;
use crate::pg::{PgDb, Readiness, RestoreOptions, restore_snapshot, snapshot_name};
use crate::{BackupKey, ENC_SUFFIX, Reseal, looks_encrypted};

fn key(b: u8) -> BackupKey {
    BackupKey::from_slice(&[b; 32]).unwrap()
}

#[tokio::test]
async fn sec_052_encrypted_backup_is_ciphertext_and_restores_with_the_key() {
    let t = TestDb::new().await;
    sqlx::query("SELECT nzbd.audit_append(1, NULL, 'download', 'plaintext-marker-xyzzy', NULL, NULL, 'system', NULL, NULL)")
        .execute(t.db.web())
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let backups = dir.path().join("backups");
    fs::create_dir(&backups).unwrap();
    let k = key(7);
    let rep =
        t.db.snapshot_backup(&backups, 1_700_000_000, 14, Some(&k))
            .await
            .unwrap();
    let name = rep.path.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(name.ends_with(&format!("Z.nzbdpg{ENC_SUFFIX}")), "{name}");
    assert_eq!(
        fs::metadata(&rep.path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(looks_encrypted(&rep.path));
    // Only the sealed file remains: the plaintext snapshot and temp files are gone.
    assert_eq!(fs::read_dir(&backups).unwrap().count(), 1);
    let raw = fs::read(&rep.path).unwrap();
    assert!(!raw.windows(22).any(|w| w == b"plaintext-marker-xyzzy"));
    assert!(
        !raw.starts_with(b"NZBDPGX1"),
        "no plaintext snapshot header"
    );
    // Restore drill.
    let target = TestDb::new().await;
    let opts = RestoreOptions {
        key: Some(&k),
        allow_unencrypted: false,
    };
    restore_snapshot(target.owner_options(), &rep.path, dir.path(), opts, 1)
        .await
        .unwrap();
    let detail: String = sqlx::query_scalar("SELECT detail FROM audit_log")
        .fetch_one(target.db.web())
        .await
        .unwrap();
    assert_eq!(detail, "plaintext-marker-xyzzy");
    // No decrypted plaintext is left in the scratch directory.
    assert!(
        fs::read_dir(dir.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("plain"))
    );
}

#[tokio::test]
async fn sec_052_wrong_key_and_tampering_fail_closed_and_publish_nothing() {
    let t = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    let rep =
        t.db.snapshot_backup(dir.path(), 10, 14, Some(&key(1)))
            .await
            .unwrap();
    let mut raw = fs::read(&rep.path).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0x80;
    let bad = dir.path().join("bad.enc");
    fs::write(&bad, &raw).unwrap();
    for (file, k) in [(&rep.path, key(2)), (&bad, key(1))] {
        let target = TestDb::new().await;
        let opts = RestoreOptions {
            key: Some(&k),
            allow_unencrypted: false,
        };
        assert!(
            restore_snapshot(target.owner_options(), file, dir.path(), opts, 1)
                .await
                .is_err()
        );
        // Nothing was loaded or marked, and no plaintext was published next to the file.
        assert_eq!(target.db.readiness().await.unwrap(), Readiness::Ready);
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(target.db.web())
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(fs::read_dir(dir.path()).unwrap().all(|e| {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            !n.contains(".decrypt.tmp") && !n.contains("plain")
        }));
    }
}

#[tokio::test]
async fn sec_052_plain_and_encrypted_backups_rotate_together_and_stale_temps_are_cleaned() {
    let t = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    let k = key(3);
    // A crashed run left a plaintext snapshot temp file and a sealed temp file behind.
    let n = snapshot_name(50);
    fs::write(dir.path().join(format!(".{n}.tmp")), b"NZBDPGX1 stale").unwrap();
    fs::write(dir.path().join(format!(".{n}{ENC_SUFFIX}.tmp")), b"stale").unwrap();
    t.db.snapshot_backup(dir.path(), 100, 2, None)
        .await
        .unwrap();
    t.db.snapshot_backup(dir.path(), 200, 2, Some(&k))
        .await
        .unwrap();
    t.db.snapshot_backup(dir.path(), 300, 2, Some(&k))
        .await
        .unwrap();
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.iter().all(|n| n.ends_with(ENC_SUFFIX)), "{names:?}");
}

#[tokio::test]
async fn sec_052_an_encrypted_backup_never_overwrites_an_existing_file() {
    let t = TestDb::new().await;
    let dir = tempfile::tempdir().unwrap();
    let k = key(4);
    t.db.snapshot_backup(dir.path(), 100, 14, Some(&k))
        .await
        .unwrap();
    assert!(
        t.db.snapshot_backup(dir.path(), 100, 14, Some(&k))
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------- TOTP re-seal

async fn db_with_users(blobs: &[Option<&[u8]>]) -> (TestDb, PgDb) {
    let t = TestDb::new().await;
    for (i, b) in blobs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO account (id, username, password_hash, totp_secret_enc, totp_enabled, created_at, \
             password_changed_at) VALUES ($1, $2, 'h', $3, $4, 1, 1)",
        )
        .bind(i64::try_from(i).unwrap() + 1)
        .bind(format!("u{i}"))
        .bind(*b)
        .bind(b.is_some())
        .execute(t.db.web())
        .await
        .unwrap();
    }
    let db = t.db.clone();
    (t, db)
}

async fn blobs(db: &PgDb) -> Vec<Option<Vec<u8>>> {
    sqlx::query_scalar("SELECT totp_secret_enc FROM account ORDER BY id")
        .fetch_all(db.web())
        .await
        .unwrap()
}

async fn rotations(db: &PgDb) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE event = 'totp_key_rotated'")
        .fetch_one(db.web())
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
    let (_t, db) = db_with_users(&[Some(&[1, 1]), None, Some(&[1, 3])]).await;
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
            .fetch_one(db.web())
            .await
            .unwrap();
    assert_eq!(ev, "totp_key_rotated");
    assert_eq!(detail, "resealed=2 already_current=0 staging=0");
    let again = db.reseal_totp_secrets(501, false, toy(1, 2)).await.unwrap();
    assert_eq!((again.resealed, again.already_current), (0, 2));
}

#[tokio::test]
async fn sec_053_one_undecryptable_secret_aborts_everything() {
    let (_t, db) = db_with_users(&[Some(&[1, 1]), Some(&[9, 9]), Some(&[1, 3])]).await;
    let before = blobs(&db).await;
    let err = db
        .reseal_totp_secrets(500, false, toy(1, 2))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains('2'), "names the user id: {err}");
    assert_eq!(blobs(&db).await, before, "nothing changed");
    assert_eq!(rotations(&db).await, 0);
}

#[tokio::test]
async fn sec_053_dry_run_and_a_failure_midway_leave_the_database_untouched() {
    let (t, db) = db_with_users(&[Some(&[1, 1]), Some(&[1, 2]), Some(&[1, 3])]).await;
    let before = blobs(&db).await;
    let rep = db.reseal_totp_secrets(500, true, toy(1, 2)).await.unwrap();
    assert_eq!(rep.resealed, 3);
    assert_eq!(blobs(&db).await, before);
    // Fault injection: the UPDATE of the LAST account fails after the first two were updated inside the transaction.
    let mut su = t.superuser_conn().await;
    sqlx::raw_sql(
        "CREATE FUNCTION nzbd.inject() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'injected'; END $$; \
         CREATE TRIGGER inject BEFORE UPDATE OF totp_secret_enc ON nzbd.account FOR EACH ROW \
         WHEN (NEW.id = 3) EXECUTE FUNCTION nzbd.inject();",
    )
    .execute(&mut su)
    .await
    .unwrap();
    assert!(db.reseal_totp_secrets(500, false, toy(1, 2)).await.is_err());
    assert_eq!(blobs(&db).await, before, "rolled back as a whole");
    assert_eq!(rotations(&db).await, 0);
    sqlx::raw_sql("DROP TRIGGER inject ON nzbd.account")
        .execute(&mut su)
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
    let (_t, db) = db_with_users(&[Some(&[1, 1]), Some(&[1, 2])]).await;
    let invite: i64 = sqlx::query_scalar(
        "INSERT INTO invite (purpose, token_hash, account_id, created_via, created_at, expires_at) \
         VALUES ('recover', $1, 2, 'cli', 1, 100) RETURNING id",
    )
    .bind([5u8; 32].as_slice())
    .fetch_one(db.web())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO credential_staging (account_id, session_hash, invite_id, password_hash, totp_secret_enc, \
         created_at, expires_at) VALUES (2, $1, $2, 'x', $3, 1, 100)",
    )
    .bind([9u8; 32].as_slice())
    .bind(invite)
    .bind([1u8, 2].as_slice())
    .execute(db.web())
    .await
    .unwrap();
    let rep = db.reseal_totp_secrets(500, false, toy(1, 2)).await.unwrap();
    assert_eq!((rep.resealed, rep.staging_resealed), (2, 1));
    let staged: Vec<u8> = sqlx::query_scalar("SELECT totp_secret_enc FROM credential_staging")
        .fetch_one(db.web())
        .await
        .unwrap();
    assert_eq!(staged, vec![2, 2]);
    sqlx::query("UPDATE credential_staging SET totp_secret_enc = '\\x0909'::bytea")
        .execute(db.web())
        .await
        .unwrap();
    let before = blobs(&db).await;
    assert!(db.reseal_totp_secrets(501, false, toy(2, 3)).await.is_err());
    assert_eq!(blobs(&db).await, before);
}

#[tokio::test]
async fn sec_052_clock_rollback_keeps_latest_encrypted_backup() {
    crate::pg_backup_tests::clock_rollback_retains_latest_backup(Some(&key(8))).await;
}
