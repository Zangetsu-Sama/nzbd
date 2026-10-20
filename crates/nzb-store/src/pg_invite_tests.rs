//! Invitation and recovery codes, redemption and the staged credential swap (T101a).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::used_underscore_binding
)]

use crate::pg::PgDb;
#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::pg_testkit::{Env, PHC, POLICY, T0, TEST_EMAIL, chosen_name, code, env, sess};
use crate::{
    AccountActor, AccountError, CommitRecovery, GrantableRole, InviteCode, NewInvite, NewRecovery,
    Redeemed, Redemption, RegistrationProfile, Role, SessionStage, StoreError,
};

fn err_code<T: std::fmt::Debug>(r: Result<T, StoreError>) -> &'static str {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(StoreError::Account(e)) => e.code(),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

async fn invite(
    e: &Env,
    admin: &AccountActor,
    name: &str,
    role: GrantableRole,
    n: u8,
    now: i64,
) -> i64 {
    let h = code(n).hash();
    e.db.create_invite(
        admin,
        &NewInvite {
            username: name,
            role,
            code_hash: &h,
            ttl_secs: 48 * 3600,
        },
        POLICY,
        Some("192.0.2.1"),
        now,
    )
    .await
    .unwrap()
}

async fn redeem(e: &Env, n: u8, sess_n: u8, now: i64) -> Result<Redeemed, StoreError> {
    redeem_on(&e.db, n, sess_n, now).await
}

async fn redeem_on(db: &PgDb, n: u8, sess_n: u8, now: i64) -> Result<Redeemed, StoreError> {
    redeem_on_replacing(db, n, sess_n, None, now).await
}

async fn redeem_on_replacing(
    db: &PgDb,
    n: u8,
    sess_n: u8,
    replacing: Option<&[u8; 32]>,
    now: i64,
) -> Result<Redeemed, StoreError> {
    let h = code(n).hash();
    let s = sess(0, sess_n, SessionStage::PendingMfa, now);
    let name = chosen_name(n);
    db.redeem_code_with_profile(
        &Redemption {
            code_hash: &h,
            password_hash: PHC,
            session: &s,
            replacing,
        },
        &RegistrationProfile {
            email: TEST_EMAIL,
            display_name: &name,
        },
        POLICY,
        Some("198.51.100.7"),
        now,
    )
    .await
}

/// admin A, uploader M with MFA, an old password and an old sealed secret.
async fn world() -> (Env, i64, i64, AccountActor) {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    sqlx::query(
        "UPDATE account SET password_hash = 'old-hash', totp_secret_enc = '\\x0102'::bytea, totp_enabled = true, \
         totp_last_step = 10 WHERE id = $1",
    )
    .bind(m)
    .execute(e.db.web())
    .await
    .unwrap();
    let act = e.actor(a).await;
    (e, a, m, act)
}

async fn recover(e: &Env, act: &AccountActor, target: i64, n: u8, now: i64) -> i64 {
    let h = code(n).hash();
    e.db.issue_recovery(
        act,
        &NewRecovery {
            target_id: target,
            code_hash: &h,
            ttl_secs: 2 * 3600,
        },
        None,
        now,
    )
    .await
    .unwrap()
}

async fn password_of(e: &Env, id: i64) -> String {
    sqlx::query_scalar("SELECT password_hash FROM account WHERE id = $1")
        .bind(id)
        .fetch_one(e.db.web())
        .await
        .unwrap()
}

#[tokio::test]
async fn sec_063_redemption_replaces_presented_session_for_invitation_and_recovery() {
    for recovery in [false, true] {
        let (e, _admin, member, actor) = world().await;
        for n in [40, 41] {
            e.db.insert_session(&sess(member, n, SessionStage::Active, T0), 5)
                .await
                .unwrap();
        }
        if recovery {
            recover(&e, &actor, member, 10, T0).await;
        } else {
            invite(&e, &actor, "newcomer", GrantableRole::Uploader, 10, T0).await;
        }
        let done = redeem_on_replacing(&e.db, 10, 50, Some(&[40; 32]), T0 + 1)
            .await
            .unwrap();
        let expected_user = match done {
            Redeemed::Recovery { user_id, .. } => {
                assert!(recovery);
                assert_eq!(user_id, member);
                user_id
            }
            Redeemed::Account { user_id, .. } => {
                assert!(!recovery);
                assert_ne!(user_id, member);
                user_id
            }
        };
        assert!(e.db.get_session(&[40; 32]).await.unwrap().is_none());
        assert!(e.db.get_session(&[41; 32]).await.unwrap().is_some());
        let pending = e.db.get_session(&[50; 32]).await.unwrap().unwrap();
        assert_eq!(pending.user_id, expected_user);
        assert_eq!(pending.stage, SessionStage::PendingMfa);
        assert_eq!(e.count("invite", "used_at IS NOT NULL").await, 1);
        assert_eq!(
            e.count("credential_staging", "1=1").await,
            i64::from(recovery)
        );
        if recovery {
            assert!(
                e.db.staged_swap(member, &[50; 32], T0 + 2)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(password_of(&e, member).await, "old-hash");
        }
    }
}

#[tokio::test]
async fn sec_063_rejected_redemption_preserves_presented_session() {
    let (e, _admin, member, actor) = world().await;
    e.db.insert_session(&sess(member, 40, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    assert_eq!(
        err_code(redeem_on_replacing(&e.db, 10, 50, Some(&[40; 32]), T0 + 1).await),
        "INVALID_CODE"
    );
    invite(&e, &actor, "newcomer", GrantableRole::Uploader, 10, T0).await;
    // This refusal commits its counter, but must not revoke the caller's existing session.
    e.db.set_display_name_operator(member, Some(&chosen_name(10)), T0)
        .await
        .unwrap();
    assert_eq!(
        err_code(redeem_on_replacing(&e.db, 10, 50, Some(&[40; 32]), T0 + 2).await),
        "DISPLAY_NAME_UNAVAILABLE"
    );
    assert!(e.db.get_session(&[40; 32]).await.unwrap().is_some());
    assert!(e.db.get_session(&[50; 32]).await.unwrap().is_none());
    assert_eq!(e.count("invite", "used_at IS NOT NULL").await, 0);
    assert_eq!(e.count("invite", "name_refusals = 1").await, 1);
}

#[tokio::test]
async fn sec_063_redemption_revoke_failure_rolls_back_invitation_and_recovery() {
    for recovery in [false, true] {
        let (e, _admin, member, actor) = world().await;
        e.db.insert_session(&sess(member, 40, SessionStage::Active, T0), 5)
            .await
            .unwrap();
        if recovery {
            recover(&e, &actor, member, 10, T0).await;
        } else {
            invite(&e, &actor, "newcomer", GrantableRole::Uploader, 10, T0).await;
        }
        e.superuser_exec(
            "CREATE FUNCTION nzbd.reject_session_delete() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'injected revoke failure'; END $$; \
             CREATE TRIGGER reject_session_delete BEFORE DELETE ON nzbd.session FOR EACH ROW \
             EXECUTE FUNCTION nzbd.reject_session_delete();",
        )
        .await;
        // The DELETE happens after the account/session/code/audit writes in the transaction.
        // A failure must undo every one of them, not leave a consumed invitation behind.
        let result = redeem_on_replacing(&e.db, 10, 50, Some(&[40; 32]), T0 + 1).await;
        assert!(matches!(result, Err(StoreError::Db(_))));
        assert!(e.db.get_session(&[40; 32]).await.unwrap().is_some());
        assert!(e.db.get_session(&[50; 32]).await.unwrap().is_none());
        assert_eq!(e.count("account", "1=1").await, 2);
        assert_eq!(e.count("invite", "used_at IS NOT NULL").await, 0);
        assert_eq!(e.count("credential_staging", "1=1").await, 0);
        assert_eq!(
            e.audit(if recovery {
                "recover_redeem"
            } else {
                "invite_redeem"
            })
            .await,
            Vec::new()
        );
        assert_eq!(password_of(&e, member).await, "old-hash");
        e.superuser_exec(
            "DROP TRIGGER reject_session_delete ON nzbd.session; \
             DROP FUNCTION nzbd.reject_session_delete();",
        )
        .await;
        assert!(
            redeem_on_replacing(&e.db, 10, 50, Some(&[40; 32]), T0 + 2)
                .await
                .is_ok()
        );
        assert!(e.db.get_session(&[40; 32]).await.unwrap().is_none());
        assert!(e.db.get_session(&[50; 32]).await.unwrap().is_some());
    }
}

#[test]
fn sec_063_code_canonical_form_is_strict() {
    // RFC 4648 vector: base32("12345678901234567890").
    let c = InviteCode::from_entropy(b"12345678901234567890");
    assert_eq!(
        c.grouped(),
        "GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
        "grouped display form"
    );
    assert_eq!(
        InviteCode::from_entropy(&[0; 20])
            .grouped()
            .replace('-', ""),
        "A".repeat(32)
    );
    assert_eq!(
        InviteCode::from_entropy(&[255; 20])
            .grouped()
            .replace('-', ""),
        "7".repeat(32)
    );
    let h = c.hash();
    // Accepted spellings: grouped, lower case, spaces, tabs, no separators.
    for ok in [
        "GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
        "gezd-gnbv-gy3t-qojq-gezd-gnbv-gy3t-qojq",
        "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        " GEZD\tGNBV-GY3TQOJQGEZDGNBVGY3TQOJQ ",
    ] {
        assert_eq!(InviteCode::parse(ok).unwrap().hash(), h, "{ok:?}");
    }
    // Everything else is malformed: Unicode dashes and spaces, digits outside 2-7, padding, NUL,
    // wrong length, overlong input, non-ASCII look-alikes.
    let long = "A".repeat(200);
    for bad in [
        "",
        "GEZD-GNBV",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQA",
        "GEZD\u{2010}GNBV\u{2011}GY3T\u{2012}QOJQ\u{2013}GEZD\u{2014}GNBV\u{2015}GY3T\u{2212}QOJQ",
        "GEZD\u{a0}GNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "0EZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "1EZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "8EZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ=",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ\0",
        "ÄEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        long.as_str(),
    ] {
        assert!(InviteCode::parse(bad).is_none(), "{bad:?}");
    }
    assert_eq!(format!("{c:?}"), "InviteCode([REDACTED])");
}

#[tokio::test]
async fn sec_063_code_is_stored_hashed_and_shown_once() {
    let (e, a, _m, act) = world().await;
    let c = code(77);
    let id = invite(&e, &act, "newbie", GrantableRole::Uploader, 77, T0).await;
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM invite WHERE id = $1")
        .bind(id)
        .fetch_one(e.db.web())
        .await
        .unwrap();
    assert_eq!(stored, c.hash().to_vec());
    // The canonical text appears in no invite column and in no audit row.
    let canon = c.grouped().replace('-', "");
    let dump: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce(username,'') || coalesce(role,'') || created_via FROM invite",
    )
    .fetch_all(e.db.web())
    .await
    .unwrap();
    assert!(dump.iter().all(|s| !s.contains(&canon)));
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT coalesce(detail,'') || coalesce(actor,'') FROM audit_log")
            .fetch_all(e.db.web())
            .await
            .unwrap();
    assert!(
        audit
            .iter()
            .all(|s| !s.contains(&canon) && !s.contains(&c.grouped()))
    );
    // No listing function returns the code or the hash.
    let rows = e.db.list_open_invites(T0).await.unwrap();
    assert_eq!(rows.len(), 1);
    let dbg = format!("{rows:?}");
    assert!(!dbg.contains(&canon));
    let h = c.hash();
    let s = sess(0, 1, SessionStage::PendingMfa, T0);
    let r = Redemption {
        code_hash: &h,
        password_hash: PHC,
        session: &s,
        replacing: None,
    };
    assert!(!format!("{r:?}").contains(PHC));
    let _ = a;
}

#[tokio::test]
async fn sec_063_code_is_single_use_under_concurrent_redemption() {
    let (e, _a, _m, act) = world().await;
    invite(&e, &act, "racer", GrantableRole::Viewer, 5, T0).await;
    // Two processes (two connections) present the same code at once, several rounds with fresh codes.
    let other = e.second().await;
    let (r1, r2) = tokio::join!(
        redeem_on(&e.db, 5, 1, T0 + 1),
        redeem_on(&other, 5, 2, T0 + 1)
    );
    let oks = [r1.is_ok(), r2.is_ok()];
    assert_eq!(oks.iter().filter(|b| **b).count(), 1, "exactly one wins");
    let loser = if r1.is_err() { r1 } else { r2 };
    assert_eq!(err_code(loser), "INVALID_CODE");
    assert_eq!(e.count("account", "username = 'racer'").await, 1);
    assert_eq!(e.count("invite", "used_at IS NOT NULL").await, 1);
}

#[tokio::test]
async fn sec_063_expired_revoked_used_unknown_are_indistinguishable() {
    let (e, a, _m, act) = world().await;
    let short = |name: &'static str, n: u8| {
        let db = e.db.clone();
        let act = act.clone();
        async move {
            let h = code(n).hash();
            db.create_invite(
                &act,
                &NewInvite {
                    username: name,
                    role: GrantableRole::Uploader,
                    code_hash: &h,
                    ttl_secs: 3600,
                },
                POLICY,
                None,
                T0,
            )
            .await
            .unwrap()
        }
    };
    // used
    invite(&e, &act, "u-used", GrantableRole::Uploader, 1, T0).await;
    assert!(redeem(&e, 1, 11, T0 + 1).await.is_ok());
    // revoked
    let rev = invite(&e, &act, "u-revoked", GrantableRole::Uploader, 2, T0).await;
    e.db.revoke_invite(&act, rev, None, T0 + 1).await.unwrap();
    // expired (1 h lifetime, presented after 2 h)
    short("u-expired", 3).await;
    // the issuing admin is disabled meanwhile
    let b = e.admin("second").await;
    e.mfa(a).await;
    e.mfa(b).await;
    let actor_b = e.actor(b).await;
    invite(&e, &actor_b, "u-issuer", GrantableRole::Uploader, 4, T0).await;
    e.db.disable_account_operator(b, T0 + 1).await.unwrap();
    // the name is taken meanwhile (raw insert: another creation path)
    invite(&e, &act, "u-taken", GrantableRole::Uploader, 5, T0).await;
    sqlx::query(
        "INSERT INTO account (username, password_hash, created_at, password_changed_at) \
         VALUES ('u-taken', 'h', 0, 0)",
    )
    .execute(e.db.web())
    .await
    .unwrap();

    let now = T0 + 7200;
    let before_sessions = e.count("session", "stage = 'pending_mfa'").await;
    let results = [
        redeem(&e, 1, 21, now).await,  // used
        redeem(&e, 2, 22, now).await,  // revoked
        redeem(&e, 3, 23, now).await,  // expired
        redeem(&e, 4, 24, now).await,  // issuer no longer an enabled admin
        redeem(&e, 5, 25, now).await,  // name taken
        redeem(&e, 99, 29, now).await, // unknown
    ];
    for r in &results {
        assert!(
            matches!(r, Err(StoreError::Account(AccountError::InvalidCode))),
            "{r:?}"
        );
    }
    // None of them created a session or an account; together they left the one throttled row.
    assert_eq!(
        e.count("session", "stage = 'pending_mfa'").await,
        before_sessions
    );
    assert_eq!(
        e.count(
            "account",
            "username IN ('u-expired','u-issuer','u-revoked')"
        )
        .await,
        0
    );
    let fails = e.audit("invite_redeem_failure").await;
    assert_eq!(fails.len(), 1, "throttled 1/min per address");
    assert_eq!(fails[0].kind.as_deref(), Some("anonymous"));
    assert_eq!(fails[0].detail.as_deref(), Some("invalid"));
}

#[tokio::test]
async fn sec_023_invite_redemption_yields_pending_session_only() {
    let (e, admin_id, _m, act) = world().await;
    invite(&e, &act, "newbie", GrantableRole::Viewer, 9, T0).await;
    let r = redeem(&e, 9, 5, T0 + 1).await.unwrap();
    let Redeemed::Account {
        user_id,
        username,
        role,
    } = r
    else {
        panic!("expected an account");
    };
    assert_eq!(username, "newbie");
    assert_eq!(role, Role::Viewer, "role comes from the invite row only");
    let row = e.db.get_account(user_id).await.unwrap().unwrap();
    assert!(!row.totp_enabled, "MFA is still to enroll");
    assert_eq!(row.created_by, Some(admin_id));
    assert_eq!(
        row.handle(),
        chosen_name(9),
        "the display name chosen at redemption"
    );
    let st: (String, i64) =
        sqlx::query_as("SELECT stage, enroll_proven::int::int8 FROM session WHERE account_id = $1")
            .bind(user_id)
            .fetch_one(e.db.web())
            .await
            .unwrap();
    assert_eq!(st, ("pending_mfa".to_owned(), 1));
    let loaded = e.db.get_session(&[5; 32]).await.unwrap().unwrap();
    assert!(loaded.enroll_proven);
    assert_eq!(loaded.mfa_failures, 0);
    assert_eq!(
        e.count(
            "session",
            &format!("account_id = {user_id} AND stage = 'active'")
        )
        .await,
        0
    );
    // The audit row is anonymous with the new account as target.
    let rows = e.audit("invite_redeem").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind.as_deref(), Some("anonymous"));
    assert_eq!((rows[0].actor_id, rows[0].target_id), (None, Some(user_id)));
    // A session loader sees a pending actor, never an active one.
    let actor = e.db.session_actor(&[5; 32], T0 + 2).await.unwrap().unwrap();
    assert_eq!(actor.stage, SessionStage::PendingMfa);
}

#[tokio::test]
async fn sec_061_no_invite_can_carry_the_admin_role() {
    let (e, _a, _m, act) = world().await;
    // Through the writer the stored role is always the requested one, never admin.
    let id = invite(&e, &act, "fine", GrantableRole::Uploader, 1, T0).await;
    let row = e.db.get_invite(id).await.unwrap().unwrap();
    assert_eq!(row.role, Some(Role::Uploader));
    // The type system has no admin for invitations (`GrantableRole`), and the table refuses it too.
    let err = sqlx::query(
        "INSERT INTO invite (purpose, token_hash, username, role, created_via, created_at, expires_at) \
         VALUES ('invite', $1, 'evil', 'admin', 'cli', 1, 100)",
    )
    .bind([1_u8; 32].as_slice())
    .execute(e.db.web())
    .await
    .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("check"), "{err}");
}

#[tokio::test]
async fn sec_061_role_checks_know_only_admin_uploader_viewer() {
    // D40 (migration v3/0010_roles): the CHECKs of `account.role`, `invite.role` and
    // `audit_log.actor_role` know `admin`, `uploader`, `viewer`; the former `member` is refused.
    let (e, _a, m, _act) = world().await;
    let w = e.db.web();
    let mut su = e.t.superuser_conn().await;
    for role in ["member", "Uploader", "owner"] {
        let err = sqlx::query("UPDATE account SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(m)
            .execute(w)
            .await
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "{role}: {err}"
        );
        let err = sqlx::query(
            "INSERT INTO invite (purpose, token_hash, username, role, created_via, created_at, expires_at) \
             VALUES ('invite', $1, 'someone', $2, 'cli', 1, 100)",
        )
        .bind([9_u8; 32].as_slice())
        .bind(role)
        .execute(w)
        .await
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "{role}: {err}"
        );
        // The app role cannot insert audit rows at all; the CHECK itself is probed as the superuser.
        let err = sqlx::query(
            "INSERT INTO nzbd.audit_log (ts, event, actor_kind, actor_role) VALUES (1, 'x', 'user', $1)",
        )
        .bind(role)
        .execute(&mut su)
        .await
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("check"),
            "{role}: {err}"
        );
    }
    for role in ["viewer", "uploader"] {
        sqlx::query("UPDATE account SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(m)
            .execute(w)
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO invite (purpose, token_hash, username, role, created_via, created_at, expires_at) \
         VALUES ('invite', $1, 'someone', 'uploader', 'cli', 1, 100)",
    )
    .bind([9_u8; 32].as_slice())
    .execute(w)
    .await
    .unwrap();
    assert_eq!(
        e.db.get_account(m).await.unwrap().unwrap().role,
        Role::Uploader
    );
}

#[tokio::test]
async fn sec_063_open_invite_limit() {
    let (e, _a, _m, act) = world().await;
    for i in 0..20_u8 {
        invite(
            &e,
            &act,
            &format!("guest{i}"),
            GrantableRole::Viewer,
            100 + i,
            T0,
        )
        .await;
    }
    let h = code(200).hash();
    let over =
        e.db.create_invite(
            &act,
            &NewInvite {
                username: "one-too-many",
                role: GrantableRole::Viewer,
                code_hash: &h,
                ttl_secs: 3600,
            },
            POLICY,
            None,
            T0,
        )
        .await;
    assert_eq!(err_code(over), "TOO_MANY_INVITES");
    // A duplicate name is refused as unavailable, not as a limit error.
    let h2 = code(201).hash();
    let dup =
        e.db.create_invite(
            &act,
            &NewInvite {
                username: "GUEST3",
                role: GrantableRole::Viewer,
                code_hash: &h2,
                ttl_secs: 3600,
            },
            POLICY,
            None,
            T0,
        )
        .await;
    assert!(matches!(
        dup,
        Err(StoreError::Account(
            AccountError::TooManyOpenInvites | AccountError::UsernameUnavailable
        ))
    ));
    // Revoking one frees a slot; so does expiry.
    let first = e.db.list_open_invites(T0).await.unwrap()[0].id;
    e.db.revoke_invite(&act, first, None, T0 + 1).await.unwrap();
    invite(&e, &act, "replacement", GrantableRole::Viewer, 202, T0 + 2).await;
    let later = T0 + 48 * 3600 + 10;
    invite(&e, &act, "after-expiry", GrantableRole::Viewer, 203, later).await;
    // An expired open invite no longer reserves its name.
    invite(&e, &act, "guest7", GrantableRole::Viewer, 204, later).await;
    // Disabled multi-user refuses invitations outright.
    let off = crate::AccountPolicy::default();
    let h3 = code(205).hash();
    let r =
        e.db.create_invite(
            &act,
            &NewInvite {
                username: "nope",
                role: GrantableRole::Viewer,
                code_hash: &h3,
                ttl_secs: 3600,
            },
            off,
            None,
            later,
        )
        .await;
    assert_eq!(err_code(r), "MULTI_USER_OFF");
}

#[tokio::test]
async fn sec_063_recovery_code_has_its_own_short_ttl() {
    let (e, _a, m, act) = world().await;
    let h = code(1).hash();
    for ttl in [0, 3599, 86_401, 7 * 86_400] {
        let r =
            e.db.issue_recovery(
                &act,
                &NewRecovery {
                    target_id: m,
                    code_hash: &h,
                    ttl_secs: ttl,
                },
                None,
                T0,
            )
            .await;
        assert_eq!(err_code(r), "BAD_TTL", "{ttl}");
    }
    // Invitations may live up to 7 days, but not longer.
    let r =
        e.db.create_invite(
            &act,
            &NewInvite {
                username: "slow",
                role: GrantableRole::Viewer,
                code_hash: &h,
                ttl_secs: 7 * 86_400 + 1,
            },
            POLICY,
            None,
            T0,
        )
        .await;
    assert_eq!(err_code(r), "BAD_TTL");
    let id = recover(&e, &act, m, 2, T0).await;
    let row = e.db.get_invite(id).await.unwrap().unwrap();
    assert_eq!(row.expires_at - row.created_at, 7200);
    // The table CHECK is the backstop for any other writer.
    let err = sqlx::query(
        "INSERT INTO invite (purpose, token_hash, account_id, created_via, created_at, expires_at) \
         VALUES ('recover', $1, $2, 'cli', 0, 90000)",
    )
    .bind([3_u8; 32].as_slice())
    .bind(m)
    .execute(e.db.web())
    .await
    .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("check"));
    // Redemption after the 2 h TTL is the uniform failure.
    let r = redeem(&e, 2, 8, T0 + 7201).await;
    assert_eq!(err_code(r), "INVALID_CODE");
}

#[tokio::test]
async fn sec_061_recovery_code_dies_when_target_becomes_admin() {
    let (e, a, m, act) = world().await;
    let id = recover(&e, &act, m, 3, T0).await;
    e.mfa(a).await;
    e.db.set_role_operator(m, Role::Admin, T0 + 1)
        .await
        .unwrap();
    assert_eq!(
        e.db.get_invite(id).await.unwrap().unwrap().revoked_at,
        Some(T0 + 1)
    );
    assert_eq!(err_code(redeem(&e, 3, 4, T0 + 2).await), "INVALID_CODE");
}

#[tokio::test]
async fn sec_061_recovery_redeem_rechecks_target_in_transaction() {
    // Each variant mutates the account with RAW SQL (bypassing the revocations of the writers) so only
    // the in-transaction re-check can stop the redemption.
    for (n, stmt) in [
        (
            1_u8,
            "UPDATE account SET role = 'admin' WHERE username = 'mem'",
        ),
        (
            2,
            "UPDATE account SET disabled_at = 5 WHERE username = 'mem'",
        ),
        (
            3,
            "UPDATE account SET deleted_at = 5, username = '~deleted~2' WHERE username = 'mem'",
        ),
    ] {
        let (e, _a, m, act) = world().await;
        recover(&e, &act, m, n, T0).await;
        sqlx::query(stmt).execute(e.db.web()).await.unwrap();
        assert_eq!(
            err_code(redeem(&e, n, 9, T0 + 1).await),
            "INVALID_CODE",
            "{stmt}"
        );
        assert_eq!(password_of(&e, m).await, "old-hash");
        assert_eq!(e.count("credential_staging", "1=1").await, 0);
    }
    // The issuer demoted/disabled with raw SQL: refused too.
    let (e, a, m, act) = world().await;
    let b = e.admin("other").await;
    e.mfa(a).await;
    e.mfa(b).await;
    recover(&e, &act, m, 7, T0).await;
    sqlx::query("UPDATE account SET role = 'viewer' WHERE id = $1")
        .bind(a)
        .execute(e.db.web())
        .await
        .unwrap();
    assert_eq!(err_code(redeem(&e, 7, 9, T0 + 1).await), "INVALID_CODE");
}

#[tokio::test]
async fn sec_061_admin_accounts_are_not_recoverable_over_http() {
    let (e, a, _m, act) = world().await;
    let b = e.admin("other").await;
    let h = code(1).hash();
    let r =
        e.db.issue_recovery(
            &act,
            &NewRecovery {
                target_id: b,
                code_hash: &h,
                ttl_secs: 3600,
            },
            None,
            T0,
        )
        .await;
    assert_eq!(err_code(r), "ADMIN_IS_CLI_ONLY");
    // Not even by the operator: admins are recovered with reset-password / enroll-token.
    let r =
        e.db.issue_recovery_operator(
            &NewRecovery {
                target_id: b,
                code_hash: &h,
                ttl_secs: 3600,
            },
            T0,
        )
        .await;
    assert_eq!(err_code(r), "ADMIN_IS_CLI_ONLY");
    // A hand-written recovery row for an admin is never redeemable.
    sqlx::query(
        "INSERT INTO invite (purpose, token_hash, account_id, created_via, created_at, expires_at) \
         VALUES ('recover', $1, $2, 'cli', $3, $4)",
    )
    .bind(code(2).hash().as_slice())
    .bind(b)
    .bind(T0)
    .bind(T0 + 3600)
    .execute(e.db.web())
    .await
    .unwrap();
    assert_eq!(err_code(redeem(&e, 2, 3, T0 + 1).await), "INVALID_CODE");
    let _ = a;
}

#[tokio::test]
async fn sec_027_admin_accounts_are_not_recoverable_over_http() {
    // Same property at the account layer: a web actor can neither issue nor cancel a recovery on an
    // admin, and the CLI-only path (reset-password) exists for the operator.
    let (e, _a, _m, act) = world().await;
    let b = e.admin("other").await;
    let h = code(1).hash();
    let r =
        e.db.issue_recovery(
            &act,
            &NewRecovery {
                target_id: b,
                code_hash: &h,
                ttl_secs: 3600,
            },
            None,
            T0,
        )
        .await;
    assert_eq!(err_code(r), "ADMIN_IS_CLI_ONLY");
    assert_eq!(e.count("invite", "purpose = 'recover'").await, 0);
    e.db.reset_password_for(b, "new-hash", T0 + 1)
        .await
        .unwrap();
    assert_eq!(password_of(&e, b).await, "new-hash");
}

#[tokio::test]
async fn sec_063_recovery_is_staged_until_enrollment_is_confirmed() {
    let (e, a, m, act) = world().await;
    e.db.insert_session(&sess(m, 40, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    let (_k, key_hash) = e.key(m, 41).await;
    recover(&e, &act, m, 5, T0 + 1).await;
    let r = redeem(&e, 5, 50, T0 + 2).await.unwrap();
    assert_eq!(
        r,
        Redeemed::Recovery {
            user_id: m,
            issued_by: Some(a)
        }
    );
    // Nothing about the account changed: password, TOTP, step, sessions, keys.
    assert_eq!(password_of(&e, m).await, "old-hash");
    let (enc, en, step): (Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT totp_secret_enc, totp_enabled::int::int8, totp_last_step FROM account WHERE id = $1",
    )
    .bind(m)
    .fetch_one(e.db.web())
    .await
    .unwrap();
    assert_eq!((enc, en, step), (vec![1, 2], 1, 10));
    assert_eq!(
        e.count("session", &format!("account_id = {m} AND stage = 'active'"))
            .await,
        1
    );
    assert!(
        e.db.find_api_key(&key_hash)
            .await
            .unwrap()
            .unwrap()
            .may_upload()
    );
    assert_eq!(
        e.count("credential_staging", &format!("account_id = {m}"))
            .await,
        1
    );
    let acct = e.db.get_account(m).await.unwrap().unwrap();
    assert_eq!(acct.recovery_staged_at, Some(T0 + 2));
    assert!(acct.credentials_replaced_at.is_none());
    // The enrollment page parks its sealed secret in the staged row; a reload sees the same blob.
    let pending = [50_u8; 32];
    let sealed = b"sealed-new-secret".to_vec();
    assert_eq!(
        e.db.stage_totp_secret(m, &pending, &sealed, T0 + 3)
            .await
            .unwrap(),
        Some(sealed.clone())
    );
    assert_eq!(
        e.db.stage_totp_secret(m, &pending, b"other", T0 + 4)
            .await
            .unwrap(),
        Some(sealed.clone())
    );
    // A wrong confirming session, or a different sealed blob, commits nothing.
    let new_session = sess(0, 60, SessionStage::Active, T0 + 5);
    let hashes = [[1_u8; 32], [2_u8; 32]];
    let bad_session = [51_u8; 32];
    for (sh, blob) in [
        (&bad_session, sealed.as_slice()),
        (&pending, b"nope".as_slice()),
    ] {
        let r =
            e.db.commit_staged_recovery(
                &CommitRecovery {
                    user_id: m,
                    session_hash: sh,
                    sealed: blob,
                    step: 99,
                    recovery_hashes: &hashes,
                    new_session: &new_session,
                    ip_key: Some("198.51.100.7"),
                },
                None,
                T0 + 5,
            )
            .await;
        assert_eq!(err_code(r), "STAGING_INVALID");
    }
    assert_eq!(password_of(&e, m).await, "old-hash");
    // The commit.
    e.db.commit_staged_recovery(
        &CommitRecovery {
            user_id: m,
            session_hash: &pending,
            sealed: &sealed,
            step: 99,
            recovery_hashes: &hashes,
            new_session: &new_session,
            ip_key: Some("198.51.100.7"),
        },
        Some("198.51.100.7"),
        T0 + 6,
    )
    .await
    .unwrap();
    assert_eq!(password_of(&e, m).await, PHC, "the staged hash is applied");
    let (enc, en, step, rep_at, rep_by): (Vec<u8>, i64, i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT totp_secret_enc, totp_enabled::int::int8, totp_last_step, credentials_replaced_at, \
         credentials_replaced_by FROM account WHERE id = $1",
    )
    .bind(m)
    .fetch_one(e.db.web())
    .await
    .unwrap();
    assert_eq!(
        (enc, en, step, rep_at, rep_by),
        (sealed.clone(), 1, 99, T0 + 6, Some(a))
    );
    // Every other session and key is gone, only the new active session remains.
    assert_eq!(e.count("session", &format!("account_id = {m}")).await, 1);
    assert_eq!(
        e.count(
            "session",
            &format!(
                "account_id = {m} AND stage = 'active' AND id_hash = '\\x{}'::bytea",
                "3c".repeat(32)
            )
        )
        .await,
        1
    );
    assert!(
        !e.db
            .find_api_key(&key_hash)
            .await
            .unwrap()
            .unwrap()
            .may_upload()
    );
    assert_eq!(
        e.count("recovery_code", &format!("account_id = {m}")).await,
        2
    );
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    assert_eq!(
        e.count(
            "user_known_ip",
            &format!("account_id = {m} AND ip_key = '198.51.100.7'")
        )
        .await,
        1
    );
    // Applying again is impossible (the staged row is gone).
    let r =
        e.db.commit_staged_recovery(
            &CommitRecovery {
                user_id: m,
                session_hash: &pending,
                sealed: &sealed,
                step: 100,
                recovery_hashes: &hashes,
                new_session: &new_session,
                ip_key: None,
            },
            None,
            T0 + 7,
        )
        .await;
    assert_eq!(err_code(r), "STAGING_INVALID");
    assert_eq!(e.audit("recover_apply").await.len(), 1);
}

#[tokio::test]
async fn sec_063_abandoned_recovery_leaves_account_untouched() {
    let (e, _a, m, act) = world().await;
    e.db.insert_session(&sess(m, 40, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    recover(&e, &act, m, 5, T0 + 1).await;
    redeem(&e, 5, 50, T0 + 2).await.unwrap();
    let before = e.db.get_account(m).await.unwrap().unwrap();
    // The redeemer walks away; an hour later the maintenance job removes the staged row and its
    // pending session, and the account is exactly as it was (old credentials still work).
    let rep = e.db.purge_account_state(T0 + 2 + 3601).await.unwrap();
    assert_eq!(rep.staging, 1);
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    assert!(e.db.get_session(&[50; 32]).await.unwrap().is_none());
    let after = e.db.get_account(m).await.unwrap().unwrap();
    assert!(before.recovery_staged_at.is_some());
    assert_eq!(after.recovery_staged_at, None);
    assert_eq!(password_of(&e, m).await, "old-hash");
    assert_eq!(
        e.count("session", &format!("account_id = {m} AND stage = 'active'"))
            .await,
        1
    );
    assert!(after.totp_enabled);
    // The code is spent: it cannot be replayed to stage again.
    assert_eq!(err_code(redeem(&e, 5, 51, T0 + 3).await), "INVALID_CODE");
}

#[tokio::test]
async fn sec_063_staging_dies_with_its_session() {
    let (e, _a, m, act) = world().await;
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    // Logout / revoke of the bound session.
    assert!(e.db.delete_session(&[50; 32]).await.unwrap());
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    // Expiry purge of the bound session.
    recover(&e, &act, m, 6, T0 + 2).await;
    redeem(&e, 6, 51, T0 + 3).await.unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    e.db.purge_sessions(T0 + 4 + 3600 + 1, 0).await.unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    // Cascade of the sessions of the account (revoke-sessions).
    recover(&e, &act, m, 7, T0 + 5).await;
    redeem(&e, 7, 52, T0 + 6).await.unwrap();
    e.db.revoke_account_sessions(&act, m, None, T0 + 7)
        .await
        .unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
}

#[tokio::test]
async fn sec_063_commit_requires_matching_session_and_unexpired_staging() {
    let (e, _a, m, act) = world().await;
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    let sealed = b"sealed".to_vec();
    e.db.stage_totp_secret(m, &[50; 32], &sealed, T0 + 2)
        .await
        .unwrap();
    let ns = sess(0, 61, SessionStage::Active, T0 + 3601);
    let c = CommitRecovery {
        user_id: m,
        session_hash: &[50; 32],
        sealed: &sealed,
        step: 5,
        recovery_hashes: &[],
        new_session: &ns,
        ip_key: None,
    };
    // 60 minutes after redemption the staged row no longer commits (even before the purge ran).
    let r = e.db.commit_staged_recovery(&c, None, T0 + 1 + 3600).await;
    assert_eq!(err_code(r), "STAGING_INVALID");
    // A stale hash cannot be applied over a newer password: the owner changes the password first.
    let (e, _a, m, act) = world().await;
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    e.db.stage_totp_secret(m, &[50; 32], &sealed, T0 + 2)
        .await
        .unwrap();
    e.db.insert_session(&sess(m, 70, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    e.db.change_password(
        m,
        &[70; 32],
        "owner-new",
        &sess(0, 71, SessionStage::Active, T0 + 3),
        None,
        T0 + 3,
    )
    .await
    .unwrap();
    let c = CommitRecovery {
        user_id: m,
        session_hash: &[50; 32],
        sealed: &sealed,
        step: 5,
        recovery_hashes: &[],
        new_session: &ns,
        ip_key: None,
    };
    let r = e.db.commit_staged_recovery(&c, None, T0 + 4).await;
    assert_eq!(err_code(r), "STAGING_INVALID");
    assert_eq!(password_of(&e, m).await, "owner-new");
}

#[tokio::test]
async fn sec_063_reissue_deletes_staged_swap() {
    let (e, _a, m, act) = world().await;
    let first = recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    // A second code for the same account: the previous attempt (code, staged row, its session) dies.
    // (The first code is already used, so it is the staged swap that has to go.)
    let second = recover(&e, &act, m, 6, T0 + 2).await;
    assert_ne!(first, second);
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    assert!(e.db.get_session(&[50; 32]).await.unwrap().is_none());
    // Re-issuing while one is open revokes the open one (one open code per target).
    let third = recover(&e, &act, m, 7, T0 + 3).await;
    assert_eq!(
        e.db.get_invite(second).await.unwrap().unwrap().revoked_at,
        Some(T0 + 3)
    );
    assert!(
        e.db.get_invite(third)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    assert_eq!(err_code(redeem(&e, 6, 51, T0 + 4).await), "INVALID_CODE");
}

#[tokio::test]
async fn sec_063_owner_password_change_deletes_staged_swap() {
    let (e, _a, m, act) = world().await;
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    e.db.insert_session(&sess(m, 70, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    e.db.change_password(
        m,
        &[70; 32],
        "owner-new",
        &sess(0, 71, SessionStage::Active, T0 + 2),
        None,
        T0 + 2,
    )
    .await
    .unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    // The same goes for every CLI credential command.
    for step in 0..3_u8 {
        recover(&e, &act, m, 10 + step, T0 + 10).await;
        redeem(&e, 10 + step, 60 + step, T0 + 11).await.unwrap();
        assert_eq!(e.count("credential_staging", "1=1").await, 1);
        match step {
            0 => {
                e.db.reset_password_for(m, "cli-new", T0 + 12)
                    .await
                    .unwrap();
            }
            1 => e.db.reset_mfa_for(m, T0 + 12).await.unwrap(),
            _ => {
                sqlx::query("UPDATE account SET totp_enabled = false WHERE id = $1")
                    .bind(m)
                    .execute(e.db.web())
                    .await
                    .unwrap();
                e.db.set_enrollment_token_for(m, &[8; 32], T0 + 9999, T0 + 12)
                    .await
                    .unwrap();
            }
        }
        assert_eq!(e.count("credential_staging", "1=1").await, 0, "step {step}");
        // reset-mfa / reset-password leave the account without TOTP enrolled afterwards.
        sqlx::query("UPDATE account SET totp_enabled = true, totp_secret_enc = '\\x01'::bytea WHERE id = $1")
            .bind(m)
            .execute(e.db.web())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn sec_063_staged_session_is_not_an_eviction_candidate() {
    let (e, _a, m, act) = world().await;
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    // Somebody who only knows the password logs in six times: the staged session survives and the
    // cap evicts the other pending sessions instead.
    for n in 1..=7_u8 {
        e.db.insert_session(
            &sess(m, 100 + n, SessionStage::PendingMfa, T0 + 10 + i64::from(n)),
            5,
        )
        .await
        .unwrap();
    }
    assert!(e.db.get_session(&[50; 32]).await.unwrap().is_some());
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    let pending = e
        .count(
            "session",
            &format!("account_id = {m} AND stage = 'pending_mfa'"),
        )
        .await;
    assert!(
        (5..=6).contains(&pending),
        "pending sessions stay bounded: {pending}"
    );
}

#[tokio::test]
async fn sec_063_admin_can_cancel_a_staged_recovery() {
    let (e, a, m, act) = world().await;
    assert_eq!(
        err_code(e.db.cancel_recovery(&act, m, None, T0).await),
        "INVALID_STATE",
        "nothing staged"
    );
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    // Only an admin may cancel.
    let uploader = e.actor(m).await;
    assert_eq!(
        err_code(e.db.cancel_recovery(&uploader, m, None, T0 + 2).await),
        "FORBIDDEN"
    );
    e.db.cancel_recovery(&act, m, Some("203.0.113.9"), T0 + 3)
        .await
        .unwrap();
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    assert!(
        e.db.get_session(&[50; 32]).await.unwrap().is_none(),
        "pending session dies too"
    );
    let rows = e.audit("recover_cancel").await;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].actor_id, rows[0].target_id), (Some(a), Some(m)));
    assert_eq!(password_of(&e, m).await, "old-hash");
}

#[tokio::test]
async fn sec_067_recover_redeem_names_the_issuer() {
    let (e, a, m, act) = world().await;
    recover(&e, &act, m, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    let issue = e.audit("recover_issue").await;
    assert_eq!(issue.len(), 1);
    assert_eq!((issue[0].actor_id, issue[0].target_id), (Some(a), Some(m)));
    assert_eq!(issue[0].kind.as_deref(), Some("user"));
    assert_eq!(issue[0].role.as_deref(), Some("admin"));
    let red = e.audit("recover_redeem").await;
    assert_eq!(red.len(), 1);
    assert_eq!(red[0].kind.as_deref(), Some("anonymous"));
    assert_eq!(red[0].actor_id, None);
    assert_eq!(red[0].target_id, Some(m));
    assert!(
        red[0]
            .detail
            .as_deref()
            .unwrap()
            .contains(&format!("issued_by={a}"))
    );
    // The row of a redeemed code lists the account it recovered.
    let inv = e.db.get_invite(1).await.unwrap().unwrap();
    assert_eq!(inv.used_by, Some(m));
}

#[tokio::test]
async fn sec_063_invite_and_recovery_revocation_require_current_admin_session() {
    let (e, a, m, act) = world().await;
    for n in [80, 81] {
        e.db.insert_session(&sess(a, n, SessionStage::Active, T0), 5)
            .await
            .unwrap();
    }
    let stale = AccountActor {
        session: Some([80; 32]),
        ..act.clone()
    };
    let open = invite(&e, &stale, "guest", GrantableRole::Viewer, 8, T0).await;
    recover(&e, &stale, m, 9, T0).await;
    redeem(&e, 9, 90, T0 + 1).await.unwrap();
    // Both requests authenticated before their cookie was revoked, then waited for their body.
    assert!(e.db.delete_session(&[80; 32]).await.unwrap());
    assert_eq!(
        err_code(e.db.revoke_invite(&stale, open, None, T0 + 2).await),
        "FORBIDDEN"
    );
    assert_eq!(
        err_code(e.db.cancel_recovery(&stale, m, None, T0 + 2).await),
        "FORBIDDEN"
    );
    assert!(
        e.db.get_invite(open)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    assert!(e.db.get_session(&[90; 32]).await.unwrap().is_some());
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
    assert_eq!(e.audit("invite_revoke").await.len(), 0);
    assert_eq!(e.audit("recover_cancel").await.len(), 0);

    // A current admin session retains both cancellation operations.
    let live = AccountActor {
        session: Some([81; 32]),
        ..act
    };
    e.db.revoke_invite(&live, open, None, T0 + 3).await.unwrap();
    e.db.cancel_recovery(&live, m, None, T0 + 3).await.unwrap();
    assert_eq!(
        e.db.get_invite(open).await.unwrap().unwrap().revoked_at,
        Some(T0 + 3)
    );
    assert!(e.db.get_session(&[90; 32]).await.unwrap().is_none());
    assert_eq!(e.count("credential_staging", "1=1").await, 0);
    assert_eq!(e.audit("invite_revoke").await.len(), 1);
    assert_eq!(e.audit("recover_cancel").await.len(), 1);
}

#[tokio::test]
async fn maintenance_purges_only_what_the_retention_says() {
    let (e, _a, _m, act) = world().await;
    invite(&e, &act, "old-used", GrantableRole::Viewer, 1, T0).await;
    redeem(&e, 1, 1, T0 + 1).await.unwrap();
    let revoked = invite(&e, &act, "old-revoked", GrantableRole::Viewer, 2, T0).await;
    e.db.revoke_invite(&act, revoked, None, T0 + 2)
        .await
        .unwrap();
    invite(
        &e,
        &act,
        "fresh",
        GrantableRole::Viewer,
        3,
        T0 + 10 * 86_400,
    )
    .await;
    let day = 86_400;
    // 5 days after use: nothing yet; 8 days: the used and revoked ones go, the fresh one stays.
    assert_eq!(
        e.db.purge_account_state(T0 + 5 * day)
            .await
            .unwrap()
            .invites,
        0
    );
    let rep = e.db.purge_account_state(T0 + 8 * day + 10).await.unwrap();
    assert_eq!(rep.invites, 2);
    assert_eq!(e.count("invite", "username = 'fresh'").await, 1);
    // The audit rows survive the purge.
    assert_eq!(e.audit("invite_create").await.len(), 3);
}

#[tokio::test]
async fn redemption_is_refused_while_multi_user_is_off() {
    let (e, _a, _m, act) = world().await;
    invite(&e, &act, "early", GrantableRole::Viewer, 1, T0).await;
    let h = code(1).hash();
    let s = sess(0, 1, SessionStage::PendingMfa, T0 + 1);
    let r =
        e.db.redeem_code_with_profile(
            &Redemption {
                code_hash: &h,
                password_hash: PHC,
                session: &s,
                replacing: None,
            },
            &RegistrationProfile {
                email: TEST_EMAIL,
                display_name: "Invitee_x",
            },
            crate::AccountPolicy::default(),
            None,
            T0 + 1,
        )
        .await;
    assert_eq!(err_code(r), "INVALID_CODE");
    assert_eq!(e.count("account", "username = 'early'").await, 0);
    // Startup revokes open invitations while the flag is off, so flipping it back cannot revive a code.
    assert_eq!(e.db.revoke_open_invites_system(T0 + 2).await.unwrap(), 1);
    assert_eq!(err_code(redeem(&e, 1, 2, T0 + 3).await), "INVALID_CODE");
    let rows = e.audit("invite_revoke").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind.as_deref(), Some("system"));
}

#[tokio::test]
async fn sec_068_tombstone_revokes_recovery_codes_for_target() {
    let (e, a, m, act) = world().await;
    // An open recovery code for the uploader and one open invitation issued BY the uploader's own admin
    // are written raw, as a state the writers could have left behind (the tombstone must not rely on
    // an earlier revocation having happened).
    e.db.disable_account(&act, m, None, T0).await.unwrap();
    sqlx::query(
        "INSERT INTO invite (purpose, token_hash, account_id, created_by, created_via, created_at, expires_at) \
         VALUES ('recover', $1, $2, $3, 'ui', $4, $5)",
    )
    .bind(code(1).hash().as_slice())
    .bind(m)
    .bind(a)
    .bind(T0)
    .bind(T0 + 3600)
    .execute(e.db.web())
    .await
    .unwrap();
    // The uploader also issued something itself (an old admin that was demoted keeps nothing alive).
    sqlx::query(
        "INSERT INTO invite (purpose, token_hash, username, role, created_by, created_via, created_at, expires_at) \
         VALUES ('invite', $1, 'by-uploader', 'viewer', $2, 'ui', $3, $4)",
    )
    .bind(code(2).hash().as_slice())
    .bind(m)
    .bind(T0)
    .bind(T0 + 3600)
    .execute(e.db.web())
    .await
    .unwrap();
    e.db.delete_account(&act, m, None, T0 + 1).await.unwrap();
    assert_eq!(
        e.count("invite", "revoked_at IS NULL AND used_at IS NULL")
            .await,
        0
    );
    assert_eq!(
        e.count("invite", &format!("revoked_at = {}", T0 + 1)).await,
        2
    );
    // Neither code is redeemable any more.
    assert_eq!(err_code(redeem(&e, 1, 7, T0 + 2).await), "INVALID_CODE");
    assert_eq!(err_code(redeem(&e, 2, 8, T0 + 2).await), "INVALID_CODE");
    assert_eq!(e.count("account", "username IN ('by-uploader')").await, 0);
}

#[tokio::test]
async fn sec_061_registration_disabled_store_refuses_invites_and_keeps_recovery() {
    use crate::AccountPolicy;
    let (e, _a, m, act) = world().await;
    // An invitation issued while registration was on...
    invite(&e, &act, "newbie", GrantableRole::Uploader, 1, T0).await;
    let off = AccountPolicy {
        registration_enabled: false,
        ..POLICY
    };
    // ...cannot be redeemed once it is off: the same generic failure as any unknown code.
    let h = code(1).hash();
    let s = sess(0, 1, SessionStage::PendingMfa, T0 + 1);
    let r =
        e.db.redeem_code_with_profile(
            &Redemption {
                code_hash: &h,
                password_hash: PHC,
                session: &s,
                replacing: None,
            },
            &RegistrationProfile {
                email: TEST_EMAIL,
                display_name: "Invitee_x",
            },
            off,
            None,
            T0 + 1,
        )
        .await;
    assert_eq!(err_code(r), "INVALID_CODE");
    // Creating a new one is refused with a stable code.
    let h2 = code(2).hash();
    let r =
        e.db.create_invite(
            &act,
            &NewInvite {
                username: "other",
                role: GrantableRole::Viewer,
                code_hash: &h2,
                ttl_secs: 3600,
            },
            off,
            None,
            T0 + 2,
        )
        .await;
    assert_eq!(err_code(r), "INVITES_DISABLED");
    // Recovery codes stay redeemable.
    recover(&e, &act, m, 3, T0 + 3).await;
    let h3 = code(3).hash();
    let s3 = sess(0, 3, SessionStage::PendingMfa, T0 + 4);
    let r =
        e.db.redeem_code_with_profile(
            &Redemption {
                code_hash: &h3,
                password_hash: PHC,
                session: &s3,
                replacing: None,
            },
            &RegistrationProfile {
                email: TEST_EMAIL,
                display_name: "Invitee_x",
            },
            off,
            None,
            T0 + 4,
        )
        .await
        .unwrap();
    assert!(matches!(r, Redeemed::Recovery { .. }));
    // Startup revocation closes the open invitation with its own audit reason.
    let n =
        e.db.revoke_open_invites_system_for(T0 + 5, "registration_disabled")
            .await
            .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn password_change_is_bound_to_the_reauthenticated_session() {
    let (e, _a, m, _act) = world().await;
    let before = password_of(&e, m).await;
    // The session that re-authenticated is gone (a recovery, reset or revocation committed
    // meanwhile): nothing is written and no session is minted.
    let r =
        e.db.change_password(
            m,
            &[70; 32],
            "late",
            &sess(0, 71, SessionStage::Active, T0),
            None,
            T0,
        )
        .await;
    assert!(matches!(r, Err(StoreError::NotFound)));
    assert_eq!(password_of(&e, m).await, before);
    assert!(e.db.get_session(&[71; 32]).await.unwrap().is_none());
    // With it, the change applies and the caller continues on the new session only.
    for n in [70, 72] {
        e.db.insert_session(&sess(m, n, SessionStage::Active, T0), 5)
            .await
            .unwrap();
    }
    e.db.change_password(
        m,
        &[70; 32],
        "owner-new",
        &sess(0, 71, SessionStage::Active, T0),
        None,
        T0,
    )
    .await
    .unwrap();
    assert_eq!(password_of(&e, m).await, "owner-new");
    assert!(e.db.get_session(&[70; 32]).await.unwrap().is_none());
    assert!(e.db.get_session(&[72; 32]).await.unwrap().is_none());
    assert!(e.db.get_session(&[71; 32]).await.unwrap().is_some());
}

#[tokio::test]
async fn sec_024_expired_session_cannot_change_credentials_or_admin_state() {
    let (e, a, m, act) = world().await;
    for (id, n) in [(m, 70), (a, 71)] {
        e.db.insert_session(&sess(id, n, SessionStage::Active, T0), 5)
            .await
            .unwrap();
    }
    e.db.replace_recovery_codes(m, &[70; 32], &[[7; 32]], None, T0 + 1)
        .await
        .unwrap();
    let now = T0 + 3600;
    // Expired rows have not been purged. The request's late activity touch must not revive one.
    e.db.touch_session(&[70; 32], now, now + 3600)
        .await
        .unwrap();
    let password =
        e.db.change_password(
            m,
            &[70; 32],
            "late-password",
            &sess(m, 72, SessionStage::Active, now),
            None,
            now,
        )
        .await;
    assert!(matches!(password, Err(StoreError::NotFound)));
    assert_eq!(password_of(&e, m).await, "old-hash");
    assert!(e.db.get_session(&[72; 32]).await.unwrap().is_none());
    let codes =
        e.db.replace_recovery_codes(m, &[70; 32], &[], None, now)
            .await;
    assert!(matches!(codes, Err(StoreError::NotFound)));
    assert_eq!(e.db.count_unused_recovery_codes(m).await.unwrap(), 1);
    let key =
        e.db.create_api_key_for_session(
            crate::NewApiKey {
                label: "late",
                prefix: "abcdef",
                key_hash: &[8; 32],
                rate_per_min: None,
            },
            m,
            &[70; 32],
            10,
            now,
            &crate::AuditActor::account(m, Role::Uploader, "mem"),
            None,
        )
        .await;
    assert!(matches!(key, Err(StoreError::NotFound)));
    assert_eq!(e.count("api_key", "1=1").await, 0);

    let expired_admin = AccountActor {
        session: Some([71; 32]),
        ..act
    };
    let h = code(20).hash();
    assert_eq!(
        err_code(
            e.db.create_invite(
                &expired_admin,
                &NewInvite {
                    username: "late",
                    role: GrantableRole::Viewer,
                    code_hash: &h,
                    ttl_secs: 3600,
                },
                POLICY,
                None,
                now,
            )
            .await
        ),
        "FORBIDDEN"
    );
    assert_eq!(
        err_code(
            e.db.issue_recovery(
                &expired_admin,
                &NewRecovery {
                    target_id: m,
                    code_hash: &h,
                    ttl_secs: 3600
                },
                None,
                now,
            )
            .await
        ),
        "FORBIDDEN"
    );
    assert_eq!(
        err_code(
            e.db.set_role(&expired_admin, m, GrantableRole::Viewer, None, now)
                .await
        ),
        "FORBIDDEN"
    );
    assert_eq!(e.count("invite", "1=1").await, 0);
    assert_eq!(
        e.db.get_account(m).await.unwrap().unwrap().role,
        Role::Uploader
    );
    assert!(e.db.get_session(&[70; 32]).await.unwrap().is_some());
    assert!(e.db.get_session(&[71; 32]).await.unwrap().is_some());
}

#[tokio::test]
async fn admin_credential_writers_are_bound_to_the_reauthenticated_session() {
    let (e, _a, m, act) = world().await;
    // The admin's session died after the re-authentication (a recovery, reset or revocation): no
    // invitation, no recovery code, no account action.
    let dead = AccountActor {
        session: Some([95; 32]),
        ..act.clone()
    };
    let h = code(30).hash();
    let r =
        e.db.create_invite(
            &dead,
            &NewInvite {
                username: "late",
                role: GrantableRole::Viewer,
                code_hash: &h,
                ttl_secs: 3600,
            },
            POLICY,
            None,
            T0,
        )
        .await;
    assert_eq!(err_code(r), "FORBIDDEN");
    let h = code(31).hash();
    let r =
        e.db.issue_recovery(
            &dead,
            &NewRecovery {
                target_id: m,
                code_hash: &h,
                ttl_secs: 3600,
            },
            None,
            T0,
        )
        .await;
    assert_eq!(err_code(r), "FORBIDDEN");
    assert_eq!(e.count("invite", "1=1").await, 0);
    // With the session alive, the same writer works.
    e.db.insert_session(&sess(act.user_id, 95, SessionStage::Active, T0), 5)
        .await
        .unwrap();
    recover(&e, &dead, m, 32, T0).await;
    assert_eq!(e.count("invite", "1=1").await, 1);
}

#[tokio::test]
async fn recovery_secret_access_and_commit_require_unexpired_pending_session() {
    let (e, _a, member, actor) = world().await;
    recover(&e, &actor, member, 5, T0).await;
    redeem(&e, 5, 50, T0 + 1).await.unwrap();
    let sealed = b"sealed";
    assert_eq!(
        e.db.stage_totp_secret(member, &[50; 32], sealed, T0 + 2)
            .await
            .unwrap(),
        Some(sealed.to_vec())
    );
    // Pending browser sessions can expire before the longer-lived staging record is purged.
    sqlx::query("UPDATE session SET expires_at = $1 WHERE account_id = $2")
        .bind(T0 + 3)
        .bind(member)
        .execute(e.db.web())
        .await
        .unwrap();
    assert_eq!(
        e.db.stage_totp_secret(member, &[50; 32], b"replacement", T0 + 3)
            .await
            .unwrap(),
        None
    );
    let replacement = sess(0, 61, SessionStage::Active, T0 + 3);
    let c = CommitRecovery {
        user_id: member,
        session_hash: &[50; 32],
        sealed,
        step: 99,
        recovery_hashes: &[[71; 32]],
        new_session: &replacement,
        ip_key: None,
    };
    assert_eq!(
        err_code(e.db.commit_staged_recovery(&c, None, T0 + 3).await),
        "STAGING_INVALID"
    );
    assert_eq!(password_of(&e, member).await, "old-hash");
    assert!(
        e.db.get_session(&replacement.id_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(e.count("credential_staging", "1=1").await, 1);
}
