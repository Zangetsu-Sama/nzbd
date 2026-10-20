//! Invite redemption with the registration profile (T109, DECISIONS D32): chosen display name and email, the
//! 3-refusal bound on the login-name oracle, SEC-064 uniformity for invalid codes, email kept out of audit and
//! cleared by the tombstone.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use crate::pg::PgDb;
#[allow(unused_imports)]
use crate::pg::testing::{TEST_APP_PASSWORD, TestDb};
use crate::pg_testkit::{Env, PHC, POLICY, T0, code, env, sess};
use crate::{
    AccountActor, AccountError, AccountPolicy, GrantableRole, MAX_NAME_REFUSALS, NewInvite,
    NewRecovery, Redeemed, Redemption, RegistrationProfile, SessionStage, StoreError,
};

const IP: Option<&str> = Some("198.51.100.7");
const EMAIL: &str = "  Invitee.Private+tag@Example-Mail.ORG ";
const EMAIL_NORM: &str = "invitee.private+tag@example-mail.org";

fn err_code<T: std::fmt::Debug>(r: Result<T, StoreError>) -> &'static str {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(StoreError::Account(e)) => e.code(),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

/// admin `root`, uploader `mem` (display name `Mem_Shown`), the admin's actor.
async fn world() -> (Env, i64, AccountActor) {
    let e = env().await;
    let a = e.admin("root").await;
    let m = e.uploader("mem").await;
    e.db.set_display_name_operator(m, Some("Mem_Shown"), T0)
        .await
        .unwrap();
    let act = e.actor(a).await;
    (e, m, act)
}

async fn invite_ttl(e: &Env, act: &AccountActor, name: &str, n: u8, ttl: i64) -> i64 {
    let h = code(n).hash();
    e.db.create_invite(
        act,
        &NewInvite {
            username: name,
            role: GrantableRole::Uploader,
            code_hash: &h,
            ttl_secs: ttl,
        },
        POLICY,
        None,
        T0,
    )
    .await
    .unwrap()
}

async fn invite(e: &Env, act: &AccountActor, name: &str, n: u8) -> i64 {
    invite_ttl(e, act, name, n, 48 * 3600).await
}

async fn redeem_p(
    db: &PgDb,
    n: u8,
    sess_n: u8,
    email: &str,
    display_name: &str,
    policy: AccountPolicy,
    now: i64,
) -> Result<Redeemed, StoreError> {
    let h = code(n).hash();
    let s = sess(0, sess_n, SessionStage::PendingMfa, now);
    db.redeem_code_with_profile(
        &Redemption {
            code_hash: &h,
            password_hash: PHC,
            session: &s,
            replacing: None,
        },
        &RegistrationProfile {
            email,
            display_name,
        },
        policy,
        IP,
        now,
    )
    .await
}

async fn redeem(e: &Env, n: u8, sess_n: u8, display_name: &str) -> Result<Redeemed, StoreError> {
    redeem_p(&e.db, n, sess_n, EMAIL, display_name, POLICY, T0 + 10).await
}

async fn refusals(e: &Env, invite_id: i64) -> (i64, Option<i64>) {
    sqlx::query_as("SELECT name_refusals, revoked_at FROM invite WHERE id = $1")
        .bind(invite_id)
        .fetch_one(e.db.web())
        .await
        .unwrap()
}

/// Every text column of every audit row, concatenated per row.
async fn audit_text(db: &PgDb) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT coalesce(actor,'') || '|' || event || '|' || coalesce(detail,'') || '|' || coalesce(ip,'') \
         || '|' || coalesce(actor_kind,'') || '|' || coalesce(actor_role,'') FROM audit_log ORDER BY id",
    )
    .fetch_all(db.web())
    .await
    .unwrap()
}

#[tokio::test]
async fn sec_085_redemption_stores_chosen_name_and_normalised_email() {
    let (e, _m, act) = world().await;
    let inv = invite(&e, &act, "newbie", 1).await;
    let r = redeem(&e, 1, 1, "Newbie_Pub").await.unwrap();
    let Redeemed::Account {
        user_id, username, ..
    } = r
    else {
        panic!("{r:?}")
    };
    assert_eq!(username, "newbie");
    let row = e.db.get_account(user_id).await.unwrap().unwrap();
    assert_eq!(row.display_name.as_deref(), Some("Newbie_Pub"));
    assert_eq!(row.handle(), "Newbie_Pub");
    assert_eq!(row.email.as_deref(), Some(EMAIL_NORM));
    // The admin listing carries it; accounts created otherwise have none.
    let all = e.db.list_accounts(false).await.unwrap();
    let emails: Vec<Option<&str>> = all.iter().map(|a| a.email.as_deref()).collect();
    assert_eq!(emails, vec![None, None, Some(EMAIL_NORM)]);
    // The code is used, the counter untouched, the pending session exists.
    assert_eq!(refusals(&e, inv).await, (0, None));
    assert_eq!(e.count("invite", "used_at IS NOT NULL").await, 1);
    assert_eq!(
        e.count(
            "session",
            &format!("account_id = {user_id} AND stage = 'pending_mfa'")
        )
        .await,
        1
    );
    // `invite_redeem` keeps its detail shape: no name, no email.
    let rows = e.audit("invite_redeem").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].detail.as_deref(),
        Some(&*format!("invite={inv} role=uploader"))
    );
    assert_eq!(rows[0].target_id, Some(user_id));
    // The actor struct of a session stays without email (not needed per request).
    let actor = e.actor(user_id).await;
    assert!(!format!("{actor:?}").contains("example"));
}

#[tokio::test]
async fn sec_085_invite_revoked_after_three_unavailable_names() {
    let (e, _m, act) = world().await;
    let inv = invite(&e, &act, "newbie", 1).await;
    invite(&e, &act, "pending", 2).await;
    let users_before = e.count("account", "1=1").await;

    // 1: a live login name (NOCASE).
    let r = redeem(&e, 1, 1, "MEM").await;
    assert_eq!(err_code(r), "DISPLAY_NAME_UNAVAILABLE");
    assert_eq!(refusals(&e, inv).await, (1, None));
    // 2: a live display name (NOCASE).
    let r = redeem(&e, 1, 2, "mem_shown").await;
    assert!(matches!(
        r,
        Err(StoreError::Account(AccountError::DisplayNameUnavailable {
            invite_revoked: false
        }))
    ));
    assert_eq!(refusals(&e, inv).await, (2, None));
    // 3: the invitation's own login name: the 3rd refusal revokes the invitation.
    let r = redeem(&e, 1, 3, "NewBie").await;
    assert!(matches!(
        r,
        Err(StoreError::Account(AccountError::DisplayNameUnavailable {
            invite_revoked: true
        }))
    ));
    let (n, revoked) = refusals(&e, inv).await;
    assert_eq!((n, revoked), (MAX_NAME_REFUSALS, Some(T0 + 10)));

    // Durable: a second, independent handle on the file sees the committed counter and revocation.
    let other = e.second().await;
    let (n2, rev2): (i64, Option<i64>) =
        sqlx::query_as("SELECT name_refusals, revoked_at FROM invite WHERE id = $1")
            .bind(inv)
            .fetch_one(other.web())
            .await
            .unwrap();
    assert_eq!((n2, rev2), (3, Some(T0 + 10)));

    // A 4th try, even with a perfect name, is the uniform invalid code.
    let r = redeem_p(&other, 1, 4, EMAIL, "Fine_Name", POLICY, T0 + 11).await;
    assert_eq!(err_code(r), "INVALID_CODE");
    assert_eq!(refusals(&e, inv).await, (3, Some(T0 + 10)));

    // Nothing was created by the refusals: no account, no pending session.
    assert_eq!(e.count("account", "1=1").await, users_before);
    assert_eq!(e.count("session", "1=1").await, 0);
    // Audit: one counted row per refusal (id and count only) and one system revocation.
    let rows = e.audit("invite_name_unavailable").await;
    let details: Vec<&str> = rows.iter().filter_map(|r| r.detail.as_deref()).collect();
    assert_eq!(
        details,
        vec![
            format!("invite={inv} refusals=1"),
            format!("invite={inv} refusals=2"),
            format!("invite={inv} refusals=3"),
        ]
    );
    assert!(
        rows.iter()
            .all(|r| r.kind.as_deref() == Some("anonymous") && r.actor_id.is_none())
    );
    let rev: Vec<_> = e
        .audit("invite_revoke")
        .await
        .into_iter()
        .filter(|r| r.detail.as_deref() == Some(&*format!("invite={inv} reason=name_refusals")))
        .collect();
    assert_eq!(rev.len(), 1);
    assert_eq!(rev[0].kind.as_deref(), Some("system"));
    // The guesses themselves are recorded nowhere (the setup's own `user_display_name` row aside).
    for t in audit_text(&e.db).await {
        if t.contains("|user_display_name|") {
            continue;
        }
        let l = t.to_ascii_lowercase();
        assert!(!l.contains("mem_shown") && !l.contains("fine_name"), "{t}");
    }
    // The CHECK is the backstop for the ceiling.
    let over = sqlx::query("UPDATE invite SET name_refusals = 4 WHERE id = $1")
        .bind(inv)
        .execute(e.db.web())
        .await;
    assert!(over.is_err());
}

#[tokio::test]
async fn sec_085_open_invitation_names_are_unavailable_and_counted() {
    let (e, _m, act) = world().await;
    let inv = invite(&e, &act, "newbie", 1).await;
    let other = invite(&e, &act, "pending", 2).await;
    let r = redeem(&e, 1, 1, "PENDING").await;
    assert_eq!(err_code(r), "DISPLAY_NAME_UNAVAILABLE");
    assert_eq!(refusals(&e, inv).await, (1, None));
    // The counter is per invitation: the other one is untouched.
    assert_eq!(refusals(&e, other).await, (0, None));
    // A good name afterwards still works (1 refusal used, invitation open).
    let r = redeem(&e, 1, 2, "Newbie_Pub").await.unwrap();
    assert!(matches!(r, Redeemed::Account { .. }));
    assert_eq!(refusals(&e, inv).await, (1, None));
}

#[tokio::test]
async fn sec_064_chosen_display_name_never_equals_a_login_name() {
    let (e, _m, act) = world().await;
    invite(&e, &act, "newbie", 1).await;
    // `root` (the admin's login) is also a reserved word since `SECURITY_REVIEW` 26 L1: a free shape refusal.
    assert_eq!(
        err_code(redeem(&e, 1, 9, "ROOT").await),
        "INVALID_DISPLAY_NAME"
    );
    for (i, taken) in ["mem", "MEM", "newbie"].iter().enumerate() {
        let r = redeem(&e, 1, u8::try_from(i).unwrap() + 1, taken).await;
        if i < 2 {
            assert_eq!(err_code(r), "DISPLAY_NAME_UNAVAILABLE", "{taken}");
        } else {
            assert_eq!(
                err_code(r),
                "DISPLAY_NAME_UNAVAILABLE_INVITE_REVOKED",
                "{taken}"
            );
            break;
        }
    }
    // The other direction holds too: once a chosen name exists, it cannot become a login name.
    let (e, _m, act) = world().await;
    invite(&e, &act, "newbie", 1).await;
    redeem(&e, 1, 1, "Chosen_One").await.unwrap();
    let h = code(9).hash();
    let r =
        e.db.create_invite(
            &act,
            &NewInvite {
                username: "chosen_one",
                role: GrantableRole::Viewer,
                code_hash: &h,
                ttl_secs: 3600,
            },
            POLICY,
            None,
            T0 + 20,
        )
        .await;
    assert_eq!(err_code(r), "USERNAME_UNAVAILABLE");
    let r =
        e.db.create_account_operator(
            &crate::NewAccount {
                username: "CHOSEN_ONE",
                password_hash: PHC,
                role: Some(crate::Role::Viewer),
            },
            POLICY,
            T0 + 20,
        )
        .await;
    assert_eq!(err_code(r), "USERNAME_UNAVAILABLE");
    // No live login name equals a live display name, NOCASE.
    assert_eq!(
        e.count(
            "account a",
            "a.deleted_at IS NULL AND EXISTS (SELECT 1 FROM account b WHERE b.deleted_at IS NULL \
             AND lower(b.username) = lower(a.display_name))"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn sec_085_shape_refusals_consume_nothing() {
    let (e, _m, act) = world().await;
    let inv = invite(&e, &act, "newbie", 1).await;
    let audit_before = e.count("audit_log", "1=1").await;
    for (name, email, want) in [
        ("ab", EMAIL, "INVALID_DISPLAY_NAME"),
        ("has space", EMAIL, "INVALID_DISPLAY_NAME"),
        ("user-12", EMAIL, "INVALID_DISPLAY_NAME"),
        ("acct-3", EMAIL, "INVALID_DISPLAY_NAME"),
        ("system", EMAIL, "INVALID_DISPLAY_NAME"),
        ("bоb", EMAIL, "INVALID_DISPLAY_NAME"), // Cyrillic o
        ("Good_Name", "", "INVALID_EMAIL"),
        ("Good_Name", "a@@b.cd", "INVALID_EMAIL"),
        ("Good_Name", "a@bücher.de", "INVALID_EMAIL"),
        ("Good_Name", "a@b.cd\r\nBcc: c@d.ef", "INVALID_EMAIL"),
        // Shape is checked before availability: an invalid email never burns a refusal.
        ("mem", "nope", "INVALID_EMAIL"),
    ] {
        let r = redeem_p(&e.db, 1, 1, email, name, POLICY, T0 + 10).await;
        assert_eq!(err_code(r), want, "{name:?} {email:?}");
    }
    assert_eq!(refusals(&e, inv).await, (0, None));
    assert_eq!(e.count("invite", "used_at IS NOT NULL").await, 0);
    assert_eq!(e.count("account", "username = 'newbie'").await, 0);
    assert_eq!(e.count("session", "1=1").await, 0);
    assert_eq!(e.count("audit_log", "1=1").await, audit_before);
    // The invitation still works.
    let r = redeem(&e, 1, 2, "Good_Name").await.unwrap();
    assert!(matches!(r, Redeemed::Account { .. }));
}

#[tokio::test]
async fn sec_085_invalid_code_never_reaches_name_check() {
    let (e, _m, act) = world().await;
    // used
    let used = invite(&e, &act, "u-used", 1).await;
    redeem(&e, 1, 1, "Used_Pub").await.unwrap();
    // revoked
    let revoked = invite(&e, &act, "u-revoked", 2).await;
    e.db.revoke_invite(&act, revoked, None, T0 + 1)
        .await
        .unwrap();
    // expired (1 h ttl, redeemed after it)
    let expired = invite_ttl(&e, &act, "u-expired", 3, 3600).await;
    // valid, but redeemed with registration switched off (D28)
    let off = invite(&e, &act, "u-off", 4).await;
    let no_reg = AccountPolicy {
        registration_enabled: false,
        ..POLICY
    };
    let late = T0 + 3601;
    let before_fail = e
        .count("audit_log", "event = 'invite_redeem_failure'")
        .await;
    // Unavailable name AND invalid email: an invalid code must answer exactly INVALID_CODE regardless.
    let cases: [(u8, AccountPolicy); 5] = [
        (1, POLICY),  // used
        (2, POLICY),  // revoked
        (3, POLICY),  // expired
        (4, no_reg),  // registration off
        (99, POLICY), // unknown
    ];
    for (i, (n, pol)) in cases.iter().enumerate() {
        for (name, email) in [("mem", "x"), ("ab", "bad@@x"), ("Fine_Name", EMAIL)] {
            let s = u8::try_from(i).unwrap() * 3 + 10;
            let r = redeem_p(&e.db, *n, s, email, name, *pol, late).await;
            assert_eq!(err_code(r), "INVALID_CODE", "code {n} {name}");
        }
    }
    // The name check never ran: no counter moved, no refusal row, no revocation by refusals.
    for id in [used, revoked, expired, off] {
        let (n, _) = refusals(&e, id).await;
        assert_eq!(n, 0, "invite {id}");
    }
    assert_eq!(
        e.count("audit_log", "event = 'invite_name_unavailable'")
            .await,
        0
    );
    assert_eq!(
        e.count("audit_log", "detail LIKE '%reason=name_refusals%'")
            .await,
        0
    );
    // The failure row is the same throttled `invite_redeem_failure` as before (1/min per address).
    assert_eq!(
        e.count("audit_log", "event = 'invite_redeem_failure'")
            .await,
        before_fail + 1
    );
    // A malformed code from the web layer reaches the store as an all-zero hash: same answer.
    let zero = [0_u8; 32];
    let s = sess(0, 201, SessionStage::PendingMfa, late);
    let r =
        e.db.redeem_code_with_profile(
            &Redemption {
                code_hash: &zero,
                password_hash: PHC,
                session: &s,
                replacing: None,
            },
            &RegistrationProfile {
                email: "x",
                display_name: "mem",
            },
            POLICY,
            IP,
            late,
        )
        .await;
    assert_eq!(err_code(r), "INVALID_CODE");
}

#[tokio::test]
async fn sec_085_recovery_code_ignores_the_profile() {
    let (e, m, act) = world().await;
    let h = code(7).hash();
    e.db.issue_recovery(
        &act,
        &NewRecovery {
            target_id: m,
            code_hash: &h,
            ttl_secs: 2 * 3600,
        },
        None,
        T0,
    )
    .await
    .unwrap();
    // Empty/garbage profile fields: a recovery code does not look at them.
    let r = redeem_p(&e.db, 7, 1, "", "", POLICY, T0 + 10)
        .await
        .unwrap();
    assert!(matches!(r, Redeemed::Recovery { user_id, .. } if user_id == m));
    let row = e.db.get_account(m).await.unwrap().unwrap();
    assert_eq!(row.email, None);
    assert_eq!(row.display_name.as_deref(), Some("Mem_Shown"));
}

#[tokio::test]
async fn sec_085_email_never_in_audit_detail() {
    let (e, _m, act) = world().await;
    invite(&e, &act, "first", 1).await;
    invite(&e, &act, "second", 2).await;
    redeem(&e, 1, 1, "First_Pub").await.unwrap();
    // A refusal and shape errors with the email present.
    assert_eq!(
        err_code(redeem(&e, 2, 2, "first_pub").await),
        "DISPLAY_NAME_UNAVAILABLE"
    );
    assert_eq!(
        err_code(redeem_p(&e.db, 2, 3, "Leak.Me@Example.COM", "x", POLICY, T0 + 10).await),
        "INVALID_DISPLAY_NAME"
    );
    let r = redeem_p(
        &e.db,
        2,
        4,
        "leak.me@@example.com",
        "Second_Pub",
        POLICY,
        T0 + 10,
    )
    .await;
    // The error value carries no part of the input.
    let err = r.unwrap_err();
    for shown in [format!("{err}"), format!("{err:?}")] {
        assert!(!shown.to_ascii_lowercase().contains("leak"), "{shown}");
        assert!(!shown.contains("Second_Pub"), "{shown}");
    }
    redeem(&e, 2, 5, "Second_Pub").await.unwrap();
    for t in audit_text(&e.db).await {
        let l = t.to_ascii_lowercase();
        assert!(
            !l.contains("invitee")
                && !l.contains("example-mail")
                && !l.contains("leak")
                && !l.contains('@'),
            "{t}"
        );
    }
    // Listing rows redact the email in Debug (a stray `{:?}` in a log line cannot leak it).
    let rows = e.db.list_accounts(true).await.unwrap();
    assert_eq!(rows.iter().filter(|r| r.email.is_some()).count(), 2);
    let dbg = format!("{rows:?}");
    assert!(
        !dbg.contains("invitee") && !dbg.contains("example-mail"),
        "{dbg}"
    );
    assert!(dbg.contains("[REDACTED]"));
}

#[tokio::test]
async fn sec_085_delete_clears_email() {
    let (e, _m, act) = world().await;
    invite(&e, &act, "leaver", 1).await;
    let Redeemed::Account { user_id, .. } = redeem(&e, 1, 1, "Leaver_Pub").await.unwrap() else {
        panic!()
    };
    assert_eq!(
        e.db.get_account(user_id)
            .await
            .unwrap()
            .unwrap()
            .email
            .as_deref(),
        Some(EMAIL_NORM)
    );
    // Web path (admin) and operator path both tombstone through the same code; use the admin one here.
    e.db.disable_account(&act, user_id, None, T0 + 20)
        .await
        .unwrap();
    // Disabling alone keeps it (the account can be re-enabled).
    assert!(
        e.db.get_account(user_id)
            .await
            .unwrap()
            .unwrap()
            .email
            .is_some()
    );
    e.db.delete_account(&act, user_id, None, T0 + 21)
        .await
        .unwrap();
    let row = e.db.get_account(user_id).await.unwrap().unwrap();
    assert!(row.deleted_at.is_some());
    assert_eq!(row.email, None);
    assert_eq!(e.count("account", "email IS NOT NULL").await, 0);
    // Operator path too.
    invite(&e, &act, "leaver2", 2).await;
    let Redeemed::Account { user_id: u2, .. } = redeem(&e, 2, 2, "Leaver_Two").await.unwrap()
    else {
        panic!()
    };
    e.db.disable_account_operator(u2, T0 + 30).await.unwrap();
    e.db.delete_account_operator(u2, T0 + 31).await.unwrap();
    assert_eq!(e.db.get_account(u2).await.unwrap().unwrap().email, None);
}

#[tokio::test]
async fn sec_085_concurrent_redemptions_cannot_share_a_display_name() {
    let (e, _m, act) = world().await;
    let a = invite(&e, &act, "alpha", 1).await;
    let b = invite(&e, &act, "beta", 2).await;
    let other = e.second().await;
    let (r1, r2) = tokio::join!(
        redeem_p(&e.db, 1, 1, EMAIL, "Shared", POLICY, T0 + 10),
        redeem_p(&other, 2, 2, EMAIL, "SHARED", POLICY, T0 + 10)
    );
    assert_eq!([r1.is_ok(), r2.is_ok()].iter().filter(|b| **b).count(), 1);
    let loser = if r1.is_err() { r1 } else { r2 };
    assert_eq!(err_code(loser), "DISPLAY_NAME_UNAVAILABLE");
    let counts = [refusals(&e, a).await.0, refusals(&e, b).await.0];
    assert_eq!(counts.iter().sum::<i64>(), 1);
    assert_eq!(
        e.count("account", "lower(display_name) = 'shared'").await,
        1
    );
    // Only the winner's account (and email) exists.
    assert_eq!(
        e.count("account", &format!("email = '{EMAIL_NORM}'")).await,
        1
    );
}

#[tokio::test]
async fn sec_085_email_is_not_unique() {
    let (e, _m, act) = world().await;
    invite(&e, &act, "one", 1).await;
    invite(&e, &act, "two", 2).await;
    redeem(&e, 1, 1, "One_Pub").await.unwrap();
    redeem(&e, 2, 2, "Two_Pub").await.unwrap();
    assert_eq!(
        e.count("account", &format!("email = '{EMAIL_NORM}'")).await,
        2
    );
}

/// `SECURITY_REVIEW` 26 L2: a name whose confusable skeleton equals another live display name's is "not available" at
/// redemption (and counts as one of the 3 refusals), and the admin/operator set path refuses it as taken.
#[tokio::test]
async fn sec_085_display_name_confusable_with_another_is_unavailable() {
    let (e, m, act) = world().await;
    let inv = invite(&e, &act, "newbie", 1).await;
    // `Mem_Shown` is live: `_`/`-`, `rn`/`m` and `I`/`l` folds all collide with it.
    for (i, name) in ["Mem-Shown", "Mern_Shovvn"].iter().enumerate() {
        let s = u8::try_from(i).unwrap() + 1;
        let r = redeem(&e, 1, s, name).await;
        assert!(
            matches!(
                r,
                Err(StoreError::Account(AccountError::DisplayNameUnavailable {
                    invite_revoked: false
                }))
            ),
            "{name}: {r:?}"
        );
    }
    assert_eq!(refusals(&e, inv).await, (2, None));
    // A name that merely resembles it is fine and redeems the invitation (the counter did not burn it).
    let ok = redeem(&e, 1, 9, "Mem_Shows").await.unwrap();
    let Redeemed::Account { user_id, .. } = ok else {
        panic!("account expected")
    };
    assert_eq!(
        e.db.get_account(user_id).await.unwrap().unwrap().handle(),
        "Mem_Shows"
    );
    // The admin and operator paths apply the same skeleton rule, but never against the target's own name.
    let r =
        e.db.set_display_name(&act, user_id, Some("MEM_SH0WN"), None, T0 + 20)
            .await;
    assert_eq!(err_code(r), "DISPLAY_NAME_TAKEN");
    let r =
        e.db.set_display_name_operator(user_id, Some("rnem-shown"), T0 + 21)
            .await;
    assert_eq!(err_code(r), "DISPLAY_NAME_TAKEN");
    e.db.set_display_name_operator(m, Some("Mem-Shown"), T0 + 22)
        .await
        .unwrap();
    // The 3rd skeleton collision on a fresh invitation revokes it like any other refusal.
    let inv2 = invite(&e, &act, "third", 2).await;
    for (s, name) in [
        (20_u8, "mem_shovvn"),
        (21, "MEM-SH0WN"),
        (22, "rnern-shown"),
    ] {
        let r = redeem(&e, 2, s, name).await;
        assert!(
            matches!(
                r,
                Err(StoreError::Account(
                    AccountError::DisplayNameUnavailable { .. }
                ))
            ),
            "{name}: {r:?}"
        );
    }
    let (n, revoked) = refusals(&e, inv2).await;
    assert_eq!(n, MAX_NAME_REFUSALS);
    assert!(revoked.is_some());
}
