//! The cookie jar: a Playwright export in, Meta's rotations applied, the right header out.

use chrono::{DateTime, TimeZone, Utc};
use messenger_client::cookies::Jar;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap()
}

/// A Playwright `context.cookies()` export, made-up values.
const EXPORT: &str = r#"[
 {"name":"c_user","value":"100000000000001","domain":".messenger.com","path":"/","expires":2000000000,"httpOnly":false,"secure":true,"sameSite":"None"},
 {"name":"xs","value":"12%3Aold","domain":".messenger.com","path":"/","expires":2000000000,"httpOnly":true,"secure":true,"sameSite":"None"},
 {"name":"datr","value":"d1","domain":".facebook.com","path":"/","expires":2000000000,"httpOnly":true,"secure":true,"sameSite":"None"},
 {"name":"wd","value":"1280x900","domain":".messenger.com","path":"/","expires":-1,"httpOnly":false,"secure":true,"sameSite":"Lax"},
 {"name":"old","value":"gone","domain":".messenger.com","path":"/","expires":1000,"httpOnly":false,"secure":true,"sameSite":"Lax"},
 {"name":"only","value":"here","domain":"www.messenger.com","path":"/t/","expires":-1,"httpOnly":false,"secure":true,"sameSite":"Lax"}
]"#;

#[test]
fn a_playwright_export_gives_each_host_its_own_live_cookies() {
    let jar = Jar::from_json(EXPORT).unwrap();
    assert_eq!(jar.get("c_user"), Some("100000000000001"));
    assert_eq!(
        jar.header("www.messenger.com", "/", now()),
        "c_user=100000000000001; xs=12%3Aold; wd=1280x900"
    );
    // A host-only cookie with a longer path goes first, and only where it belongs.
    assert_eq!(
        jar.header("www.messenger.com", "/t/123", now()),
        "only=here; c_user=100000000000001; xs=12%3Aold; wd=1280x900"
    );
    assert_eq!(
        jar.header("gateway.facebook.com", "/ws/lightspeed", now()),
        "datr=d1"
    );
    assert_eq!(jar.header("evilmessenger.com", "/", now()), "");
}

#[test]
fn rotations_replace_and_deletions_remove() {
    let mut jar = Jar::from_json(EXPORT).unwrap();
    // How Meta rotates xs and drops a cookie (values made up).
    jar.set(
        "xs=12%3Anew; expires=Fri, 12-Nov-2027 12:00:00 GMT; Max-Age=31536000; path=/; domain=.messenger.com; secure; httponly; SameSite=None",
        "www.messenger.com",
        now(),
    );
    jar.set(
        "wd=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=.messenger.com",
        "www.messenger.com",
        now(),
    );
    jar.set(
        "presence=EDvF; path=/; domain=.messenger.com; secure",
        "www.messenger.com",
        now(),
    );
    assert_eq!(
        jar.header("www.messenger.com", "/", now()),
        "c_user=100000000000001; xs=12%3Anew; presence=EDvF"
    );
    // A cookie without Domain is the responding host's alone.
    jar.set("hostonly=1; path=/", "www.messenger.com", now());
    assert!(
        jar.header("www.messenger.com", "/", now())
            .ends_with("hostonly=1")
    );
    assert!(
        !jar.header("m.messenger.com", "/", now())
            .contains("hostonly")
    );
    // An Expires-only deletion works too.
    jar.set(
        "presence=x; expires=Thu, 01-Jan-1970 00:00:01 GMT; domain=.messenger.com",
        "www.messenger.com",
        now(),
    );
    assert!(
        !jar.header("www.messenger.com", "/", now())
            .contains("presence")
    );
}

#[test]
fn the_saved_jar_reads_back_the_same() {
    let mut jar = Jar::from_json(EXPORT).unwrap();
    jar.set(
        "xs=rotated; Max-Age=60; domain=.messenger.com; path=/",
        "www.messenger.com",
        now(),
    );
    let back = Jar::from_json(&jar.to_json()).unwrap();
    assert_eq!(back, jar);
    assert_eq!(back.get("xs"), Some("rotated"));
}

#[test]
fn max_age_alone_decides_and_overrides_expires() {
    let mut jar = Jar::from_json(EXPORT).unwrap();
    // Max-Age=0 with no Expires is a deletion.
    jar.set(
        "xs=gone; Max-Age=0; domain=.messenger.com; path=/",
        "www.messenger.com",
        now(),
    );
    assert_eq!(jar.get("xs"), None);
    // A far Expires does not save a cookie whose Max-Age has run out.
    jar.set(
        "c_user=1; expires=Fri, 12-Nov-2027 12:00:00 GMT; Max-Age=60; domain=.messenger.com; path=/",
        "www.messenger.com",
        now(),
    );
    let later = now() + chrono::Duration::seconds(61);
    assert!(
        jar.header("www.messenger.com", "/", now())
            .contains("c_user=1")
    );
    assert!(
        !jar.header("www.messenger.com", "/", later)
            .contains("c_user")
    );
}
