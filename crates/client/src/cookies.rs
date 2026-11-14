//! The login: Messenger's cookies, kept and rotated by this client.
//!
//! It starts from a browser session exported once in Playwright's `context.cookies()` shape
//! (at cutover, from the retired harvester's Chromium profile), so the browser decrypts its
//! own store and nothing here has to. From then on Meta rotates `xs` and friends through
//! `Set-Cookie`, and the jar must keep what it is given: a session that stops taking
//! rotations is logged out.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Playwright's cookie shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// A leading dot means the domain and its subdomains; none means that host only.
    pub domain: String,
    #[serde(default = "root")]
    pub path: String,
    /// Seconds since the epoch; -1 (or absent) for a session cookie.
    #[serde(default = "session")]
    pub expires: f64,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
}

fn root() -> String {
    "/".to_owned()
}

fn session() -> f64 {
    -1.0
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Jar {
    cookies: Vec<Cookie>,
}

impl Jar {
    /// A Playwright export, or this jar's own saved form: the same JSON array.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("cookies serialize")
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.value.as_str())
    }

    /// The `Cookie` header for a request to `host` at `now`: every live cookie that matches,
    /// longest path first as browsers send them.
    pub fn header(&self, host: &str, path: &str, now: DateTime<Utc>) -> String {
        let mut matching: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                domain_matches(&c.domain, host) && path.starts_with(&c.path) && !expired(c, now)
            })
            .collect();
        matching.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        matching
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// One `Set-Cookie` header from a response to `host`. A cookie that arrives already
    /// expired (`Max-Age=0`, a past `Expires`, Meta's `deleted`) is removed.
    pub fn set(&mut self, header: &str, host: &str, now: DateTime<Utc>) {
        let mut parts = header.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else {
            return;
        };
        let mut cookie = Cookie {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
            domain: host.to_owned(),
            path: root(),
            expires: session(),
            secure: false,
            http_only: false,
        };
        let mut max_age = None;
        for attribute in parts {
            let (key, value) = attribute.split_once('=').unwrap_or((attribute, ""));
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "domain" if !value.is_empty() => {
                    cookie.domain = format!(".{}", value.trim_start_matches('.'));
                }
                "path" if value.starts_with('/') => cookie.path = value.to_owned(),
                "max-age" => max_age = value.parse::<i64>().ok(),
                "expires" => {
                    if let Ok(when) = DateTime::parse_from_rfc2822(&value.replace('-', " ")) {
                        cookie.expires = when.timestamp() as f64;
                    }
                }
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                _ => {}
            }
        }
        // Max-Age wins over Expires (RFC 6265 5.3).
        if let Some(seconds) = max_age {
            cookie.expires = (now.timestamp() + seconds) as f64;
        }
        self.cookies.retain(|c| {
            !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
        });
        if !expired(&cookie, now) {
            self.cookies.push(cookie);
        }
    }
}

fn domain_matches(domain: &str, host: &str) -> bool {
    match domain.strip_prefix('.') {
        Some(base) => host == base || host.ends_with(&format!(".{base}")),
        None => host == domain,
    }
}

fn expired(c: &Cookie, now: DateTime<Utc>) -> bool {
    c.expires >= 0.0 && c.expires <= now.timestamp() as f64
}
