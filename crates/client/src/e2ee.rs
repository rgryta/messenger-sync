//! Messenger's encrypted chat: WhatsApp's protocol on Meta's own socket, logged in as the
//! adopted browser device.
//!
//! Ported from mautrix-meta (`pkg/messagix/e2ee-client.go`, `getClientPayload`) and whatsmeow's
//! Messenger mode (`client.go`). Against WhatsApp the differences are few: another URL and
//! `Origin`, the browser's user agent, and a login payload that names Messenger and carries the
//! page's crypto auth token where WhatsApp would rely on a pairing.

use prost::Message;
use whatsapp_client::baileys::Device;
use whatsapp_client::binary::Node;
use whatsapp_client::conn::{self, ConnError, Connection, Endpoint};

use crate::device::Messenger;
use crate::gateway::{BASE, USER_AGENT};

pub const URL: &str = "wss://web-chat-e2ee.facebook.com/ws/chat";

// waWa6.ClientPayload, the fields mautrix-meta sets.
const PRODUCT_MESSENGER: i32 = 1;
const PLATFORM_BLUE_WEB: i32 = 32;
const RELEASE_CHANNEL_DEBUG: i32 = 3;
const CONNECT_TYPE_WIFI_UNKNOWN: i32 = 1;
const CONNECT_REASON_USER_ACTIVATED: i32 = 1;

#[derive(Clone, PartialEq, Message)]
struct ClientPayload {
    #[prost(uint64, optional, tag = "1")]
    username: Option<u64>,
    #[prost(bool, optional, tag = "3")]
    passive: Option<bool>,
    #[prost(message, optional, tag = "5")]
    user_agent: Option<UserAgent>,
    #[prost(int32, optional, tag = "12")]
    connect_type: Option<i32>,
    #[prost(int32, optional, tag = "13")]
    connect_reason: Option<i32>,
    #[prost(uint32, optional, tag = "18")]
    device: Option<u32>,
    #[prost(int32, optional, tag = "20")]
    product: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "21")]
    fb_cat: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "22")]
    fb_user_agent: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "33")]
    pull: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct UserAgent {
    #[prost(int32, optional, tag = "1")]
    platform: Option<i32>,
    #[prost(message, optional, tag = "2")]
    app_version: Option<AppVersion>,
    #[prost(string, optional, tag = "3")]
    mcc: Option<String>,
    #[prost(string, optional, tag = "4")]
    mnc: Option<String>,
    #[prost(string, optional, tag = "5")]
    os_version: Option<String>,
    #[prost(string, optional, tag = "6")]
    manufacturer: Option<String>,
    #[prost(string, optional, tag = "7")]
    device: Option<String>,
    #[prost(string, optional, tag = "8")]
    os_build_number: Option<String>,
    #[prost(int32, optional, tag = "10")]
    release_channel: Option<i32>,
    #[prost(string, optional, tag = "11")]
    locale_language_iso6391: Option<String>,
    #[prost(string, optional, tag = "12")]
    locale_country_iso31661_alpha2: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct AppVersion {
    #[prost(uint32, optional, tag = "1")]
    primary: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    secondary: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    tertiary: Option<u32>,
}

/// The login for `fbid`'s device `device`, with the page's crypto auth token `cat`: what
/// mautrix-meta sends, field for field.
pub fn client_payload(fbid: u64, device: u32, cat: &str) -> Vec<u8> {
    ClientPayload {
        username: Some(fbid),
        passive: Some(false),
        user_agent: Some(UserAgent {
            platform: Some(PLATFORM_BLUE_WEB),
            app_version: Some(AppVersion {
                primary: Some(301),
                secondary: Some(0),
                tertiary: Some(2),
            }),
            mcc: Some("000".into()),
            mnc: Some("000".into()),
            os_version: Some(String::new()),
            manufacturer: Some("Linux".into()),
            device: Some("Chrome".into()),
            os_build_number: Some(String::new()),
            release_channel: Some(RELEASE_CHANNEL_DEBUG),
            locale_language_iso6391: Some("en".into()),
            locale_country_iso31661_alpha2: Some("en".into()),
        }),
        connect_type: Some(CONNECT_TYPE_WIFI_UNKNOWN),
        connect_reason: Some(CONNECT_REASON_USER_ACTIVATED),
        device: Some(device),
        product: Some(PRODUCT_MESSENGER),
        fb_cat: Some(cat.as_bytes().to_vec()),
        fb_user_agent: Some(USER_AGENT.as_bytes().to_vec()),
        pull: Some(true),
    }
    .encode_to_vec()
}

/// Connects and logs in. The second value is the server's first node: `<success>` when the
/// login was accepted, `<failure reason=…>` when not.
pub async fn connect(
    device: &Device,
    messenger: &Messenger,
    cat: &str,
) -> Result<(Connection, Node), ConnError> {
    let fbid = messenger
        .fbid
        .parse()
        .map_err(|_| ConnError::BadAccountId(messenger.fbid.clone()))?;
    let endpoint = Endpoint {
        url: URL,
        origin: BASE,
        user_agent: Some(USER_AGENT),
    };
    let payload = client_payload(fbid, messenger.device_id, cat);
    conn::connect_to(&endpoint, None, &device.noise, &payload).await
}
