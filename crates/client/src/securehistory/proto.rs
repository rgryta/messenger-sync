//! The protobufs an archived message is made of, from whatsmeow's
//! `waArmadilloBackupMessage`, `waArmadilloBackupCommon`, `waMsgApplication`,
//! `waConsumerApplication`, `waMediaTransport`, `waArmadilloApplication` and `waArmadilloXMA`,
//! with only the fields read or written here.
//!
//! Echo documents are rebuilt into these messages, and the result must be the bytes Go
//! writes: Go writes fields in field-number order, as prost does, and a oneof is declared as
//! its separate optional fields (as in [`crate::armadillo`]), which reads and writes the same
//! bytes when one is set.

use prost::Message;

/// A message that carries nothing read here: only whether it is there.
#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

/// `waCommon.SubProtocol` and `waArmadilloBackupCommon.Subprotocol`: versioned bytes.
#[derive(Clone, PartialEq, Message)]
pub struct SubProtocol {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub payload: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    pub version: Option<i32>,
}

impl SubProtocol {
    /// What armadilloutil's `Marshal` makes of a message at `version`.
    pub fn of(message: &impl Message, version: i32) -> Self {
        Self {
            payload: Some(message.encode_to_vec()),
            version: Some(version),
        }
    }

    /// armadilloutil's `Unmarshal`: the payload, if the version is the one expected.
    pub fn decode<M: Message + Default>(
        &self,
        version: i32,
    ) -> Option<Result<M, prost::DecodeError>> {
        (self.version.unwrap_or(0) == version)
            .then(|| M::decode(self.payload.as_deref().unwrap_or_default()))
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct FrankingMetadata {
    #[prost(bytes = "vec", optional, tag = "3")]
    pub franking_tag: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub reporting_tag: Option<Vec<u8>>,
}

/// `waArmadilloBackupCommon.Metadata`, in full, so a decrypted message encodes back as it came.
#[derive(Clone, PartialEq, Message)]
pub struct Metadata {
    #[prost(string, optional, tag = "1")]
    pub sender_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub message_id: Option<String>,
    #[prost(int64, optional, tag = "3")]
    pub timestamp_ms: Option<i64>,
    #[prost(message, optional, tag = "4")]
    pub franking_metadata: Option<FrankingMetadata>,
    #[prost(int32, optional, tag = "5")]
    pub payload_version: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    pub future_proof_behavior: Option<i32>,
    #[prost(int32, optional, tag = "7")]
    pub thread_type_tag: Option<i32>,
    #[prost(int64, optional, tag = "8")]
    pub client_timestamp_ms: Option<i64>,
}

/// What an archived message decrypts to.
#[derive(Clone, PartialEq, Message)]
pub struct BackupMessage {
    #[prost(message, optional, tag = "1")]
    pub metadata: Option<Metadata>,
    #[prost(oneof = "BackupPayload", tags = "2, 5, 6, 7")]
    pub payload: Option<BackupPayload>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum BackupPayload {
    /// A `MessageApplication`, unversioned.
    #[prost(bytes, tag = "2")]
    EncryptedTransportMessage(Vec<u8>),
    #[prost(message, tag = "5")]
    EncryptedTransportEvent(SubProtocol),
    #[prost(message, tag = "6")]
    EncryptedTransportLocallyTransformedMessage(SubProtocol),
    #[prost(message, tag = "7")]
    MiTransportAdminMessage(SubProtocol),
}

impl BackupMessage {
    /// The metadata's sender, or `""`, as Go's getters read it.
    pub fn sender_id(&self) -> &str {
        self.metadata
            .as_ref()
            .and_then(|m| m.sender_id.as_deref())
            .unwrap_or_default()
    }

    /// The metadata's message id, or `""`.
    pub fn message_id(&self) -> &str {
        self.metadata
            .as_ref()
            .and_then(|m| m.message_id.as_deref())
            .unwrap_or_default()
    }

    /// The metadata's timestamp, when it has one.
    pub fn timestamp_ms(&self) -> Option<i64> {
        self.metadata.as_ref().and_then(|m| m.timestamp_ms)
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct MessageApplication {
    #[prost(message, optional, tag = "1")]
    pub payload: Option<ApplicationPayload>,
    #[prost(message, optional, tag = "2")]
    pub metadata: Option<ApplicationMetadata>,
}

/// `MessageApplication.Payload`'s oneof `content`.
#[derive(Clone, PartialEq, Message)]
pub struct ApplicationPayload {
    #[prost(message, optional, tag = "1")]
    pub core_content: Option<Empty>,
    #[prost(message, optional, tag = "2")]
    pub signal: Option<Empty>,
    #[prost(message, optional, tag = "3")]
    pub application_data: Option<Empty>,
    #[prost(message, optional, tag = "4")]
    pub sub_protocol: Option<SubProtocolPayload>,
}

/// `MessageApplication.SubProtocolPayload`'s oneof `subProtocol`.
#[derive(Clone, PartialEq, Message)]
pub struct SubProtocolPayload {
    #[prost(message, optional, tag = "2")]
    pub consumer_message: Option<SubProtocol>,
    #[prost(message, optional, tag = "3")]
    pub business_message: Option<SubProtocol>,
    #[prost(message, optional, tag = "4")]
    pub payment_message: Option<SubProtocol>,
    #[prost(message, optional, tag = "5")]
    pub multi_device: Option<SubProtocol>,
    #[prost(message, optional, tag = "6")]
    pub voip: Option<SubProtocol>,
    #[prost(message, optional, tag = "7")]
    pub armadillo: Option<SubProtocol>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ApplicationMetadata {
    #[prost(bool, optional, tag = "6")]
    pub is_forwarded: Option<bool>,
    #[prost(message, optional, tag = "10")]
    pub quoted_message: Option<QuotedMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct QuotedMessage {
    #[prost(string, optional, tag = "1")]
    pub stanza_id: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub participant: Option<String>,
}

/// `MessageApplication`'s sub-protocol versions (`waMsgApplication`'s `*ApplicationVersion`).
pub const CONSUMER_APPLICATION_VERSION: i32 = 1;
pub const ARMADILLO_APPLICATION_VERSION: i32 = 1;
pub const MULTI_DEVICE_APPLICATION_VERSION: i32 = 1;
/// Every `waMediaTransport` transport is at version 1 (`waConsumerApplication`'s constants).
pub const MEDIA_TRANSPORT_VERSION: i32 = 1;

#[derive(Clone, PartialEq, Message)]
pub struct ConsumerApplication {
    #[prost(message, optional, tag = "1")]
    pub payload: Option<ConsumerPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConsumerPayload {
    #[prost(message, optional, tag = "1")]
    pub content: Option<ConsumerContent>,
}

/// `ConsumerApplication.Content`'s oneof `content`.
#[derive(Clone, PartialEq, Message)]
pub struct ConsumerContent {
    #[prost(message, optional, tag = "1")]
    pub message_text: Option<MessageText>,
    #[prost(message, optional, tag = "2")]
    pub image_message: Option<CaptionedMedia>,
    #[prost(message, optional, tag = "7")]
    pub document_message: Option<DocumentMessage>,
    #[prost(message, optional, tag = "8")]
    pub audio_message: Option<AudioMessage>,
    #[prost(message, optional, tag = "9")]
    pub video_message: Option<CaptionedMedia>,
    #[prost(message, optional, tag = "12")]
    pub sticker_message: Option<StickerMessage>,
    #[prost(message, optional, tag = "16")]
    pub reaction_message: Option<ReactionMessage>,
    #[prost(message, optional, tag = "17")]
    pub poll_creation_message: Option<Empty>,
    #[prost(message, optional, tag = "18")]
    pub poll_update_message: Option<Empty>,
    #[prost(message, optional, tag = "19")]
    pub edit_message: Option<EditMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct MessageText {
    #[prost(string, optional, tag = "1")]
    pub text: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct MessageKey {
    #[prost(string, optional, tag = "3")]
    pub id: Option<String>,
}

/// `ImageMessage` and `VideoMessage`: the transport, then a caption.
#[derive(Clone, PartialEq, Message)]
pub struct CaptionedMedia {
    #[prost(message, optional, tag = "1")]
    pub media: Option<SubProtocol>,
    #[prost(message, optional, tag = "2")]
    pub caption: Option<MessageText>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AudioMessage {
    #[prost(message, optional, tag = "1")]
    pub audio: Option<SubProtocol>,
    #[prost(bool, optional, tag = "2")]
    pub ptt: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DocumentMessage {
    #[prost(message, optional, tag = "1")]
    pub document: Option<SubProtocol>,
    #[prost(string, optional, tag = "2")]
    pub file_name: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StickerMessage {
    #[prost(message, optional, tag = "1")]
    pub sticker: Option<SubProtocol>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ReactionMessage {
    #[prost(message, optional, tag = "1")]
    pub key: Option<MessageKey>,
    #[prost(string, optional, tag = "2")]
    pub text: Option<String>,
    #[prost(int64, optional, tag = "4")]
    pub sender_timestamp_ms: Option<i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EditMessage {
    #[prost(message, optional, tag = "1")]
    pub key: Option<MessageKey>,
    #[prost(message, optional, tag = "2")]
    pub message: Option<MessageText>,
    #[prost(int64, optional, tag = "3")]
    pub timestamp_ms: Option<i64>,
}

/// `waMediaTransport.WAMediaTransport`: where an encrypted file is and how to open it.
#[derive(Clone, PartialEq, Message)]
pub struct WaMediaTransport {
    #[prost(message, optional, tag = "1")]
    pub integral: Option<WaMediaIntegral>,
    #[prost(message, optional, tag = "2")]
    pub ancillary: Option<WaMediaAncillary>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WaMediaIntegral {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub file_sha256: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub media_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub file_enc_sha256: Option<Vec<u8>>,
    #[prost(string, optional, tag = "4")]
    pub direct_path: Option<String>,
    #[prost(int64, optional, tag = "5")]
    pub media_key_timestamp: Option<i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WaMediaAncillary {
    #[prost(uint64, optional, tag = "1")]
    pub file_length: Option<u64>,
    #[prost(string, optional, tag = "2")]
    pub mimetype: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub object_id: Option<String>,
}

/// Every `*Transport`'s integral part: the `WAMediaTransport`.
#[derive(Clone, PartialEq, Message)]
pub struct TransportIntegral {
    #[prost(message, optional, tag = "1")]
    pub transport: Option<WaMediaTransport>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ImageTransport {
    #[prost(message, optional, tag = "1")]
    pub integral: Option<TransportIntegral>,
    #[prost(message, optional, tag = "2")]
    pub ancillary: Option<ImageAncillary>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ImageAncillary {
    #[prost(uint32, optional, tag = "1")]
    pub height: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub width: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct VideoTransport {
    #[prost(message, optional, tag = "1")]
    pub integral: Option<TransportIntegral>,
    #[prost(message, optional, tag = "2")]
    pub ancillary: Option<VideoAncillary>,
}

#[derive(Clone, PartialEq, Message)]
pub struct VideoAncillary {
    #[prost(uint32, optional, tag = "1")]
    pub seconds: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub height: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    pub width: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AudioTransport {
    #[prost(message, optional, tag = "1")]
    pub integral: Option<TransportIntegral>,
    #[prost(message, optional, tag = "2")]
    pub ancillary: Option<AudioAncillary>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AudioAncillary {
    #[prost(uint32, optional, tag = "1")]
    pub seconds: Option<u32>,
}

/// `DocumentTransport`, whose ancillary part is written empty.
#[derive(Clone, PartialEq, Message)]
pub struct DocumentTransport {
    #[prost(message, optional, tag = "1")]
    pub integral: Option<TransportIntegral>,
    #[prost(message, optional, tag = "2")]
    pub ancillary: Option<Empty>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StickerTransport {
    #[prost(message, optional, tag = "1")]
    pub integral: Option<TransportIntegral>,
    #[prost(message, optional, tag = "2")]
    pub ancillary: Option<StickerAncillary>,
}

#[derive(Clone, PartialEq, Message)]
pub struct StickerAncillary {
    #[prost(uint32, optional, tag = "2")]
    pub height: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub width: Option<u32>,
}

/// `waArmadilloApplication.Armadillo`.
#[derive(Clone, PartialEq, Message)]
pub struct Armadillo {
    #[prost(message, optional, tag = "1")]
    pub payload: Option<ArmadilloPayload>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ArmadilloPayload {
    #[prost(message, optional, tag = "1")]
    pub content: Option<ArmadilloContent>,
}

/// `Armadillo.Content`'s oneof `content`.
#[derive(Clone, PartialEq, Message)]
pub struct ArmadilloContent {
    #[prost(message, optional, tag = "4")]
    pub extended_content_message: Option<ExtendedContentMessage>,
    #[prost(message, optional, tag = "6")]
    pub raven_action_notif_message: Option<Empty>,
}

/// `waArmadilloXMA.ExtendedContentMessage`: a link, share or call card ("XMA").
#[derive(Clone, PartialEq, Message)]
pub struct ExtendedContentMessage {
    #[prost(int32, optional, tag = "2")]
    pub target_type: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub target_username: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub target_id: Option<String>,
    #[prost(int64, optional, tag = "5")]
    pub target_expiring_at_sec: Option<i64>,
    #[prost(int32, optional, tag = "6")]
    pub xma_layout_type: Option<i32>,
    #[prost(message, repeated, tag = "7")]
    pub ctas: Vec<Cta>,
    #[prost(message, repeated, tag = "8")]
    pub previews: Vec<SubProtocol>,
    #[prost(string, optional, tag = "9")]
    pub title_text: Option<String>,
    #[prost(string, optional, tag = "10")]
    pub subtitle_text: Option<String>,
    #[prost(string, optional, tag = "15")]
    pub header_title: Option<String>,
    #[prost(int32, optional, tag = "16")]
    pub overlay_icon_glyph: Option<i32>,
    #[prost(string, optional, tag = "20")]
    pub message_text: Option<String>,
    #[prost(string, optional, tag = "21")]
    pub header_subtitle: Option<String>,
    #[prost(string, optional, tag = "22")]
    pub xma_dataclass: Option<String>,
    #[prost(string, optional, tag = "23")]
    pub content_ref: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Cta {
    #[prost(int32, optional, tag = "1")]
    pub button_type: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub action_url: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub native_url: Option<String>,
}

/// `ExtendedContentMessage.CtaButtonType.OPEN_NATIVE`.
pub const CTA_OPEN_NATIVE: i32 = 11;

/// The number an enum table gives a name, as Go's generated `_value` maps do.
pub fn enum_value(table: &[(&str, i32)], name: &str) -> Option<i32> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// `ExtendedContentMessage.ExtendedContentType` by name, as Echo documents name it.
pub const EXTENDED_CONTENT_TYPES: &[(&str, i32)] = &[
    ("UNSUPPORTED", 0),
    ("IG_STORY_PHOTO_MENTION", 4),
    ("IG_SINGLE_IMAGE_POST_SHARE", 9),
    ("IG_MULTIPOST_SHARE", 10),
    ("IG_SINGLE_VIDEO_POST_SHARE", 11),
    ("IG_STORY_PHOTO_SHARE", 12),
    ("IG_STORY_VIDEO_SHARE", 13),
    ("IG_CLIPS_SHARE", 14),
    ("IG_IGTV_SHARE", 15),
    ("IG_SHOP_SHARE", 16),
    ("IG_PROFILE_SHARE", 19),
    ("IG_STORY_PHOTO_HIGHLIGHT_SHARE", 20),
    ("IG_STORY_VIDEO_HIGHLIGHT_SHARE", 21),
    ("IG_STORY_REPLY", 22),
    ("IG_STORY_REACTION", 23),
    ("IG_STORY_VIDEO_MENTION", 24),
    ("IG_STORY_HIGHLIGHT_REPLY", 25),
    ("IG_STORY_HIGHLIGHT_REACTION", 26),
    ("IG_EXTERNAL_LINK", 27),
    ("IG_RECEIVER_FETCH", 28),
    ("FB_FEED_SHARE", 1000),
    ("FB_STORY_REPLY", 1001),
    ("FB_STORY_SHARE", 1002),
    ("FB_STORY_MENTION", 1003),
    ("FB_FEED_VIDEO_SHARE", 1004),
    ("FB_GAMING_CUSTOM_UPDATE", 1005),
    ("FB_PRODUCER_STORY_REPLY", 1006),
    ("FB_EVENT", 1007),
    ("FB_FEED_POST_PRIVATE_REPLY", 1008),
    ("FB_SHORT", 1009),
    ("FB_COMMENT_MENTION_SHARE", 1010),
    ("FB_POST_MENTION", 1011),
    ("FB_PROFILE_DIRECTORY_ITEM", 1013),
    ("FB_FEED_POST_REACTION_REPLY", 1014),
    ("FB_QUICKSNAP_REPLY", 1015),
    ("MSG_STATUS_REPLY", 1016),
    ("FB_GROUP_POST", 1017),
    ("FB_DAILY_GAME_CHALLENGE", 1018),
    ("FB_QUICKSNAP_REACTION_REPLY", 1019),
    ("MSG_EXTERNAL_LINK_SHARE", 2000),
    ("MSG_P2P_PAYMENT", 2001),
    ("MSG_LOCATION_SHARING", 2002),
    ("MSG_LOCATION_SHARING_V2", 2003),
    ("MSG_HIGHLIGHTS_TAB_FRIEND_UPDATES_REPLY", 2004),
    ("MSG_HIGHLIGHTS_TAB_LOCAL_EVENT_REPLY", 2005),
    ("MSG_RECEIVER_FETCH", 2006),
    ("MSG_IG_MEDIA_SHARE", 2007),
    ("MSG_GEN_AI_SEARCH_PLUGIN_RESPONSE", 2008),
    ("MSG_REELS_LIST", 2009),
    ("MSG_CONTACT", 2010),
    ("MSG_THREADS_POST_SHARE", 2011),
    ("MSG_FILE", 2012),
    ("MSG_AVATAR_DETAILS", 2013),
    ("MSG_AI_CONTACT", 2014),
    ("MSG_MEMORIES_SHARE", 2015),
    ("MSG_SHARED_ALBUM_REPLY", 2016),
    ("MSG_SHARED_ALBUM", 2017),
    ("MSG_OCCAMADILLO_XMA", 2018),
    ("MSG_GEN_AI_SUBSCRIPTION", 2021),
    ("MSG_GEN_AI_REMINDER", 2022),
    ("MSG_GEN_AI_MEMU_ONBOARDING_RESPONSE", 2023),
    ("MSG_NOTE_REPLY", 2024),
    ("MSG_NOTE_MENTION", 2025),
    ("GEN_AI_ENTITY", 2026),
    ("MSG_OPG_P2P_PAYMENT", 2027),
    ("GEN_AI_RICH_RESPONSE", 2028),
    ("MSG_MUSIC_STICKER", 2029),
    ("MSG_PHONE_NUMBER", 2030),
    ("AI_ACTIVITY_SHARE", 2031),
    ("MSG_PRIVATE_XMA", 2032),
    ("MSG_SOCIAL_CUE_MEMORIES", 2033),
    ("MSG_MANUS_GROWTH_REFERRAL", 2060),
    ("MSG_MOMENT_LINK", 2061),
    ("MSG_HORIZON_WEEL", 2062),
    ("MSG_MOMENT_ADDED", 2063),
    ("MSG_STORYTELLING_PROMPT", 2067),
    ("MSG_SUPERVISION_INVITE", 2068),
    ("MSG_SOCIAL_CUE_MLE", 2069),
    ("MSG_SOCIAL_CUE_POST", 2070),
    ("RTC_AUDIO_CALL", 3000),
    ("RTC_VIDEO_CALL", 3001),
    ("RTC_MISSED_AUDIO_CALL", 3002),
    ("RTC_MISSED_VIDEO_CALL", 3003),
    ("RTC_GROUP_AUDIO_CALL", 3004),
    ("RTC_GROUP_VIDEO_CALL", 3005),
    ("RTC_MISSED_GROUP_AUDIO_CALL", 3006),
    ("RTC_MISSED_GROUP_VIDEO_CALL", 3007),
    ("RTC_ONGOING_AUDIO_CALL", 3008),
    ("RTC_ONGOING_VIDEO_CALL", 3009),
    ("MSG_RECEIVER_FETCH_FALLBACK", 3025),
    ("DATACLASS_SENDER_COPY", 4000),
];

/// `ExtendedContentMessage.XmaLayoutType` by name.
pub const XMA_LAYOUT_TYPES: &[(&str, i32)] = &[
    ("SINGLE", 0),
    ("HSCROLL", 1),
    ("PORTRAIT", 3),
    ("STANDARD_DXMA", 12),
    ("LIST_DXMA", 15),
    ("GRID", 16),
];

/// `ExtendedContentMessage.OverlayIconGlyph` by name.
pub const OVERLAY_ICON_GLYPHS: &[(&str, i32)] = &[
    ("INFO", 0),
    ("EYE_OFF", 1),
    ("NEWS_OFF", 2),
    ("WARNING", 3),
    ("PRIVATE", 4),
    ("NONE", 5),
    ("MEDIA_LABEL", 6),
    ("POST_COVER", 7),
    ("POST_LABEL", 8),
    ("WARNING_SCREENS", 9),
];
