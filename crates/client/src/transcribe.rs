//! Encrypted voice messages to text, as whatsapp-sync transcribes WhatsApp's.
//!
//! Every pass takes the pending voice messages newest first, fetches each file from Meta's
//! CDN by the reference its attachment keeps, opens it with whatsapp-client's audio
//! decryption (Messenger's media use WhatsApp's keys: "WhatsApp Audio Keys"), and sends the
//! audio to the whisper.cpp server. Only the words are stored.
//!
//! How a step fails decides what happens, as in whatsapp-sync:
//!
//! - the file is gone, does not decrypt, or whisper refuses the audio: `failed`, never retried;
//! - the CDN or the whisper server cannot be reached: still `pending`, and the rest of the
//!   batch waits for the next pass, which would only fail the same way.

use std::time::Duration;

use messenger_core::store::e2ee::{self, PendingAudio};
use sqlx::PgPool;
use whatsapp_client::media::{self, MediaRef};
use whatsapp_client::transcribe::{TranscribeError, Whisper};

/// whatsapp-sync's batch and cadence.
const BATCH: i64 = 20;
pub const INTERVAL: Duration = Duration::from_secs(120);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

enum Outcome {
    Done(String),
    Failed(String),
    /// Try again next pass.
    Later(String),
}

pub struct Worker {
    pool: PgPool,
    http: reqwest::Client,
    whisper: Whisper,
}

impl Worker {
    pub fn new(pool: PgPool, whisper_url: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(DOWNLOAD_TIMEOUT)
            .build()
            .expect("HTTP client");
        Self {
            pool,
            http,
            whisper: Whisper::new(whisper_url),
        }
    }

    pub async fn run(self, interval: Duration) {
        loop {
            if let Err(e) = self.pass().await {
                tracing::warn!("transcription pass failed: {e}");
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn pass(&self) -> sqlx::Result<()> {
        let mut conn = self.pool.acquire().await?;
        let pending = e2ee::pending_transcripts(&mut conn, BATCH).await?;
        for audio in &pending {
            match self.transcribe(audio).await {
                Outcome::Done(words) => {
                    e2ee::set_transcript(&mut conn, audio, Some(words.trim()), "done").await?;
                    tracing::info!("transcribed a voice message");
                }
                Outcome::Failed(why) => {
                    e2ee::set_transcript(&mut conn, audio, None, "failed").await?;
                    tracing::warn!("a voice message will not be transcribed: {why}");
                }
                Outcome::Later(why) => {
                    tracing::warn!("transcription waits for the next pass: {why}");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn transcribe(&self, audio: &PendingAudio) -> Outcome {
        let Some(file_ref) = MediaRef::from_raw(&audio.raw) else {
            return Outcome::Failed("no usable file reference".into());
        };
        let url = match file_ref.location(media::MEDIA_BASE) {
            Ok(url) => url,
            Err(e) => return Outcome::Failed(e.to_string()),
        };
        let response = match self.http.get(url).send().await {
            Ok(response) => response,
            Err(e) => return Outcome::Later(format!("CDN: {}", e.without_url())),
        };
        let status = response.status();
        if status.is_client_error() {
            return Outcome::Failed(format!("CDN answered {status}"));
        }
        if !status.is_success() {
            return Outcome::Later(format!("CDN answered {status}"));
        }
        let file = match response.bytes().await {
            Ok(file) => file,
            Err(e) => return Outcome::Later(format!("CDN: {}", e.without_url())),
        };
        let audio = match media::decrypt_audio(&file, &file_ref) {
            Ok(audio) => audio,
            Err(e) => return Outcome::Failed(e.to_string()),
        };
        match self.whisper.transcribe(audio).await {
            Ok(words) => Outcome::Done(words),
            Err(TranscribeError::Unavailable(why)) => Outcome::Later(why),
            Err(TranscribeError::Refused(why)) => Outcome::Failed(why),
        }
    }
}
