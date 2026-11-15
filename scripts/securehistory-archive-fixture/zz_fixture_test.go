// Builds crates/client/tests/fixtures/securehistory_archive.json: pages of Messenger's
// encrypted archive sealed with synthetic keys, and what mautrix-meta's own securehistory
// package decrypts them to. The Rust port is checked against that, not against a reading of
// the Go code.
//
// Most of what it calls is package-internal, so this file runs as a test inside a throwaway
// copy of the package; `run.sh` beside it does that. Every key, id and text here is made up.
//
// The encrypt side used here is mautrix's own (minos_send.go) where it has one; the archive
// and Echo envelopes and the older Minos versions, which mautrix only ever decrypts, are
// sealed by the helpers below, and the recorded result is always what Go decrypts.
package securehistory

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waArmadilloBackupCommon"
	"go.mau.fi/whatsmeow/proto/waArmadilloBackupMessage"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waConsumerApplication"
	"go.mau.fi/whatsmeow/proto/waMediaTransport"
	"go.mau.fi/whatsmeow/proto/waMsgApplication"
	"golang.org/x/crypto/chacha20"
	"google.golang.org/protobuf/proto"
)

const (
	fxSelf      = int64(100000000000001)
	fxOther     = "100000000000002"
	fxThird     = "100000000000003"
	fxDMThread  = "100000000000002"
	fxGroup     = "900000000000001"
	fxEpochA    = "3000000000000001"
	fxEpochB    = "3000000000000002"
	fxAnonA     = "4000000000000001"
	fxAnonB     = "4000000000000002"
	fxBackupID  = "2000000000000001"
	fxBaseStamp = int64(1700000000000)
)

func fxRandom(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// fxSeal is decryptData's inverse, with padding after the length-prefixed plaintext.
func fxSeal(key, plaintext, aad []byte) []byte {
	salt := fxRandom(16)
	derived := must(chacha20.HChaCha20(key, salt))
	gcm := must(cipher.NewGCM(must(aes.NewCipher(derived))))
	nonce := fxRandom(12)
	body := binary.BigEndian.AppendUint32(nil, uint32(len(plaintext)))
	body = append(body, plaintext...)
	body = append(body, make([]byte, 5)...)
	return gcm.Seal(append(salt, nonce...), nonce, body, aad)
}

// fxSealArchive is decryptArchivePayload's inverse.
func fxSealArchive(epoch Epoch, threadID string, version int64, plaintext []byte) []byte {
	info := "message_key_in_epoch_" + string(epoch.AnonID)
	salt := []byte(threadID)
	switch version {
	case 2:
		info += "_cipher_version_2"
	case 3, 4:
		info += fmt.Sprintf("_cipher_version_%d_thread_%s", version, threadID)
		salt = make([]byte, 10)
	}
	key := must(hkdf.Key(sha256.New, epoch.RootKey, salt, info, 32))
	return fxSeal(key, plaintext, []byte("message_thread_"+threadID))
}

func fxSealSupplementalKey(epoch Epoch, key string) []byte {
	derived := must(hkdf.Key(sha256.New, epoch.RootKey, make([]byte, 10), "kdf_info:mailbox_root_key_v2>supplemental_enc_key", 32))
	return fxSeal(derived, []byte(key), []byte("supplemental_enc_aad"))
}

func fxText(text string) *waConsumerApplication.ConsumerApplication_Content {
	return &waConsumerApplication.ConsumerApplication_Content{
		Content: &waConsumerApplication.ConsumerApplication_Content_MessageText{
			MessageText: &waCommon.MessageText{Text: proto.String(text)},
		},
	}
}

// fxBackup is a BackupMessage carrying a ConsumerApplication, as echoProtobuf builds one.
func fxBackup(content *waConsumerApplication.ConsumerApplication_Content, metadata *waMsgApplication.MessageApplication_Metadata, id, sender string, timestamp int64) []byte {
	decrypted := must(echoProtobuf(content, metadata, id, sender, timestamp))
	return must(proto.Marshal(decrypted.Message))
}

func fxImage(caption string) *waConsumerApplication.ConsumerApplication_Content {
	image := &waConsumerApplication.ConsumerApplication_ImageMessage{Caption: &waCommon.MessageText{Text: proto.String(caption)}}
	err := image.Set(&waMediaTransport.ImageTransport{
		Integral: &waMediaTransport.ImageTransport_Integral{Transport: &waMediaTransport.WAMediaTransport{
			Integral: &waMediaTransport.WAMediaTransport_Integral{
				FileSHA256:    fxRandom(32),
				MediaKey:      fxRandom(32),
				FileEncSHA256: fxRandom(32),
				DirectPath:    proto.String("/v/t62.0-24/synthetic_image.enc"),
			},
			Ancillary: &waMediaTransport.WAMediaTransport_Ancillary{
				FileLength: proto.Uint64(4096),
				Mimetype:   proto.String("image/jpeg"),
				ObjectID:   proto.String("8100000000000001"),
			},
		}},
		Ancillary: &waMediaTransport.ImageTransport_Ancillary{Width: proto.Uint32(640), Height: proto.Uint32(480)},
	})
	if err != nil {
		panic(err)
	}
	return &waConsumerApplication.ConsumerApplication_Content{
		Content: &waConsumerApplication.ConsumerApplication_Content_ImageMessage{ImageMessage: image},
	}
}

func fxReaction(target, emoji string, timestamp int64) *waConsumerApplication.ConsumerApplication_Content {
	return &waConsumerApplication.ConsumerApplication_Content{
		Content: &waConsumerApplication.ConsumerApplication_Content_ReactionMessage{
			ReactionMessage: &waConsumerApplication.ConsumerApplication_ReactionMessage{
				Key:               &waCommon.MessageKey{ID: proto.String(target)},
				Text:              proto.String(emoji),
				SenderTimestampMS: proto.Int64(timestamp),
			},
		},
	}
}

func fxEdit(target, text string, timestamp int64) *waConsumerApplication.ConsumerApplication_Content {
	return &waConsumerApplication.ConsumerApplication_Content{
		Content: &waConsumerApplication.ConsumerApplication_Content_EditMessage{
			EditMessage: &waConsumerApplication.ConsumerApplication_EditMessage{
				Key:         &waCommon.MessageKey{ID: proto.String(target)},
				Message:     &waCommon.MessageText{Text: proto.String(text)},
				TimestampMS: proto.Int64(timestamp),
			},
		},
	}
}

func fxStanza(epoch Epoch, threadID, version string, timestamp int64, plaintext []byte) *ArchiveProtobuf {
	number := must(archiveEncryptionVersion(version))
	return &ArchiveProtobuf{
		Encrypted:         fxSealArchive(epoch, threadID, number, plaintext),
		EncryptionVersion: version,
		EpochID:           epoch.ID,
		EpochAnonID:       string(epoch.AnonID),
		TimestampMS:       timestamp,
	}
}

func fxSupplemental(epoch Epoch, threadID, version, key string, timestamp int64, plaintext []byte) *ArchiveProtobuf {
	stanza := fxStanza(epoch, threadID, version, timestamp, plaintext)
	stanza.KeyCiphertext = fxSealSupplementalKey(epoch, key)
	stanza.SupplementalKey = "ignored-by-go"
	return stanza
}

// fxOTID is an offline threading id whose top bits carry the timestamp, as Messenger's do.
func fxOTID(timestamp int64, low uint64) string {
	return strconv.FormatUint(uint64(timestamp)<<22|low, 10)
}

// --- Echo documents ---

type fxEchoLine struct{ key, value string }

func fxEchoDoc(lines ...fxEchoLine) []byte {
	var out strings.Builder
	for _, line := range lines {
		out.WriteString(line.key + ": " + line.value + "\r\n")
	}
	out.WriteString("\r\n")
	return []byte(out.String())
}

func fxEchoHeader(id string, timestamp int64, from string) []fxEchoLine {
	return []fxEchoLine{
		{"Message-ID", "<" + id + "@synthetic.invalid>"},
		{"Thread-ID", fxDMThread},
		{"X-Offline-Threading-ID", id},
		{"Sort-Order", strconv.FormatInt(timestamp, 10)},
		{"From", from},
	}
}

func fxB64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func fxEcho(epoch Epoch, threadID, version string, withEpochID bool, document []byte) *EchoDocument {
	number := must(archiveEncryptionVersion(version))
	echo := &EchoDocument{
		EchoDocumentString: fxSealArchive(epoch, threadID, number, document),
		EncryptionVersion:  version,
		EpochAnonID:        string(epoch.AnonID),
	}
	if withEpochID {
		echo.EpochID = proto.String(epoch.ID)
	}
	return echo
}

// --- Minos ---

type fxIdentity struct{ private, public [32]byte }

func fxNewIdentity() fxIdentity {
	pair := must(ecc.GenerateKeyPair())
	return fxIdentity{private: pair.PrivateKey().Serialize(), public: pair.PublicKey().PublicKey()}
}

func fxRecipientKey(epoch Epoch) []byte {
	sk, kem := must2(minosMailboxKeys(epoch))
	out := append([]byte{3}, sk.PublicKey().Bytes()...)
	return append(out, kem.EncapsulationKey().Bytes()...)
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

type fxCreatorMinos = struct {
	AuthPublicKey []byte `json:"sender_auth_pk"`
	EpochHead     []byte `json:"sender_epoch_head"`
}

type fxCreatorTransport = struct {
	EphemeralPublicKey []byte `json:"ephm_hpke_pk"`
	Signature          []byte `json:"ephm_signature"`
	SigningPublicKey   []byte `json:"mek_creator_transport_signing_pk"`
}

// fxTransportMEK distributes a fresh version-2 MEK from a transport sender with minos_send.go.
func fxTransportMEK(fbid string, epoch Epoch, head []byte, sender fxIdentity) (*MinosMEK, *MinosKeyEntry, []byte) {
	recipients := []MinosRecipient{{ParticipantID: strconv.FormatInt(fxSelf, 10), MailboxKeyFBID: "mailbox-1", EpochHead: head, EncryptionPK: fxRecipientKey(epoch)}}
	mek := must(GenerateMinosMEK(recipients))
	distribution := must(DistributeMinosMEKFromTransport(mek, recipients, &sender.private, &sender.public))
	return mek, &MinosKeyEntry{ID: fbid, Keys: &MinosKeyData{
		MEKInfo:       &MinosMEKInfo{ID: mek.ID, RosterHash: mek.RosterHash, Encrypted: distribution.Envelopes[0].EncryptedMEK, CreationTimestamp: fxBaseStamp, EncryptionVersion: 2},
		RecipientInfo: &MinosRecipientInfo{EpochID: epoch.ID, EpochAnon: epoch.AnonID, EpochHead: head},
		CreatorInfo: &MinosCreatorInfo{Transport: &fxCreatorTransport{
			EphemeralPublicKey: distribution.EphemeralAuthPK,
			Signature:          distribution.EphemeralSignature,
			SigningPublicKey:   distribution.TransportSigningPK,
		}},
	}}, distribution.TransportSigningPK
}

// fxLegacyTransportMEK is a version-2 MEK whose ephemeral key is signed with the older
// signature string, which decryptMinosMEK falls back to.
func fxLegacyTransportMEK(fbid string, epoch Epoch, head []byte, sender fxIdentity) (*MinosMEK, *MinosKeyEntry) {
	recipients := []MinosRecipient{{EpochHead: head, EncryptionPK: fxRecipientKey(epoch)}}
	mek := must(GenerateMinosMEK(recipients))
	authSK := must(ecdh.X25519().GenerateKey(rand.Reader))
	authPK := append([]byte{3}, authSK.PublicKey().Bytes()...)
	signingPK := MinosTransportSigningPK(&sender.public)
	signature := minosSign(&sender.private, fmt.Appendf(nil, "minos.structured_signature.mek_distribution:ephemeral_auth_pubkey=%x;mek_id=%x", authPK, mek.ID))
	aad := fmt.Sprintf("minos.hpke.mek_distribution_from_transport_v2:mek_id=%x;recipient_epoch=%x;recipient_roster_hash=%x;sender_transport_pubkey=%x", mek.ID, head, mek.RosterHash, signingPK)
	encrypted := must(minosSealHPKE(fxRecipientKey(epoch), authSK, mek.Key, []byte(aad)))
	return mek, &MinosKeyEntry{ID: fbid, Keys: &MinosKeyData{
		MEKInfo:       &MinosMEKInfo{ID: mek.ID, RosterHash: mek.RosterHash, Encrypted: encrypted, EncryptionVersion: 2},
		RecipientInfo: &MinosRecipientInfo{EpochID: epoch.ID, EpochAnon: epoch.AnonID, EpochHead: head},
		CreatorInfo:   &MinosCreatorInfo{Transport: &fxCreatorTransport{EphemeralPublicKey: authPK, Signature: signature, SigningPublicKey: signingPK}},
	}}
}

// fxMinosSenderMEK is a version-1 MEK (a 17-byte AES-128 key) sent by another Minos mailbox.
func fxMinosSenderMEK(fbid string, epoch Epoch) (*MinosMEK, *MinosKeyEntry) {
	mek := &MinosMEK{Key: append([]byte{1}, fxRandom(16)...), ID: fxRandom(12), RosterHash: fxRandom(32)}
	authSK := must(ecdh.X25519().GenerateKey(rand.Reader))
	senderHead := fxRandom(32)
	aad := fmt.Sprintf("minos.hpke.mek_distribution_from_minos:mek_id=%x;recipient_roster_hash=%x;sender_epoch=%x", mek.ID, mek.RosterHash, senderHead)
	encrypted := must(minosSealHPKE(fxRecipientKey(epoch), authSK, mek.Key, []byte(aad)))
	return mek, &MinosKeyEntry{ID: fbid, Keys: &MinosKeyData{
		MEKInfo:       &MinosMEKInfo{ID: mek.ID, RosterHash: mek.RosterHash, Encrypted: encrypted, EncryptionVersion: 1},
		RecipientInfo: &MinosRecipientInfo{EpochID: epoch.ID, EpochAnon: epoch.AnonID},
		CreatorInfo:   &MinosCreatorInfo{Minos: &fxCreatorMinos{AuthPublicKey: append([]byte{3}, authSK.PublicKey().Bytes()...), EpochHead: senderHead}},
	}}
}

// fxMinosV2 seals a message with EncryptMinosMessage (message encryption version 2).
func fxMinosV2(mek *MinosMEK, fbid string, sender fxIdentity, actor, messageID, threadID string, metadataVersion int, timestamp int64, plaintext []byte) *MinosProtobuf {
	authenticated := uint64(timestamp)
	if metadataVersion == 2 {
		authenticated = must(strconv.ParseUint(messageID, 10, 64)) >> 22
	}
	ciphertext, signature, err := EncryptMinosMessage(mek, messageID, threadID, authenticated, &sender.private, &sender.public, plaintext)
	if err != nil {
		panic(err)
	}
	return &MinosProtobuf{
		ActorToken: actor, Encrypted: ciphertext, MEKFBID: fbid, MEKID: mek.ID, Timestamp: timestamp,
		TransportSigningPK: MinosTransportSigningPK(&sender.public), Signature: signature,
		EncryptionVersion: 2, MetadataVersion: metadataVersion,
	}
}

// fxMinosV1 seals a message with the version-1 cipher: AES-GCM under the MEK's sender key.
func fxMinosV1(mek *MinosMEK, fbid string, sender fxIdentity, actor, messageID, threadID string, timestamp int64, plaintext []byte) *MinosProtobuf {
	key := must(minosKDF(mek.Key, "minos.kdf.mek.sender_key", len(mek.Key)-1))
	aad := fmt.Sprintf("minos.symmetric_enc.message:mek_id=%x;message_id=%s;thread_id=%x;timestamp=%d", mek.ID, messageID, []byte(threadID), timestamp)
	gcm := must(cipher.NewGCM(must(aes.NewCipher(key))))
	nonce := fxRandom(12)
	ciphertext := gcm.Seal(slices.Clone(nonce), nonce, plaintext, []byte(aad))
	return &MinosProtobuf{
		ActorToken: actor, Encrypted: ciphertext, MEKFBID: fbid, MEKID: mek.ID, Timestamp: timestamp,
		TransportSigningPK: MinosTransportSigningPK(&sender.public),
		Signature:          minosSign(&sender.private, append([]byte("minos.unstructured_signature.message:"), ciphertext...)),
		EncryptionVersion:  1, MetadataVersion: 1,
	}
}

// --- What mautrix makes of a decrypted message ---

type fxProtobuf struct {
	TimestampMS int64  `json:"timestamp_ms"`
	Message     []byte `json:"message"`
}

type fxDecrypted struct {
	ID            string                `json:"id"`
	Message       fxProtobuf            `json:"message"`
	Supplementals map[string]fxProtobuf `json:"supplementals"`
	Attachments   []ArchiveAttachment   `json:"attachments"`
	Tags          []string              `json:"tags"`
}

type fxReactionOut struct {
	Sender      string `json:"sender"`
	TimestampMS int64  `json:"timestamp_ms"`
	Emoji       string `json:"emoji"`
}

// fxConverted is convertArchiveMessage's result without bridgev2: the message's identity,
// what its content decodes to, the edit folded into it and the reactions kept.
type fxConverted struct {
	ID              string          `json:"id"`
	Outcome         string          `json:"outcome"`
	Sender          string          `json:"sender,omitempty"`
	TimestampMS     int64           `json:"timestamp_ms,omitempty"`
	Kind            string          `json:"kind,omitempty"`
	Text            string          `json:"text,omitempty"`
	ReplyTo         string          `json:"reply_to,omitempty"`
	EditTimestampMS int64           `json:"edit_timestamp_ms,omitempty"`
	Reactions       []fxReactionOut `json:"reactions"`
}

type fxDecoded struct {
	app       *waMsgApplication.MessageApplication
	consumer  *waConsumerApplication.ConsumerApplication
	armadillo bool
	// An armadillo message without content, or a raven notice: a supplemental to pass over.
	notice bool
	sender string
}

// fxDecode is decodeArchiveMessage without the portal.
func fxDecode(message *waArmadilloBackupMessage.BackupMessage, timestampMS int64) (*fxDecoded, error) {
	var decoded fxDecoded
	switch payload := message.GetPayload().(type) {
	case *waArmadilloBackupMessage.BackupMessage_EncryptedTransportMessage:
		var application waMsgApplication.MessageApplication
		if err := proto.Unmarshal(payload.EncryptedTransportMessage, &application); err != nil {
			return nil, err
		}
		fb, err := whatsmeow.DecodeFBApplication(&application)
		if err != nil {
			return nil, err
		}
		decoded.app = &application
		decoded.consumer, _ = fb.Message.(*waConsumerApplication.ConsumerApplication)
		decoded.armadillo = fb.GetArmadillo() != nil
		decoded.notice = decoded.armadillo && (fb.GetArmadillo().GetPayload().GetContent() == nil || fb.GetArmadillo().GetPayload().GetContent().GetRavenActionNotifMessage() != nil)
	case *waArmadilloBackupMessage.BackupMessage_EncryptedTransportEvent,
		*waArmadilloBackupMessage.BackupMessage_EncryptedTransportLocallyTransformedMessage:
		return nil, nil
	case *waArmadilloBackupMessage.BackupMessage_MiTransportAdminMessage:
	default:
		return nil, fmt.Errorf("missing payload")
	}
	metadata := message.GetMetadata()
	if metadata.GetMessageID() == "" || metadata.GetSenderID() == "" || timestampMS < 0 {
		return nil, fmt.Errorf("missing metadata")
	}
	if _, err := strconv.ParseInt(metadata.GetSenderID(), 10, 64); err != nil {
		return nil, err
	}
	decoded.sender = metadata.GetSenderID()
	return &decoded, nil
}

// fxConvert is convertArchiveMessage's supplemental folding, step for step.
func fxConvert(message *DecryptedMessage) fxConverted {
	out := fxConverted{ID: message.ID, Reactions: []fxReactionOut{}}
	parent, err := fxDecode(message.Message.Message, message.Message.TimestampMS)
	if err != nil {
		out.Outcome = "error"
		return out
	} else if parent == nil {
		out.Outcome = "skipped"
		return out
	}
	parentID := message.Message.Message.GetMetadata().GetMessageID()
	type reaction struct {
		sender      string
		timestampMS int64
		text        string
	}
	reactions := map[string]reaction{}
	var latestEdit *waConsumerApplication.ConsumerApplication_EditMessage
	var editTimestampMS int64
	for _, supplemental := range message.Supplementals {
		switch supplemental.Message.GetPayload().(type) {
		case *waArmadilloBackupMessage.BackupMessage_EncryptedTransportEvent,
			*waArmadilloBackupMessage.BackupMessage_EncryptedTransportLocallyTransformedMessage,
			*waArmadilloBackupMessage.BackupMessage_MiTransportAdminMessage:
			continue
		}
		if supplemental.Message.GetMetadata() == nil || supplemental.Message.GetMetadata().TimestampMS == nil {
			out.Outcome = "error"
			return out
		}
		timestampMS := supplemental.Message.GetMetadata().GetTimestampMS()
		decoded, err := fxDecode(supplemental.Message, timestampMS)
		if err != nil {
			out.Outcome = "error"
			return out
		} else if decoded == nil {
			continue
		}
		content := decoded.consumer.GetPayload().GetContent()
		if r := content.GetReactionMessage(); r != nil {
			if target := r.GetKey().GetID(); target != "" && target != parentID {
				out.Outcome = "error"
				return out
			}
			previous, exists := reactions[decoded.sender]
			if !exists || timestampMS > previous.timestampMS || (timestampMS == previous.timestampMS && r.GetText() == "") {
				reactions[decoded.sender] = reaction{decoded.sender, timestampMS, r.GetText()}
			}
		} else if edit := content.GetEditMessage(); edit != nil {
			if target := edit.GetKey().GetID(); target != "" && target != parentID {
				out.Outcome = "error"
				return out
			} else if decoded.sender != parent.sender || edit.GetMessage() == nil {
				out.Outcome = "error"
				return out
			}
			if latestEdit == nil || timestampMS > editTimestampMS {
				latestEdit = edit
				editTimestampMS = timestampMS
			}
		} else if content.GetPollUpdateMessage() != nil && parent.consumer.GetPayload().GetContent().GetPollCreationMessage() != nil {
			continue
		} else if decoded.notice {
			continue
		} else {
			out.Outcome = "error"
			return out
		}
	}
	out.Outcome = "converted"
	out.Sender = parent.sender
	out.TimestampMS = message.Message.TimestampMS
	out.ReplyTo = parent.app.GetMetadata().GetQuotedMessage().GetStanzaID()
	content := parent.consumer.GetPayload().GetContent()
	switch {
	case latestEdit != nil:
		out.Kind = "MessageText"
		out.Text = latestEdit.GetMessage().GetText()
		out.EditTimestampMS = latestEdit.GetTimestampMS()
		if out.EditTimestampMS == 0 {
			out.EditTimestampMS = editTimestampMS
		}
	case parent.armadillo:
		out.Kind = "Armadillo"
	case content != nil:
		out.Kind = strings.TrimPrefix(fmt.Sprintf("%T", content.GetContent()), "*waConsumerApplication.ConsumerApplication_Content_")
		out.Text = content.GetMessageText().GetText() + content.GetImageMessage().GetCaption().GetText() + content.GetVideoMessage().GetCaption().GetText()
	default:
		out.Kind = "None"
	}
	senders := make([]string, 0, len(reactions))
	for sender := range reactions {
		senders = append(senders, sender)
	}
	slices.Sort(senders)
	for _, sender := range senders {
		if r := reactions[sender]; r.text != "" {
			out.Reactions = append(out.Reactions, fxReactionOut{r.sender, r.timestampMS, r.text})
		}
	}
	return out
}

type fxPage struct {
	Name       string          `json:"name"`
	ThreadID   string          `json:"thread_id"`
	SelfUserID int64           `json:"self_user_id"`
	IsGroup    bool            `json:"is_group"`
	Response   json.RawMessage `json:"response"`
	Decrypted  []fxDecrypted   `json:"decrypted"`
	Converted  []fxConverted   `json:"converted"`
}

func fxRun(t *testing.T, device *Device, name, threadID string, isGroup bool, page *MessageRange, expected []string) fxPage {
	response := must(json.Marshal(map[string]any{
		"encrypted_backup": map[string]any{"mailbox": map[string]any{"messages_from_selected_threads": []*MessageRange{page}}},
	}))
	// Go writes an empty list as null; the Rust types take only a list, so the page carries [].
	var tree any
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.UseNumber()
	if err := decoder.Decode(&tree); err != nil {
		t.Fatal(err)
	}
	response = must(json.Marshal(fxListsNotNull(tree)))
	// Decrypt what a parse of the response gives, as FetchMessages would hand it over.
	var parsed messageRangeResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		t.Fatal(err)
	}
	messages := parsed.Backup.Mailbox.Ranges[0].Decrypt(context.Background(), device, threadID, fxSelf, isGroup)
	out := fxPage{Name: name, ThreadID: threadID, SelfUserID: fxSelf, IsGroup: isGroup, Response: response}
	var ids []string
	for _, message := range messages {
		ids = append(ids, message.ID)
		decrypted := fxDecrypted{
			ID:            message.ID,
			Message:       fxProtobuf{message.Message.TimestampMS, must(proto.MarshalOptions{Deterministic: true}.Marshal(message.Message.Message))},
			Supplementals: map[string]fxProtobuf{},
			Attachments:   message.Attachments,
			Tags:          message.Tags,
		}
		for key, supplemental := range message.Supplementals {
			decrypted.Supplementals[key] = fxProtobuf{supplemental.TimestampMS, must(proto.MarshalOptions{Deterministic: true}.Marshal(supplemental.Message))}
		}
		out.Decrypted = append(out.Decrypted, decrypted)
		out.Converted = append(out.Converted, fxConvert(message))
	}
	if !slices.Equal(ids, expected) {
		t.Fatalf("%s: decrypted %v, expected %v", name, ids, expected)
	}
	return out
}

func TestWriteFixture(t *testing.T) {
	path := os.Getenv("FIXTURE_OUT")
	if path == "" {
		t.Skip("FIXTURE_OUT is not set")
	}
	epochA := Epoch{ID: fxEpochA, AnonID: []byte(fxAnonA), RootKey: fxRandom(32)}
	epochB := Epoch{ID: fxEpochB, AnonID: []byte(fxAnonB), RootKey: fxRandom(32)}
	device := &Device{
		ID: "1000000000000001", BackupID: fxBackupID,
		StoragePublicKey: fxRandom(32), StoragePrivateKey: fxRandom(32),
		MailboxRootKey: fxRandom(32), OCMFClientState: fxRandom(48),
		Epochs: map[string]Epoch{fxEpochA: epochA, fxEpochB: epochB},
	}
	self := strconv.FormatInt(fxSelf, 10)
	thread := fxDMThread
	stamp := func(n int64) int64 { return fxBaseStamp + n*1000 }
	attachment := []ArchiveAttachment{{URL: "https://cdn.synthetic.invalid/8100000000000001", ObjectID: "8100000000000001"}}
	var messages []*ArchiveMessage
	add := func(message *ArchiveMessage) { messages = append(messages, message) }
	plain := func(version, id, sender string, ts int64, content *waConsumerApplication.ConsumerApplication_Content, metadata *waMsgApplication.MessageApplication_Metadata) *ArchiveMessage {
		return &ArchiveMessage{ID: id, Protobufs: &ArchiveProtobufs{Message: fxStanza(epochA, thread, version, ts, fxBackup(content, metadata, id, sender, ts))}}
	}

	// Archive cipher version 0, a reply, with a reaction and two edits as supplementals.
	quoted := &waMsgApplication.MessageApplication_Metadata{QuotedMessage: &waMsgApplication.MessageApplication_Metadata_QuotedMessage{StanzaID: proto.String("m-reply-target"), Participant: proto.String(self + "@msgr")}}
	m := plain("", "m-v0", fxOther, stamp(1), fxText("first draft"), quoted)
	m.Protobufs.Supplementals = []*ArchiveProtobuf{
		fxSupplemental(epochA, thread, "", "reaction:"+self, stamp(2), fxBackup(fxReaction("m-v0", "\U0001F44D", stamp(2)), nil, "m-v0-r1", self, stamp(2))),
		fxSupplemental(epochB, thread, "ENCRYPTION_KDF_WITH_NULL_SALT", "edit:m-v0-e1", stamp(3), fxBackup(fxEdit("m-v0", "second draft", stamp(3)), nil, "m-v0-e1", fxOther, stamp(3))),
		fxSupplemental(epochA, thread, "ENCRYPTION_KDF_WITH_VERSION", "edit:m-v0-e2", stamp(4), fxBackup(fxEdit("m-v0", "final text", 0), nil, "m-v0-e2", fxOther, stamp(4))),
	}
	add(m)
	// Version 2: an image with a caption and its CDN attachment.
	m = plain("ENCRYPTION_KDF_WITH_VERSION", "m-v2", self, stamp(5), fxImage("a caption"), nil)
	m.Attachments = attachment
	add(m)
	// Version 3, with two reactions by one user under different keys (the later one stands)
	// and a withdrawn one; version 4, whose reaction names another message.
	m = plain("ENCRYPTION_KDF_WITH_NULL_SALT", "m-v3", fxOther, stamp(6), fxText("null salt"), nil)
	m.Protobufs.Supplementals = []*ArchiveProtobuf{
		fxSupplemental(epochA, thread, "", "reaction:first", stamp(6)+2, fxBackup(fxReaction("m-v3", "b", stamp(6)+2), nil, "m-v3-r1", fxThird, stamp(6)+2)),
		fxSupplemental(epochA, thread, "", "reaction:second", stamp(6)+1, fxBackup(fxReaction("m-v3", "a", stamp(6)+1), nil, "m-v3-r2", fxThird, stamp(6)+1)),
		fxSupplemental(epochA, thread, "", "reaction:withdrawn", stamp(6)+3, fxBackup(fxReaction("", "", stamp(6)+3), nil, "m-v3-r3", self, stamp(6)+3)),
	}
	add(m)
	m = plain("ENCRYPTION_KDF_WITH_NULL_SALT_DF_CANARY", "m-v4", fxOther, stamp(7), fxText("canary"), nil)
	m.Protobufs.Tags = []string{"SOME_TAG"}
	m.Protobufs.Supplementals = []*ArchiveProtobuf{
		fxSupplemental(epochA, thread, "", "reaction:elsewhere", stamp(7), fxBackup(fxReaction("m-elsewhere", "c", stamp(7)), nil, "m-v4-r1", fxThird, stamp(7))),
	}
	add(m)
	// "UNKNOWN" reads as version 0.
	add(plain("UNKNOWN", "m-unknown", self, stamp(8), fxText("unknown is zero"), nil))
	// A version Go does not know, a visibility record, and a message under the wrong epoch.
	m = plain("", "m-bad-version", fxOther, stamp(9), fxText("never read"), nil)
	m.Protobufs.Message.EncryptionVersion = "ENCRYPTION_FROM_THE_FUTURE"
	add(m)
	m = plain("", "m-visibility", fxOther, stamp(10), fxText("hidden"), nil)
	m.Protobufs.Tags = []string{"EB_VISIBILITY_METADATA"}
	add(m)
	m = plain("", "m-wrong-epoch", fxOther, stamp(11), fxText("wrong epoch"), nil)
	m.Protobufs.Message.EpochAnonID = fxAnonB
	add(m)
	// A supplemental without its key ciphertext fails the whole message.
	m = plain("", "m-keyless-supplemental", fxOther, stamp(12), fxText("keyless"), nil)
	m.Protobufs.Supplementals = []*ArchiveProtobuf{fxStanza(epochA, thread, "", stamp(12), fxBackup(fxReaction("m-keyless-supplemental", "x", stamp(12)), nil, "r", self, stamp(12)))}
	add(m)
	// An unencrypted stanza.
	add(&ArchiveMessage{ID: "m-plain", Protobufs: &ArchiveProtobufs{Unencrypted: &struct {
		Message     []byte `json:"unencrypted_protobuf"`
		TimestampMS int64  `json:"protobuf_timestamp_ms,string"`
	}{fxBackup(fxText("in the clear"), nil, "m-plain", fxOther, stamp(13)), stamp(13)}}})
	// A transport event: decrypts, but converts to nothing.
	event := must(proto.Marshal(&waArmadilloBackupMessage.BackupMessage{
		Metadata: &waArmadilloBackupCommon.Metadata{SenderID: proto.String(fxOther), MessageID: proto.String("m-event"), TimestampMS: proto.Int64(stamp(14))},
		Payload:  &waArmadilloBackupMessage.BackupMessage_EncryptedTransportEvent{EncryptedTransportEvent: &waArmadilloBackupCommon.Subprotocol{Payload: []byte{1, 2}, Version: proto.Int32(1)}},
	}))
	add(&ArchiveMessage{ID: "m-event", Protobufs: &ArchiveProtobufs{Message: fxStanza(epochA, thread, "", stamp(14), event)}})

	// Echo documents.
	echoText := fxEchoDoc(append(fxEchoHeader("e-text", stamp(20), "Synthetic Person <"+fxOther+"@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "text"},
		fxEchoLine{"Text", `"line one\nline \"two\""`},
		fxEchoLine{"Is-Forwarded", "1"},
		fxEchoLine{"Reply-Message-Id", "m-v0"},
		fxEchoLine{"Reply-Message-Sender", "<" + self + "@facebook.com>"},
		fxEchoLine{"Edit-Contents-e-text-edit", `"edited text"`},
		fxEchoLine{"Edit-Timestamps-e-text-edit", strconv.FormatInt(stamp(21), 10)},
		fxEchoLine{"Edit-Contents-e-text", "ignored: the message's own id"},
		fxEchoLine{"Reactions", `"` + "❤️" + `" <` + self + `@facebook.com>, =?utf-8?B?8J+YgA==?= <` + fxThird + `@facebook.com>`},
		fxEchoLine{"X-Reaction-Offline-Threading-IDs", `"e-text-r1" <a@synthetic.invalid>, e-text-r2 <b@synthetic.invalid>`},
		fxEchoLine{"Reaction-Authoritative-Timestamps", strconv.FormatInt(stamp(22), 10) + " <a@synthetic.invalid>, \"" + strconv.FormatInt(stamp(23), 10) + "\" <b@synthetic.invalid>"},
		fxEchoLine{"Empty-Later", "set"},
		fxEchoLine{"Empty-Later", ""},
	)...)
	add(&ArchiveMessage{ID: "e-text", Echo: fxEcho(epochA, thread, "ENCRYPTION_KDF_WITH_NULL_SALT", true, echoText)})

	mediaKey, plainHash, encHash := fxRandom(32), fxRandom(32), fxRandom(32)
	media := func(id, kind string, extra ...fxEchoLine) []byte {
		lines := append(fxEchoHeader(id, stamp(30), "<"+fxOther+"@facebook.com>"),
			fxEchoLine{"Message-Content-Type", "media"},
			fxEchoLine{"Attachment-Type", kind},
			fxEchoLine{"X-Object-Id", "8200000000000001"},
			fxEchoLine{"X-Media-Key", fxB64(mediaKey) + "="},
			fxEchoLine{"X-Plaintext-Hash", fxB64(plainHash)},
			fxEchoLine{"X-Encrypted-Hash", fxB64(encHash)},
			fxEchoLine{"X-Direct-Path", "/v/t62.0-24/synthetic_" + kind + ".enc"},
			fxEchoLine{"X-Media-Key-Timestamp", "1700000000"},
			fxEchoLine{"Size", "123456"},
			fxEchoLine{"Content-Type", "application/x-synthetic"},
		)
		return fxEchoDoc(append(lines, extra...)...)
	}
	add(&ArchiveMessage{ID: "e-video", Attachments: attachment, Echo: fxEcho(epochA, thread, "", false, media("e-video", "video",
		fxEchoLine{"Width", "1280"}, fxEchoLine{"Height", "720"}, fxEchoLine{"Playable-Duration", "42"}, fxEchoLine{"Text", "video caption"}))})
	add(&ArchiveMessage{ID: "e-audio", Echo: fxEcho(epochB, thread, "ENCRYPTION_KDF_WITH_VERSION", true, media("e-audio", "audio",
		fxEchoLine{"Playable-Duration", "15000"}, fxEchoLine{"X-Attachment-Type", "1"}))})
	add(&ArchiveMessage{ID: "e-document", Echo: fxEcho(epochA, thread, "", true, media("e-document", "file", fxEchoLine{"File-Name", `"report.pdf"`}))})
	add(&ArchiveMessage{ID: "e-sticker", Echo: fxEcho(epochA, thread, "", true, media("e-sticker", "sticker", fxEchoLine{"Width", "512"}, fxEchoLine{"Height", "512"}))})
	// Several attachments: the one with a backup status is the one kept, under its prefix.
	add(&ArchiveMessage{ID: "e-image", Echo: fxEcho(epochA, thread, "ENCRYPTION_KDF_WITH_NULL_SALT_DF_CANARY", true, fxEchoDoc(append(fxEchoHeader("e-image", stamp(31), "<"+fxOther+"@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "media"},
		fxEchoLine{"Attachment-Type", "animated_image"},
		fxEchoLine{"X-Attachment-Object-Ids", "8300000000000001, 8300000000000002"},
		fxEchoLine{"8300000000000002-X-Backup-Status", "ok"},
		fxEchoLine{"8300000000000002-X-Media-Key", fxB64(mediaKey)},
		fxEchoLine{"8300000000000002-X-Plaintext-Hash", fxB64(plainHash)},
		fxEchoLine{"8300000000000002-X-Encrypted-Hash", fxB64(encHash)},
		fxEchoLine{"8300000000000002-X-Direct-Path", "/v/t62.0-24/synthetic_second.enc"},
		fxEchoLine{"Width", "320"}, fxEchoLine{"Height", "200"},
		fxEchoLine{"Text", "image caption"},
	)...))})
	add(&ArchiveMessage{ID: "e-xma", Echo: fxEcho(epochA, thread, "", true, fxEchoDoc(append(fxEchoHeader("e-xma", stamp(32), "<"+fxOther+"@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "xma"},
		fxEchoLine{"XMA-Target-Type", "MSG_EXTERNAL_LINK_SHARE"},
		fxEchoLine{"XMA-Target-ID", "8400000000000001"},
		fxEchoLine{"XMA-Title-Text", `"A synthetic link"`},
		fxEchoLine{"XMA-Subtitle-Text", "synthetic.invalid"},
		fxEchoLine{"XMA-Target-Expiry", "1800000000"},
		fxEchoLine{"XMA-Layout-Type", "PORTRAIT"},
		fxEchoLine{"XMA-Gating-Type", "WARNING"},
		fxEchoLine{"XMA-Default-CTA", "https://synthetic.invalid/link"},
		fxEchoLine{"Text", "look at this"},
		fxEchoLine{"Attachment-Type", "image"},
		fxEchoLine{"X-Object-Id", "8500000000000001"},
		fxEchoLine{"X-Media-Key", fxB64(mediaKey)},
		fxEchoLine{"X-Plaintext-Hash", fxB64(plainHash)},
		fxEchoLine{"X-Encrypted-Hash", fxB64(encHash)},
		fxEchoLine{"X-Direct-Path", "/v/t62.0-24/synthetic_preview.enc"},
	)...))})
	add(&ArchiveMessage{ID: "e-unsent", Echo: fxEcho(epochA, thread, "", true, fxEchoDoc(append(fxEchoHeader("e-unsent", stamp(33), "<"+fxOther+"@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "placeholder"}, fxEchoLine{"Message-Content-Subtype", "unsend"})...))})
	add(&ArchiveMessage{ID: "e-admin", Echo: fxEcho(epochA, thread, "", true, fxEchoDoc(append(fxEchoHeader("e-admin", stamp(34), fxOther+"@facebook.com (Synthetic Name)"),
		fxEchoLine{"Message-Content-Type", "admin_message"}, fxEchoLine{"Text", "an admin line"})...))})
	add(&ArchiveMessage{ID: "e-unsupported", Echo: fxEcho(epochA, thread, "", true, fxEchoDoc(append(fxEchoHeader("e-unsupported", stamp(35), "<"+fxOther+"@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "hologram"})...))})
	add(&ArchiveMessage{ID: "e-bad-sender", Echo: fxEcho(epochA, thread, "", true, fxEchoDoc(append(fxEchoHeader("e-bad-sender", stamp(36), "<zero@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "text"}, fxEchoLine{"Text", "x"})...))})
	add(&ArchiveMessage{ID: "e-mismatched-id", Echo: fxEcho(epochA, thread, "", true, fxEchoDoc(append(fxEchoHeader("e-other-id", stamp(37), "<"+fxOther+"@facebook.com>"),
		fxEchoLine{"Message-Content-Type", "text"}, fxEchoLine{"Text", "x"})...))})

	// Minos.
	head := fxRandom(32)
	sender := fxNewIdentity()
	minosThread := self + ":" + thread
	if thread < self {
		minosThread = thread + ":" + self
	}
	mek1, entry1, _ := fxTransportMEK("7000000000000001", epochA, head, sender)
	mek2, entry2 := fxMinosSenderMEK("7000000000000002", epochA)
	mek3, entry3 := fxLegacyTransportMEK("7000000000000003", epochA, head, sender)
	minosMessage := func(mek *MinosMEK, fbid string, metadataVersion int, ts int64, low uint64, actor string, content *waConsumerApplication.ConsumerApplication_Content) (string, *MinosProtobuf) {
		id := fxOTID(ts, low)
		return id, fxMinosV2(mek, fbid, sender, actor, id, minosThread, metadataVersion, ts, fxBackup(content, nil, id, actor, ts))
	}
	id1, stanza1 := minosMessage(mek1, entry1.ID, 2, stamp(40), 1, fxOther, fxText("minos one"))
	reactionID := fxOTID(stamp(41), 2)
	reaction := fxMinosV2(mek1, entry1.ID, sender, self, reactionID, minosThread, 2, stamp(41), fxBackup(fxReaction(id1, "\U0001F525", stamp(41)), nil, reactionID, self, stamp(41)))
	reaction.SupplementalKey, reaction.SupplementalID = "reaction:"+self, reactionID
	add(&ArchiveMessage{ID: id1, Protobufs: &ArchiveProtobufs{MinosMessage: stanza1, MinosSupplementals: []*MinosProtobuf{reaction}}})
	id2, stanza2 := minosMessage(mek1, entry1.ID, 1, stamp(42), 3, self, fxText("minos two, same key"))
	add(&ArchiveMessage{ID: id2, Protobufs: &ArchiveProtobufs{MinosMessage: stanza2}})
	id3 := fxOTID(stamp(43), 4)
	add(&ArchiveMessage{ID: id3, Protobufs: &ArchiveProtobufs{MinosMessage: fxMinosV1(mek2, entry2.ID, sender, fxOther, id3, minosThread, stamp(43), fxBackup(fxText("minos version one"), nil, id3, fxOther, stamp(43)))}})
	id4, stanza4 := minosMessage(mek3, entry3.ID, 2, stamp(44), 5, fxOther, fxImage("minos image"))
	add(&ArchiveMessage{ID: id4, Attachments: attachment, Protobufs: &ArchiveProtobufs{MinosMessage: stanza4}})
	id5, stanza5 := minosMessage(mek1, entry1.ID, 2, stamp(45), 6, fxOther, fxText("server origin"))
	stanza5.ServerOriginContentType = json.RawMessage(`"SOMETHING"`)
	add(&ArchiveMessage{ID: id5, Protobufs: &ArchiveProtobufs{MinosMessage: stanza5}})
	id6, stanza6 := minosMessage(mek1, entry1.ID, 2, stamp(46), 7, fxOther, fxText("wrong actor"))
	stanza6.ActorToken = fxThird
	add(&ArchiveMessage{ID: id6, Protobufs: &ArchiveProtobufs{MinosMessage: stanza6}})
	id7, stanza7 := minosMessage(mek1, entry1.ID, 2, stamp(47), 8, fxOther, fxText("future cipher"))
	stanza7.EncryptionVersion = 3
	add(&ArchiveMessage{ID: id7, Protobufs: &ArchiveProtobufs{MinosMessage: stanza7}})
	id8, stanza8 := minosMessage(mek1, entry1.ID, 2, stamp(48), 9, fxOther, fxText("future metadata"))
	stanza8.MetadataVersion = 3
	add(&ArchiveMessage{ID: id8, Protobufs: &ArchiveProtobufs{MinosMessage: stanza8}})

	dm := &MessageRange{
		BackupID: fxBackupID, Messages: messages,
		Range:     &MessageRangeInfo{HasMoreBefore: proto.Bool(true), HasMoreAfter: proto.Bool(false), Before: stamp(0), After: stamp(50)},
		MinosKeys: []*MinosKeyEntry{entry1, entry2, entry3},
	}
	dmPage := fxRun(t, device, "dm", thread, false, dm, []string{
		"m-v0", "m-v2", "m-v3", "m-v4", "m-unknown", "m-plain", "m-event",
		"e-text", "e-video", "e-audio", "e-document", "e-sticker", "e-image", "e-xma", "e-unsent", "e-admin",
		id1, id2, id3, id4,
	})

	// A group: Minos authenticates the bare thread id, and a cipher version-3 stanza.
	groupMEK, groupEntry, _ := fxTransportMEK("7100000000000001", epochB, head, sender)
	gid := fxOTID(stamp(60), 1)
	group := &MessageRange{
		BackupID: fxBackupID,
		Messages: []*ArchiveMessage{
			{ID: gid, Protobufs: &ArchiveProtobufs{MinosMessage: fxMinosV2(groupMEK, groupEntry.ID, sender, fxThird, gid, fxGroup, 2, stamp(60), fxBackup(fxText("group minos"), nil, gid, fxThird, stamp(60)))}},
			{ID: "g-v3", Protobufs: &ArchiveProtobufs{Message: fxStanza(epochB, fxGroup, "ENCRYPTION_KDF_WITH_NULL_SALT", stamp(61), fxBackup(fxText("group archive"), nil, "g-v3", fxOther, stamp(61)))}},
		},
		Range:     &MessageRangeInfo{HasMoreBefore: proto.Bool(false), HasMoreAfter: proto.Bool(false)},
		MinosKeys: []*MinosKeyEntry{groupEntry},
	}
	groupPage := fxRun(t, device, "group", fxGroup, true, group, []string{gid, "g-v3"})

	// FetchMessages' variables, built here as it builds them.
	epochs := []string{fxEpochA, fxEpochB}
	payload := must(json.Marshal(map[string]any{
		"restore_context": map[string]any{"act_thread_id": thread, "site": "www", "source": -1, "tam_thread_subtype": 0},
		"success": map[string]any{
			"device_context": map[string]any{
				"device_id":                device.ID,
				"locally_available_epochs": epochs,
				"raw_tokens":               map[string]any{"mailbox_root_key": device.MailboxRootKey, "ocmf_client_state_blob": device.OCMFClientState},
			},
			"direction": 1, "query_num_messages": 20, "reference_timestamp": strconv.FormatInt(stamp(50), 10),
			"server_thread_key": must(strconv.ParseInt(thread, 10, 64)), "source": -1,
		},
	}))
	variables := map[string]any{
		"app_id": "999000000000001", "includeAttachmentData": true,
		"restore_payload_strings": []string{string(payload)}, "restore_type": "RANGE_QUERY_RESTORE",
	}

	fixture := map[string]any{
		"device":    device,
		"variables": map[string]any{"app_id": "999000000000001", "thread_id": thread, "before": true, "timestamp_ms": stamp(50), "count": 20, "expected": variables},
		"pages":     []fxPage{dmPage, groupPage},
	}
	data := must(json.MarshalIndent(fixture, "", "  "))
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fxListsNotNull replaces null with [] under the keys whose Go type is a slice.
func fxListsNotNull(node any) any {
	lists := []string{"encrypted_messages", "minos_decryption_keys", "attachment_data", "supplemental_protobufs", "supplemental_protobufs_v2", "message_tags", "epoch_edges"}
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if child == nil && slices.Contains(lists, key) {
				value[key] = []any{}
			} else {
				value[key] = fxListsNotNull(child)
			}
		}
	case []any:
		for i, child := range value {
			value[i] = fxListsNotNull(child)
		}
	}
	return node
}
