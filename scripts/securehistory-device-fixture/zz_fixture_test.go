// Builds crates/client/tests/fixtures/securehistory_device.json: the virtual device, epoch
// and enrolment crypto run by mautrix-meta's own securehistory package, so the Rust port is
// checked against the code that talks to Meta today. Every key, id and code is synthetic.
//
// The functions are package-internal, so this file runs as a test inside a throwaway copy of
// the package (from the repository root, in WSL):
//
//	rsync -a --delete --exclude .git ~/src/meta/ /tmp/meta-fixture/
//	cp scripts/securehistory-device-fixture/zz_fixture_test.go /tmp/meta-fixture/pkg/messagix/securehistory/
//	docker run --rm -v /tmp/meta-fixture:/meta -v "$PWD/crates/client/tests/fixtures:/out" \
//	  -w /meta golang:1.27-alpine go test ./pkg/messagix/securehistory -run TestWriteFixture
//
// testing/cryptotest makes crypto/rand deterministic, so the fixture is reproducible and
// PrepareDevice's random draws (keys, OCMF factor, signature nonces, trace id) are recorded:
// the Rust port replays them and must produce byte-identical output.
package securehistory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"testing"
	"testing/cryptotest"

	"github.com/gtank/ristretto255"
	"go.mau.fi/whatsmeow/util/keys"
	"golang.org/x/crypto/chacha20"
)

const (
	fixtureUserID   = "100000000000001"
	fixtureBackupID = "200000000000001"
	fixtureRegID    = "300000000000001"
	codeV1          = "1BQWERTYUIOPASDFGHJKLZXCVBNM234567QWERTY"
	codeV2          = "2CMNBVCXZLKJHGFDSAPOIUYTREWQ765432MNBVCX"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// seal is the inverse of decryptData.
func seal(key, value, aad []byte) []byte {
	salt, nonce := randomBytes(16), randomBytes(12)
	derived, err := chacha20.HChaCha20(key, salt)
	if err != nil {
		panic(err)
	}
	block, _ := aes.NewCipher(derived)
	gcm, _ := cipher.NewGCM(block)
	plaintext := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
	plaintext = append(plaintext, value...)
	out := append(salt, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad)
}

func sealB64(key, value []byte, aad string) []byte {
	return seal(key, []byte(base64.StdEncoding.EncodeToString(value)), []byte(aad))
}

type keyPair struct{ pub, priv []byte }

func newKeyPair() keyPair {
	k, err := ecdh.X25519().NewPrivateKey(randomBytes(32))
	if err != nil {
		panic(err)
	}
	return keyPair{k.PublicKey().Bytes(), k.Bytes()}
}

func dh(priv, pub []byte) []byte {
	k, _ := ecdh.X25519().NewPrivateKey(priv)
	p, _ := ecdh.X25519().NewPublicKey(pub)
	out, err := k.ECDH(p)
	if err != nil {
		panic(err)
	}
	return out
}

// encryptPublic is the inverse of decryptPublic: auth is the sender's key pair.
func encryptPublic(recipient []byte, auth keyPair, psk, aad, plaintext []byte) []byte {
	eph := newKeyPair()
	secret := append(dh(auth.priv, recipient), dh(eph.priv, recipient)...)
	inner := append([]byte{1}, auth.pub...)
	inner = append(inner, recipient...)
	inner = append(inner, eph.pub...)
	inner = append(inner, aad...)
	key, _ := hkdf.Key(sha256.New, secret, psk, string(inner), 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	out := append([]byte{1}, eph.pub...)
	return gcm.Seal(out, make([]byte, 12), plaintext, inner)
}

func fingerprint(key []byte, name string) string {
	fp, _ := hkdf.Key(sha256.New, key, nil, "meb/debug/fingerprint/"+name, 18)
	return base64.StdEncoding.EncodeToString(fp)
}

func chain(epoch Epoch) []byte {
	c, _ := hkdf.Key(sha256.New, epoch.RootKey, nil, "epoch_chaining_"+string(epoch.AnonID)+"_"+epoch.ID, 64)
	return c
}

func epochKey(epoch Epoch) []byte {
	k, err := deriveEpochKey(epoch, "epoch_data_storage", 32)
	if err != nil {
		panic(err)
	}
	return k
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func clone[T any](v T) T {
	data, _ := json.Marshal(v)
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return out
}

type failure struct {
	Name  string `json:"name"`
	Input any    `json:"input"`
	Error string `json:"error"`
}

func TestWriteFixture(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 1)
	out := map[string]any{}

	// deriveVirtualDevice, both code versions and what it rejects.
	var devices []map[string]any
	for _, c := range []struct{ code, user string }{
		{codeV1, fixtureUserID}, {codeV2, fixtureUserID}, {codeV2, "400000000000001"},
		{codeV1[:39], fixtureUserID}, {"3" + codeV1[1:], fixtureUserID}, {codeV2, ""},
	} {
		id, key, err := deriveVirtualDevice([]byte(c.code), c.user)
		devices = append(devices, map[string]any{"code": c.code, "user_id": c.user, "id": id, "blob_key": key, "error": errText(err)})
	}
	out["derive_virtual_device"] = devices

	id, blobKey, err := deriveVirtualDevice([]byte(codeV2), fixtureUserID)
	if err != nil {
		t.Fatal(err)
	}

	// decryptSecret: both AADs, a wrong AAD, and a plaintext that is not base64.
	secretValue := randomBytes(32)
	var secrets []map[string]any
	for _, c := range []struct{ name, aad string }{
		{"epoch_root_key", "virtual_device:epoch_root_key"},
		{"epoch_root_key", "secret_values_metadata"},
		{"epoch_root_key", "virtual_device:mailbox_root_key"},
	} {
		ct := sealB64(blobKey, secretValue, c.aad)
		value, err := (&VirtualDevice{ID: id, BlobKey: blobKey}).decryptSecret(ct, c.name)
		secrets = append(secrets, map[string]any{"name": c.name, "ciphertext": ct, "value": value, "error": errText(err)})
	}
	notBase64 := seal(blobKey, []byte("not base64!"), []byte("secret_values_metadata"))
	value, err := (&VirtualDevice{ID: id, BlobKey: blobKey}).decryptSecret(notBase64, "x")
	secrets = append(secrets, map[string]any{"name": "x", "ciphertext": notBase64, "value": value, "error": errText(err)})
	out["decrypt_secret"] = map[string]any{"blob_key": blobKey, "cases": secrets}

	// An epoch chain 101..105: 103 is the device's base, 101 and 102 sit behind it on backward
	// edges, 104 and 105 ahead of it on forward edges sealed to the epoch storage key.
	ids := []string{"", "910000000000101", "910000000000102", "910000000000103", "910000000000104", "910000000000105"}
	anon := func(i int) string { return []string{"", "101", "102", "103", "104", "105"}[i] }
	storage := newKeyPair()
	epoch := make([]Epoch, 6)
	for i := 1; i <= 3; i++ {
		epoch[i] = Epoch{ID: ids[i], AnonID: []byte(anon(i)), RootKey: randomBytes(32)}
	}
	server := make([]SyncEpoch, 6)
	for i := 1; i <= 5; i++ {
		server[i] = SyncEpoch{ID: ids[i], BackupID: fixtureBackupID, AnonID: anon(i)}
		if i > 1 {
			server[i].PreviousID = ids[i-1]
		}
		if i < 5 {
			server[i].NextID = ids[i+1]
		}
	}
	for i := 2; i <= 3; i++ {
		k := epochKey(epoch[i])
		server[i].EncryptedData = &struct {
			AnonID  []byte `json:"epoch_anon_id"`
			RootKey []byte `json:"epoch_root_key"`
		}{
			AnonID:  sealB64(k, epoch[i-1].AnonID, "epoch_data_metadata"),
			RootKey: sealB64(k, epoch[i-1].RootKey, "epoch_data_metadata"),
		}
	}
	for i := 4; i <= 5; i++ {
		auth := newKeyPair()
		server[i].AuthPublicKey = auth.pub
		server[i].EncryptedKey = encryptPublic(storage.pub, auth, chain(epoch[i-1])[32:], []byte("epoch__"+anon(i)), randomBytes(32))
		epoch[i], err = deriveNextEpoch(epoch[i-1], server[i], storage.pub, storage.priv, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	server[5].Active = true
	server[5].Minos = &MinosEpoch{Head: randomBytes(32), SelfSignature: randomBytes(64)}
	ocmfState := ristretto255.NewScalar()
	if _, err = ocmfState.SetUniformBytes(randomBytes(64)); err != nil {
		t.Fatal(err)
	}
	info := &VirtualDeviceInfo{
		Secrets: &EncryptedSecrets{
			EpochAnonID:              sealB64(blobKey, epoch[3].AnonID, "virtual_device:epoch_anon_id"),
			EpochRootKey:             sealB64(blobKey, epoch[3].RootKey, "secret_values_metadata"),
			EpochStoragePrivateKey:   sealB64(blobKey, storage.priv, "virtual_device:epoch_storage_private_key"),
			MailboxRootKey:           sealB64(blobKey, randomBytes(32), "virtual_device:mailbox_root_key"),
			ObliviousValidationToken: sealB64(blobKey, randomBytes(48), "virtual_device:oblivious_validation_token"),
			OCMFClientState:          sealB64(blobKey, ocmfState.Bytes(), "secret_values_metadata"),
			ORFClientState:           sealB64(blobKey, randomBytes(48), "virtual_device:orf_client_state"),
		},
		EpochID:               ids[3],
		EpochStoragePublicKey: storage.pub,
		LastEpochID:           ids[5],
		Epochs:                server[1:],
		Minos:                 server[5].Minos,
	}
	info.Edges = append(info.Edges, struct {
		From struct {
			ID string `json:"epoch_id"`
		} `json:"from_epoch"`
		BackwardEdge []byte `json:"backward_edge"`
	}{BackwardEdge: randomBytes(16)})
	info.Edges[0].From.ID = ids[2]
	vd := &VirtualDevice{ID: id, BlobKey: blobKey, Info: info}
	epochs, err := vd.DeriveEpochs()
	if err != nil {
		t.Fatal(err)
	}
	out["virtual_device"] = map[string]any{"code": codeV2, "user_id": fixtureUserID, "id": id, "blob_key": blobKey, "info": info, "epochs": epochs}

	// What DeriveEpochs rejects, each a change to the good device info.
	var deriveFailures []failure
	broken := func(name string, change func(*VirtualDeviceInfo)) {
		bad := clone(info)
		change(bad)
		_, err := (&VirtualDevice{ID: id, BlobKey: blobKey, Info: bad}).DeriveEpochs()
		deriveFailures = append(deriveFailures, failure{name, bad, errText(err)})
	}
	byID := func(info *VirtualDeviceInfo, id string) *SyncEpoch {
		for i := range info.Epochs {
			if info.Epochs[i].ID == id {
				return &info.Epochs[i]
			}
		}
		panic(id)
	}
	broken("no base epoch id", func(i *VirtualDeviceInfo) { i.EpochID = "" })
	broken("no secrets", func(i *VirtualDeviceInfo) { i.Secrets = nil })
	broken("anon id is not digits", func(i *VirtualDeviceInfo) {
		i.Secrets.EpochAnonID = sealB64(blobKey, []byte("10a"), "secret_values_metadata")
	})
	broken("anon id too long", func(i *VirtualDeviceInfo) {
		i.Secrets.EpochAnonID = sealB64(blobKey, []byte("123456789012"), "secret_values_metadata")
	})
	broken("root key under a foreign aad", func(i *VirtualDeviceInfo) {
		i.Secrets.EpochRootKey = sealB64(blobKey, epoch[3].RootKey, "virtual_device:other")
	})
	broken("short root key", func(i *VirtualDeviceInfo) {
		i.Secrets.EpochRootKey = sealB64(blobKey, epoch[3].RootKey[:31], "secret_values_metadata")
	})
	broken("last epoch unreachable", func(i *VirtualDeviceInfo) { i.LastEpochID = "910000000000999" })
	broken("forward epoch missing", func(i *VirtualDeviceInfo) { i.Epochs = append(i.Epochs[:3], i.Epochs[4]) })
	broken("forward cycle", func(i *VirtualDeviceInfo) { byID(i, ids[4]).NextID = ids[3] })
	broken("foreign storage public key", func(i *VirtualDeviceInfo) { i.EpochStoragePublicKey = newKeyPair().pub })
	broken("tampered forward entropy", func(i *VirtualDeviceInfo) { byID(i, ids[4]).EncryptedKey[40] ^= 1 })
	broken("forward anon id invalid", func(i *VirtualDeviceInfo) { byID(i, ids[4]).AnonID = "abc" })
	broken("backward cycle", func(i *VirtualDeviceInfo) { byID(i, ids[1]).PreviousID = ids[3] })
	broken("backward data missing", func(i *VirtualDeviceInfo) { byID(i, ids[2]).EncryptedData = nil })
	broken("backward epoch missing", func(i *VirtualDeviceInfo) { byID(i, ids[2]).PreviousID = "910000000000099" })
	broken("tampered backward root key", func(i *VirtualDeviceInfo) { byID(i, ids[3]).EncryptedData.RootKey[30] ^= 1 })
	broken("backward root key short", func(i *VirtualDeviceInfo) {
		byID(i, ids[3]).EncryptedData.RootKey = sealB64(epochKey(epoch[3]), epoch[2].RootKey[:16], "epoch_data_metadata")
	})
	out["derive_epochs_failures"] = deriveFailures

	// applyEpochs on an enrolled device holding epoch 105: forward to 106, then on to 107 from
	// the epoch the first edge added, and backward to 104.
	devStorage := newKeyPair()
	device := &Device{
		ID: "500000000000001", BackupID: fixtureBackupID,
		StoragePublicKey: devStorage.pub, StoragePrivateKey: devStorage.priv,
		MailboxRootKey: randomBytes(32), OCMFClientState: ocmfState.Bytes(),
		Epochs: map[string]Epoch{ids[5]: epoch[5]},
	}
	forward := func(from Epoch, toID, toAnon string) (EpochEdge, Epoch) {
		auth := newKeyPair()
		c := chain(from)
		next := SyncEpoch{ID: toID, AnonID: toAnon, AuthPublicKey: auth.pub,
			EncryptedKey: encryptPublic(devStorage.pub, auth, c[32:], []byte("epoch__"+toAnon), randomBytes(32))}
		to, err := deriveNextEpoch(from, next, devStorage.pub, devStorage.priv, "")
		if err != nil {
			t.Fatal(err)
		}
		return EpochEdge{
			From: EpochRef{ID: from.ID, AnonID: b64(string(from.AnonID))},
			To:   EpochRef{ID: toID, AnonID: b64(toAnon)},
			Forward: &EpochForwardEdge{AuthPublicKey: auth.pub, EncryptedEntropy: next.EncryptedKey,
				EntropyFingerprint: "unused", StoragePublicKey: devStorage.pub,
				PSKFingerprint: fingerprint(c[32:], "MEBCryptoPreSharedKey")},
			FromFingerprint: fingerprint(from.RootKey, "MEBEpochRootKey"),
			ToFingerprint:   fingerprint(to.RootKey, "MEBEpochRootKey"),
		}, to
	}
	edge6, epoch6 := forward(epoch[5], "910000000000106", "106")
	edge7, _ := forward(epoch6, "910000000000107", "107")
	edge4 := EpochEdge{
		From:            EpochRef{ID: ids[5], AnonID: b64("105")},
		To:              EpochRef{ID: ids[4], AnonID: b64("104")},
		Backward:        sealB64(epochKey(epoch[5]), epoch[4].RootKey, "epoch_data_metadata"),
		FromFingerprint: fingerprint(epoch[5].RootKey, "MEBEpochRootKey"),
		ToFingerprint:   fingerprint(epoch[4].RootKey, "MEBEpochRootKey"),
	}
	set := &EpochDerivationSet{Edges: []EpochEdge{edge6, edge7, edge4}}
	applied, err := device.WithEpochs(set)
	if err != nil {
		t.Fatal(err)
	}
	out["apply_epochs"] = map[string]any{"device": device, "set": set, "result": applied}

	var applyFailures []failure
	brokenEdge := func(name string, base EpochEdge, change func(*EpochEdge)) {
		edge := clone(base)
		change(&edge)
		bad := &EpochDerivationSet{Edges: []EpochEdge{edge}}
		_, err := device.WithEpochs(bad)
		applyFailures = append(applyFailures, failure{name, bad, errText(err)})
	}
	brokenEdge("source missing", edge7, func(e *EpochEdge) {})
	brokenEdge("source anon id differs", edge6, func(e *EpochEdge) { e.From.AnonID = b64("104") })
	brokenEdge("source fingerprint differs", edge6, func(e *EpochEdge) { e.FromFingerprint = edge4.ToFingerprint })
	brokenEdge("destination anon id not base64", edge6, func(e *EpochEdge) { e.To.AnonID = "%%%" })
	brokenEdge("destination anon id not digits", edge6, func(e *EpochEdge) { e.To.AnonID = b64("1x6") })
	brokenEdge("destination id empty", edge6, func(e *EpochEdge) { e.To.ID = "" })
	brokenEdge("destination fingerprint differs", edge6, func(e *EpochEdge) { e.ToFingerprint = edge6.FromFingerprint })
	brokenEdge("forward skips a sequence", edge6, func(e *EpochEdge) { e.To.AnonID = b64("107") })
	brokenEdge("forward to a foreign storage key", edge6, func(e *EpochEdge) { e.Forward.StoragePublicKey = newKeyPair().pub })
	brokenEdge("forward without psk fingerprint", edge6, func(e *EpochEdge) { e.Forward.PSKFingerprint = "" })
	brokenEdge("forward psk fingerprint differs", edge6, func(e *EpochEdge) { e.Forward.PSKFingerprint = edge6.ToFingerprint })
	brokenEdge("forward envelope tampered", edge6, func(e *EpochEdge) { e.Forward.EncryptedEntropy[50] ^= 1 })
	brokenEdge("forward envelope version", edge6, func(e *EpochEdge) { e.Forward.EncryptedEntropy[0] = 2 })
	brokenEdge("forward envelope short", edge6, func(e *EpochEdge) { e.Forward.EncryptedEntropy = e.Forward.EncryptedEntropy[:48] })
	brokenEdge("forward auth key short", edge6, func(e *EpochEdge) { e.Forward.AuthPublicKey = e.Forward.AuthPublicKey[:31] })
	brokenEdge("forward auth key of small order", edge6, func(e *EpochEdge) { e.Forward.AuthPublicKey = make([]byte, 32) })
	brokenEdge("backward skips a sequence", edge4, func(e *EpochEdge) { e.To.AnonID = b64("103") })
	brokenEdge("backward edge empty", edge4, func(e *EpochEdge) { e.Backward = nil })
	brokenEdge("backward edge tampered", edge4, func(e *EpochEdge) { e.Backward[40] ^= 1 })
	out["apply_epochs_failures"] = applyFailures

	// PrepareDevice, with every random draw recorded. The armadillo private key is left
	// unclamped on purpose: Baileys stores them that way, and signing clamps.
	armadilloPriv := randomBytes(32)
	armadilloPriv[0] |= 7
	armadillo := keys.NewKeyPairFromPrivateKey(*(*[32]byte)(armadilloPriv))
	var stream []byte
	t.Run("capture", func(t *testing.T) {
		cryptotest.SetGlobalRandom(t, 2)
		// evolveOCMF's factor, three key pairs, four signatures, the trace UUID.
		for _, n := range []int{64, 32, 32, 32, 64, 64, 64, 64, 16} {
			stream = append(stream, randomBytes(n)...)
		}
	})
	var enrollment *Enrollment
	t.Run("prepare", func(t *testing.T) {
		cryptotest.SetGlobalRandom(t, 2)
		enrollment, err = vd.PrepareDevice(fixtureBackupID, fixtureRegID, armadillo, epochs)
		if err != nil {
			t.Fatal(err)
		}
	})
	if enrollment == nil {
		t.FailNow()
	}
	out["prepare_device"] = map[string]any{
		"backup_id": fixtureBackupID, "registration_id": fixtureRegID,
		"armadillo_private": armadilloPriv, "armadillo_public": armadillo.Pub[:],
		"random": stream, "device": enrollment.Device, "info": enrollment.Info,
	}

	var prepareFailures []failure
	brokenPrepare := func(name, backupID, regID string, epochs map[string]Epoch, change func(*VirtualDeviceInfo)) {
		bad := clone(info)
		change(bad)
		_, err := (&VirtualDevice{ID: id, BlobKey: blobKey, Info: bad}).PrepareDevice(backupID, regID, armadillo, epochs)
		prepareFailures = append(prepareFailures, failure{name, map[string]any{
			"backup_id": backupID, "registration_id": regID, "epochs": epochs, "info": bad}, errText(err)})
	}
	same := func(*VirtualDeviceInfo) {}
	brokenPrepare("no backup id", "", fixtureRegID, epochs, same)
	brokenPrepare("no registration id", fixtureBackupID, "", epochs, same)
	brokenPrepare("latest epoch missing", fixtureBackupID, fixtureRegID, map[string]Epoch{ids[4]: epochs[ids[4]]}, same)
	brokenPrepare("no secrets", fixtureBackupID, fixtureRegID, epochs, func(i *VirtualDeviceInfo) { i.Secrets = nil })
	brokenPrepare("mailbox key unreadable", fixtureBackupID, fixtureRegID, epochs, func(i *VirtualDeviceInfo) {
		i.Secrets.MailboxRootKey = sealB64(blobKey, randomBytes(32), "virtual_device:other")
	})
	brokenPrepare("ocmf state zero", fixtureBackupID, fixtureRegID, epochs, func(i *VirtualDeviceInfo) {
		i.Secrets.OCMFClientState = sealB64(blobKey, make([]byte, 32), "secret_values_metadata")
	})
	brokenPrepare("ocmf state not canonical", fixtureBackupID, fixtureRegID, epochs, func(i *VirtualDeviceInfo) {
		v := make([]byte, 32)
		for j := range v {
			v[j] = 0xff
		}
		i.Secrets.OCMFClientState = sealB64(blobKey, v, "secret_values_metadata")
	})
	brokenPrepare("ocmf state short", fixtureBackupID, fixtureRegID, epochs, func(i *VirtualDeviceInfo) {
		i.Secrets.OCMFClientState = sealB64(blobKey, ocmfState.Bytes()[:31], "secret_values_metadata")
	})
	out["prepare_device_failures"] = prepareFailures

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("FIXTURE_OUT")
	if path == "" {
		path = "/out/securehistory_device.json"
	}
	if err = os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
