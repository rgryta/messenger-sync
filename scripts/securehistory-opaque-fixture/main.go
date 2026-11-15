// Builds crates/client/tests/fixtures/securehistory_opaque.json: OPAQUE PIN logins and Vesta
// recovery payloads as mautrix-meta's own `securehistory` code runs them, so the Rust port is
// checked against the implementation that talks to Meta's HSM today, not against a reading
// of the 2021 OPAQUE draft. Every key, PIN and payload is synthetic.
//
// A bytemare server (the library mautrix's client is built on) registers the PIN, the client
// is mautrix's `opaque.Login` with its randomness fixed, and `Finish`, `verifyHSMKey` and
// `unpackLoginPayload` are mautrix's own functions, reached through unsafe/linkname because
// they are not exported. The RSA root is generated per run, so its bytes change on every
// run; everything else is deterministic.
//
//	docker run --rm -v "$PWD/scripts/securehistory-opaque-fixture:/src" \
//	  -v <mautrix-meta checkout>:/meta:ro -v "$PWD/out:/out" -w /src golang:1.27-alpine \
//	  sh -c "go mod tidy && go run . > /out/securehistory_opaque.json"
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"unsafe"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	bytemare "github.com/bytemare/opaque"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-meta/pkg/messagix/securehistory"
	"go.mau.fi/mautrix-meta/pkg/messagix/securehistory/opaque"
)

//go:linkname verifyHSMKey go.mau.fi/mautrix-meta/pkg/messagix/securehistory.verifyHSMKey
func verifyHSMKey(key, signature []byte) bool

//go:linkname unpackLoginPayload go.mau.fi/mautrix-meta/pkg/messagix/securehistory.unpackLoginPayload
func unpackLoginPayload(payload, sessionKey, exportKey []byte) ([]byte, error)

var g = ciphersuite.Ristretto255Sha512.Get(nil)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// A canonical scalar derived from a label, as `Scalar.Random` would draw one.
func scalar(label string) []byte {
	h := sha512.Sum512([]byte(label))
	return ristretto255.NewScalar().FromUniformBytes(h[:]).Encode(nil)
}

func decodeScalar(b []byte) group.Scalar { return must(g.NewScalar().Decode(b)) }

func public(sk []byte) []byte { return g.Base().Mult(decodeScalar(sk)).Bytes() }

func fixed(label string, n int) []byte {
	h := sha512.Sum512([]byte(label))
	return h[:n]
}

var (
	blind       = scalar("client OPRF blind")
	clientEsk   = scalar("client ephemeral key")
	clientNonce = fixed("client nonce", 32)
	serverSk    = scalar("server AKE key")
	serverPk    = public(serverSk)
	oprfKey     = scalar("server OPRF key")
)

// The client exactly as mautrix's opaque.Begin builds it.
func newClient() *bytemare.Client {
	hardener := mhf.PBKDF2Sha512.Get()
	hardener.Parameterize(100_000)
	return bytemare.NewClient(voprf.RistrettoSha512, hash.SHA512, hash.SHA512, hash.SHA512,
		hardener, envelope.Base, ciphersuite.Ristretto255Sha512)
}

func newServer() *bytemare.Server {
	return bytemare.NewServer(voprf.RistrettoSha512, hash.SHA512, hash.SHA512, hash.SHA512, ciphersuite.Ristretto255Sha512)
}

type account struct {
	clientPk []byte
	env      *envelope.Envelope
}

// Registers pin with the client key clientSk, hardening the OPRF output as mautrix's login
// expects (bytemare's own registration does not).
func register(pin, clientSk, clientPk []byte) account {
	c := newClient()
	must(c.Core.Oprf.BlindBatchWithBlinds([][]byte{scalar("registration blind")}, [][]byte{pin}))
	req := c.RegistrationStart(pin) // reuses the blind set above
	resp, _, err := newServer().RegistrationResponse(req, serverPk, oprfKey)
	if err != nil {
		panic(err)
	}
	output := must(c.Core.Oprf.Finalize(&voprf.Evaluation{Elements: [][]byte{resp.Data}}))
	hardened := c.Core.Harden(output, []byte("OPAQUE_PBKDF2_SALT"), 64)
	env, _, err := c.Core.BuildEnvelopeNew(hardened, resp.Pks, envelope.Base, &envelope.Credentials{
		Sk: clientSk, Pk: clientPk, Nonce: fixed("envelope nonce", 32),
	})
	if err != nil {
		panic(err)
	}
	return account{clientPk: clientPk, env: env}
}

// mautrix's opaque.Begin with the blind, ephemeral key and nonce fixed.
func begin(pin []byte) (*opaque.Login, []byte) {
	c := newClient()
	c.Ake.Initialize(decodeScalar(clientEsk), clientNonce, 32)
	must(c.Core.Oprf.BlindBatchWithBlinds([][]byte{blind}, [][]byte{bytes.Clone(pin)}))
	ke1 := c.AuthenticationStart(bytes.Clone(pin), nil).Serialize() // reuses blind, key and nonce
	login := &opaque.Login{}
	// Login's only field is the unexported *bytemare.Client.
	*(**bytemare.Client)(unsafe.Pointer(login)) = c
	return login, ke1
}

func respond(acc account, ke1, info []byte) (*bytemare.Server, []byte) {
	server := newServer()
	server.Ake.Initialize(decodeScalar(scalar("server ephemeral key")), fixed("server nonce", 32), 32)
	// By hand: this bytemare's DeserializeKE1 drops the nonce.
	if len(ke1) != 98 || ke1[64] != 0 || ke1[65] != 0 {
		panic("unexpected KE1 layout")
	}
	k1 := &message.KE1{
		CredentialRequest: &message.CredentialRequest{Data: ke1[:32]},
		NonceU:            ke1[32:64],
		EpkU:              ke1[66:],
	}
	ke2, err := server.AuthenticationResponse(k1, info,
		&bytemare.CredentialFile{Ku: oprfKey, Pku: acc.clientPk, Envelope: acc.env},
		&envelope.Credentials{Sk: serverSk, Pk: serverPk})
	if err != nil {
		panic(err)
	}
	return server, ke2.Serialize()
}

type Login struct {
	Name       string `json:"name"`
	PIN        string `json:"pin"`
	KE1        string `json:"ke1"`
	KE2        string `json:"ke2"`
	KE3        string `json:"ke3"`
	SessionKey string `json:"sessionKey"`
	ExportKey  string `json:"exportKey"`
}

type Failure struct {
	Name       string `json:"name"`
	PIN        string `json:"pin"`
	KE2        string `json:"ke2"`
	Error      string `json:"error"`
	InvalidPIN bool   `json:"invalidPin"`
}

type Payload struct {
	Name       string `json:"name"`
	Payload    string `json:"payload"`
	SessionKey string `json:"sessionKey"`
	ExportKey  string `json:"exportKey"`
	Code       string `json:"code,omitempty"`
	Error      string `json:"error,omitempty"`
}

func seal(key, nonce, plaintext []byte) []byte {
	aead := must(cipher.NewGCM(must(aes.NewCipher(key[:16]))))
	return aead.Seal(nil, nonce, plaintext, nil)
}

func main() {
	const pin = "123456"
	x := hex.EncodeToString
	acc := register([]byte(pin), scalar("client AKE key"), public(scalar("client AKE key")))

	out := struct {
		Blind       string    `json:"blind"`
		ClientEsk   string    `json:"clientEsk"`
		ClientNonce string    `json:"clientNonce"`
		Logins      []Login   `json:"logins"`
		Failures    []Failure `json:"failures"`
		HSM         struct {
			Root           string `json:"root"`
			Key            string `json:"key"`
			Signature      string `json:"signature"`
			RealRootsAgree bool   `json:"realRootsAgree"`
		} `json:"hsm"`
		L2 struct {
			Key          string `json:"key"`
			L2           string `json:"l2"`
			Signature    string `json:"signature"`
			BadSignature string `json:"badSignature"`
		} `json:"l2"`
		Payloads []Payload `json:"payloads"`
	}{Blind: x(blind), ClientEsk: x(clientEsk), ClientNonce: x(clientNonce)}

	var goodKE1, goodKE2, sessionKey, exportKey []byte
	for _, c := range []struct{ name, info string }{{"login", ""}, {"login with server info", "synthetic server info"}} {
		login, ke1 := begin([]byte(pin))
		server, ke2 := respond(acc, ke1, []byte(c.info))
		result := must(login.Finish(ke2))
		if server.AuthenticationFinalize(&message.KE3{Mac: result.Message}) != nil || !bytes.Equal(server.SessionKey(), result.SessionKey) {
			panic("server disagrees with the client")
		}
		out.Logins = append(out.Logins, Login{c.name, pin, x(ke1), x(ke2), x(result.Message), x(result.SessionKey), x(result.ExportKey)})
		if c.info == "" {
			goodKE1, goodKE2, sessionKey, exportKey = ke1, ke2, result.SessionKey, result.ExportKey
		}
	}

	tamper := func(f func(b []byte)) []byte {
		b := bytes.Clone(goodKE2)
		f(b)
		return b
	}
	_, wrongKE1 := begin([]byte("654321"))
	_, wrongKE2 := respond(acc, wrongKE1, nil)
	badKeyAcc := register([]byte(pin), bytes.Repeat([]byte{0xff}, 32), public(scalar("other client key")))
	_, badKeyKE1 := begin([]byte(pin))
	_, badKeyKE2 := respond(badKeyAcc, badKeyKE1, nil)
	failures := []struct {
		name, pin string
		ke2       []byte
	}{
		{"wrong pin", "654321", wrongKE2},
		{"tampered server mac", pin, tamper(func(b []byte) { b[len(b)-1] ^= 1 })},
		{"tampered envelope tag", pin, tamper(func(b []byte) { b[129] ^= 1 })},
		{"tampered encrypted client key", pin, tamper(func(b []byte) { b[97] ^= 1 })},
		{"truncated", pin, goodKE2[:322]},
		{"too long", pin, append(bytes.Clone(goodKE2), 0)},
		{"wrong envelope mode", pin, tamper(func(b []byte) { b[64] = 2 })},
		{"info length mismatch", pin, tamper(func(b []byte) { b[258] = 1 })},
		{"identity evaluation", pin, tamper(func(b []byte) { copy(b[:32], make([]byte, 32)) })},
		{"undecodable server key", pin, tamper(func(b []byte) { copy(b[32:64], bytes.Repeat([]byte{0xff}, 32)) })},
		{"identity server ephemeral key", pin, tamper(func(b []byte) { copy(b[225:257], make([]byte, 32)) })},
		{"reflected evaluation", pin, tamper(func(b []byte) { copy(b[:32], goodKE1[:32]) })},
		{"non-canonical client key", pin, badKeyKE2},
	}
	for _, f := range failures {
		login, _ := begin([]byte(f.pin))
		_, err := login.Finish(f.ke2)
		if err == nil {
			panic("expected a failure: " + f.name)
		}
		out.Failures = append(out.Failures, Failure{f.name, f.pin, x(f.ke2), err.Error(), errors.Is(err, opaque.ErrInvalidPIN)})
	}

	// HSM key: a synthetic root signs the island key; mautrix's check (real roots) refuses it.
	root := must(rsa.GenerateKey(rand.Reader, 3072))
	islandKey := ed25519.NewKeyFromSeed(fixed("synthetic island key", 32))
	islandPub := []byte(islandKey.Public().(ed25519.PublicKey))
	digest := sha256.Sum256(islandPub)
	sig := must(rsa.SignPKCS1v15(nil, root, crypto.SHA256, digest[:]))
	if rsa.VerifyPKCS1v15(&root.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		panic("synthetic root does not verify")
	}
	out.HSM.Root = base64.StdEncoding.EncodeToString(must(x509.MarshalPKIXPublicKey(&root.PublicKey)))
	out.HSM.Key = x(islandPub)
	out.HSM.Signature = x(sig)
	out.HSM.RealRootsAgree = verifyHSMKey(islandPub, sig)

	// L2: the island key signs [2] ++ KE2, as vestaBegin returns it.
	signed := append([]byte{2}, goodKE2...)
	l2Sig := ed25519.Sign(islandKey, signed)
	badSig := ed25519.Sign(islandKey, goodKE2)
	if !ed25519.Verify(islandPub, signed, l2Sig) || ed25519.Verify(islandPub, signed, badSig) {
		panic("l2 signature check")
	}
	out.L2.Key, out.L2.L2, out.L2.Signature, out.L2.BadSignature = x(islandPub), x(goodKE2), x(l2Sig), x(badSig)

	// Login payloads sealed under the login's keys, opened by mautrix's unpackLoginPayload.
	code := fixed("synthetic recovery code", 32)
	kNonce, rkNonce := fixed("k nonce", 12), fixed("rk nonce", 12)
	inner := must(proto.Marshal(&securehistory.WaBackupKeyData{AesK: seal(exportKey, kNonce, code), KNonce: kNonce}))
	sealed := seal(sessionKey, rkNonce, inner)
	payload := must(proto.Marshal(&securehistory.LoginPayload{BackupKeyDataEncrypted: sealed, RkNonce: rkNonce}))
	shortNonce := must(proto.Marshal(&securehistory.LoginPayload{BackupKeyDataEncrypted: sealed, RkNonce: rkNonce[:8]}))
	cases := []struct {
		name                     string
		payload, session, export []byte
	}{
		{"payload", payload, sessionKey, exportKey},
		{"swapped keys", payload, exportKey, sessionKey},
		{"short session key", payload, sessionKey[:32], exportKey},
		{"short nonce", shortNonce, sessionKey, exportKey},
		{"not protobuf", []byte{0xff, 0xff, 0xff}, sessionKey, exportKey},
	}
	for _, c := range cases {
		p := Payload{Name: c.name, Payload: x(c.payload), SessionKey: x(c.session), ExportKey: x(c.export)}
		if got, err := unpackLoginPayload(c.payload, c.session, c.export); err != nil {
			p.Error = err.Error()
		} else {
			p.Code = x(got)
		}
		out.Payloads = append(out.Payloads, p)
	}
	if out.Payloads[0].Code != x(code) {
		panic("payload round trip")
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
