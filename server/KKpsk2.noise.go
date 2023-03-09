/*
KKpsk2:
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se, psk
  ->
  <-
*/

// Implementation Version: 1.0.3

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

type keypair struct {
	public  [32]byte
	private [32]byte
}

func (kp keypair) String() string {
	return fmt.Sprintf("Private Key: %x\nPublic Key: %x\n", kp.private, kp.public)
}

type secret struct {
	static       keypair
	remotePublic [32]byte
	preShared    [32]byte
}

// 3 * 32-byte keys (static private, remote public, pre-shared), and the crc32 checksum
const secretBytesLength = 3*32 + 4

var (
	base64URL          = base64.URLEncoding
	binaryLE           = binary.LittleEndian
	crc32Checksum      = crc32.ChecksumIEEE
	secretBase64Length = base64URL.EncodedLen(secretBytesLength)
	secretHexLength    = hex.EncodedLen(secretBytesLength)
)

func crc32KChecksum(b []byte) uint32 {
	return crc32.Checksum(b, crc32.MakeTable(crc32.Koopman))
}

func (s secret) secretBytes() []byte {
	combined := make([]byte, 0, secretBytesLength)
	combined = append(combined, s.static.private[:]...)
	combined = append(combined, s.remotePublic[:]...)
	combined = append(combined, s.preShared[:]...)

	combined = binaryLE.AppendUint32(
		combined,
		crc32Checksum(combined),
	)

	return combined
}

func (s secret) EncodeHex() []byte {
	combined := s.secretBytes()

	out := make([]byte, secretHexLength)
	hex.Encode(out, combined)
	return out
}

func (s secret) EncodeBase64() []byte {
	combined := s.secretBytes()

	out := make([]byte, secretBase64Length)
	base64URL.Encode(out, combined)

	return out
}

func (s secret) String() string {
	return string(s.EncodeHex())
}

func verifySecretCRC(b []byte) error {
	checksum1 := binaryLE.Uint32(b[96:])
	checksum2 := crc32Checksum(b[0:96])

	if checksum1 != checksum2 {
		return errors.New("checksum does not match")
	}
	return nil
}

func decodeSecretBytes(b []byte) (secret, error) {
	if len(b) != secretBytesLength {
		return secret{}, fmt.Errorf("incorrect length: got %d, wanted %d", len(b), secretBytesLength)
	}

	if err := verifySecretCRC(b); err != nil {
		return secret{}, err
	}

	privateKey := [32]byte(b[0:32])

	return secret{
		static: keypair{
			public:  generatePublicKey(privateKey),
			private: privateKey,
		},
		remotePublic: [32]byte(b[32:64]),
		preShared:    [32]byte(b[64:96]),
	}, nil
}

func DecodeSecretHex(s []byte) (secret, error) {
	secretBytes := make([]byte, secretBytesLength)

	_, err := hex.Decode(secretBytes, s)
	if err != nil {
		return secret{}, fmt.Errorf("decoding hex error: %w", err)
	}

	return decodeSecretBytes(secretBytes)
}

func DecodeSecretBase64(s []byte) (secret, error) {
	secretBytes := make([]byte, secretBytesLength)

	_, err := base64URL.Decode(secretBytes, s)
	if err != nil {
		return secret{}, fmt.Errorf("decoding hex error: %w", err)
	}

	return decodeSecretBytes(secretBytes)
}

func DecodeSecret(s []byte) (secret, error) {
	switch len(s) {
	case secretBase64Length:
		return DecodeSecretBase64(s)
	case secretHexLength:
		return DecodeSecretHex(s)
	default:
		return secret{}, fmt.Errorf("invalid secret length: %d", len(s))
	}
}

type messagebuffer struct {
	ne         [32]byte
	ns         []byte
	ciphertext []byte
}

type cipherstate struct {
	k [32]byte
	n uint64
}

type symmetricstate struct {
	cs cipherstate
	ck [32]byte
	h  [32]byte
}

type handshakestate struct {
	ss  symmetricstate
	s   keypair
	e   keypair
	rs  [32]byte
	re  [32]byte
	psk [32]byte
}

type noisesession struct {
	hs  handshakestate
	h   [32]byte
	cs1 cipherstate
	cs2 cipherstate
	mc  uint64
	i   bool
}

/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */

var emptyKey = [32]byte{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var minNonce = uint64(0)

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

func getPublicKey(kp *keypair) [32]byte {
	return kp.public
}

func isEmptyKey(k [32]byte) bool {
	return subtle.ConstantTimeCompare(k[:], emptyKey[:]) == 1
}

func validatePublicKey(k [32]byte) bool {
	forbiddenCurveValues := [12][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128},
		{76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215},
		{217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 25},
	}

	for _, testValue := range forbiddenCurveValues {
		if subtle.ConstantTimeCompare(k[:], testValue[:]) == 1 {
			panic("Invalid public key")
		}
	}
	return true
}

/* ---------------------------------------------------------------- *
 * PRIMITIVES                                                       *
 * ---------------------------------------------------------------- */

func incrementNonce(n uint64) uint64 {
	return n + 1
}

func dh(private_key [32]byte, public_key [32]byte) [32]byte {
	var ss [32]byte
	curve25519.ScalarMult(&ss, &private_key, &public_key)
	return ss
}

func generateKey() [32]byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k
}

func generateKeypair() keypair {
	privateKey := generateKey()
	publicKey := generatePublicKey(privateKey)

	if validatePublicKey(publicKey) {
		return keypair{publicKey, privateKey}
	}
	return generateKeypair()
}

func generatePublicKey(privateKey [32]byte) [32]byte {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

func encrypt(k [32]byte, n uint64, ad []byte, plaintext []byte) []byte {
	var nonce [12]byte
	var ciphertext []byte
	enc, _ := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint64(nonce[4:], n)
	ciphertext = enc.Seal(nil, nonce[:], plaintext, ad)
	return ciphertext
}

func decrypt(k [32]byte, n uint64, ad []byte, ciphertext []byte) (bool, []byte, []byte) {
	var nonce [12]byte
	var plaintext []byte
	enc, err := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint64(nonce[4:], n)
	plaintext, err = enc.Open(nil, nonce[:], ciphertext, ad)
	return (err == nil), ad, plaintext
}

func getHash(a []byte, b []byte) [32]byte {
	return blake2s.Sum256(append(a, b...))
}

func hashProtocolName(protocolName []byte) [32]byte {
	var h [32]byte
	if len(protocolName) <= 32 {
		copy(h[:], protocolName)
	} else {
		h = getHash(protocolName, []byte{})
	}
	return h
}

func blake2HkdfInterface() hash.Hash {
	h, _ := blake2s.New256([]byte{})
	return h
}

func getHkdf(ck [32]byte, ikm []byte) ([32]byte, [32]byte, [32]byte) {
	var k1 [32]byte
	var k2 [32]byte
	var k3 [32]byte
	output := hkdf.New(blake2HkdfInterface, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	return k1, k2, k3
}

/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */

/* CipherState */
func initializeKey(k [32]byte) cipherstate {
	return cipherstate{k, minNonce}
}

func hasKey(cs *cipherstate) bool {
	return !isEmptyKey(cs.k)
}

func setNonce(cs *cipherstate, newNonce uint64) *cipherstate {
	cs.n = newNonce
	return cs
}

func encryptWithAd(cs *cipherstate, ad []byte, plaintext []byte) (*cipherstate, []byte, error) {
	var err error
	if cs.n == math.MaxUint64-1 {
		err = errors.New("encryptWithAd: maximum nonce size reached")
		return cs, []byte{}, err
	}
	e := encrypt(cs.k, cs.n, ad, plaintext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, e, err
}

func decryptWithAd(cs *cipherstate, ad []byte, ciphertext []byte) (*cipherstate, []byte, bool, error) {
	var err error
	if cs.n == math.MaxUint64-1 {
		err = errors.New("decryptWithAd: maximum nonce size reached")
		return cs, []byte{}, false, err
	}
	valid, ad, plaintext := decrypt(cs.k, cs.n, ad, ciphertext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, plaintext, valid, err
}

func reKey(cs *cipherstate) *cipherstate {
	e := encrypt(cs.k, math.MaxUint64, []byte{}, emptyKey[:])
	copy(cs.k[:], e)
	return cs
}

/* SymmetricState */

func initializeSymmetric(protocolName []byte) symmetricstate {
	h := hashProtocolName(protocolName)
	ck := h
	cs := initializeKey(emptyKey)
	return symmetricstate{cs, ck, h}
}

func mixKey(ss *symmetricstate, ikm [32]byte) *symmetricstate {
	ck, tempK, _ := getHkdf(ss.ck, ikm[:])
	ss.cs = initializeKey(tempK)
	ss.ck = ck
	return ss
}

func mixHash(ss *symmetricstate, data []byte) *symmetricstate {
	ss.h = getHash(ss.h[:], data)
	return ss
}

func mixKeyAndHash(ss *symmetricstate, ikm [32]byte) *symmetricstate {
	var tempH [32]byte
	var tempK [32]byte
	ss.ck, tempH, tempK = getHkdf(ss.ck, ikm[:])
	ss = mixHash(ss, tempH[:])
	ss.cs = initializeKey(tempK)
	return ss
}

func getHandshakeHash(ss *symmetricstate) [32]byte {
	return ss.h
}

func encryptAndHash(ss *symmetricstate, plaintext []byte) (*symmetricstate, []byte, error) {
	var ciphertext []byte
	var err error
	if hasKey(&ss.cs) {
		_, ciphertext, err = encryptWithAd(&ss.cs, ss.h[:], plaintext)
		if err != nil {
			return ss, []byte{}, err
		}
	} else {
		ciphertext = plaintext
	}
	ss = mixHash(ss, ciphertext)
	return ss, ciphertext, err
}

func decryptAndHash(ss *symmetricstate, ciphertext []byte) (*symmetricstate, []byte, bool, error) {
	var plaintext []byte
	var valid bool
	var err error
	if hasKey(&ss.cs) {
		_, plaintext, valid, err = decryptWithAd(&ss.cs, ss.h[:], ciphertext)
		if err != nil {
			return ss, []byte{}, false, err
		}
	} else {
		plaintext, valid = ciphertext, true
	}
	ss = mixHash(ss, ciphertext)
	return ss, plaintext, valid, err
}

func split(ss *symmetricstate) (cipherstate, cipherstate) {
	tempK1, tempK2, _ := getHkdf(ss.ck, []byte{})
	cs1 := initializeKey(tempK1)
	cs2 := initializeKey(tempK2)
	return cs1, cs2
}

/* HandshakeState */

func initializeInitiator(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	mixHash(&ss, s.public[:])
	mixHash(&ss, rs[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func initializeResponder(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	mixHash(&ss, rs[:])
	mixHash(&ss, s.public[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func writeMessageA(hs *handshakestate, payload []byte) (*handshakestate, messagebuffer, error) {
	var err error
	var messageBuffer messagebuffer
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = generateKeypair()
	ne = hs.e.public
	mixHash(&hs.ss, ne[:])
	mixKey(&hs.ss, hs.e.public)
	mixKey(&hs.ss, dh(hs.e.private, hs.rs))
	mixKey(&hs.ss, dh(hs.s.private, hs.rs))
	_, ciphertext, err = encryptAndHash(&hs.ss, payload)
	if err != nil {
		return hs, messageBuffer, err
	}
	messageBuffer = messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer, err
}

func writeMessageB(hs *handshakestate, payload []byte) ([32]byte, messagebuffer, cipherstate, cipherstate, error) {
	var err error
	var messageBuffer messagebuffer
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = generateKeypair()
	ne = hs.e.public
	mixHash(&hs.ss, ne[:])
	mixKey(&hs.ss, hs.e.public)
	mixKey(&hs.ss, dh(hs.e.private, hs.re))
	mixKey(&hs.ss, dh(hs.e.private, hs.rs))
	mixKeyAndHash(&hs.ss, hs.psk)
	_, ciphertext, err = encryptAndHash(&hs.ss, payload)
	if err != nil {
		cs1, cs2 := split(&hs.ss)
		return hs.ss.h, messageBuffer, cs1, cs2, err
	}
	messageBuffer = messagebuffer{ne, ns, ciphertext}
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, messageBuffer, cs1, cs2, err
}

func writeMessageRegular(cs *cipherstate, payload []byte) (*cipherstate, messagebuffer, error) {
	var err error
	var messageBuffer messagebuffer
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	cs, ciphertext, err = encryptWithAd(cs, []byte{}, payload)
	if err != nil {
		return cs, messageBuffer, err
	}
	messageBuffer = messagebuffer{ne, ns, ciphertext}
	return cs, messageBuffer, err
}

func readMessageA(hs *handshakestate, message *messagebuffer) (*handshakestate, []byte, bool, error) {
	var err error
	var plaintext []byte
	var valid2 bool = false
	var valid1 bool = true
	if validatePublicKey(message.ne) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	mixKey(&hs.ss, hs.re)
	mixKey(&hs.ss, dh(hs.s.private, hs.re))
	mixKey(&hs.ss, dh(hs.s.private, hs.rs))
	_, plaintext, valid2, err = decryptAndHash(&hs.ss, message.ciphertext)
	return hs, plaintext, (valid1 && valid2), err
}

func readMessageB(hs *handshakestate, message *messagebuffer) ([32]byte, []byte, bool, cipherstate, cipherstate, error) {
	var err error
	var plaintext []byte
	var valid2 bool = false
	var valid1 bool = true
	if validatePublicKey(message.ne) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	mixKey(&hs.ss, hs.re)
	mixKey(&hs.ss, dh(hs.e.private, hs.re))
	mixKey(&hs.ss, dh(hs.s.private, hs.re))
	mixKeyAndHash(&hs.ss, hs.psk)
	_, plaintext, valid2, err = decryptAndHash(&hs.ss, message.ciphertext)
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2, err
}

func readMessageRegular(cs *cipherstate, message *messagebuffer) (*cipherstate, []byte, bool, error) {
	var err error
	var plaintext []byte
	var valid2 bool = false
	/* No encrypted keys */
	_, plaintext, valid2, err = decryptWithAd(cs, []byte{}, message.ciphertext)
	return cs, plaintext, valid2, err
}

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func InitSession(initiator bool, prologue []byte, s keypair, rs [32]byte, psk [32]byte) noisesession {
	var session noisesession
	/* PSK defined by user */
	if initiator {
		session.hs = initializeInitiator(prologue, s, rs, psk)
	} else {
		session.hs = initializeResponder(prologue, s, rs, psk)
	}
	session.i = initiator
	session.mc = 0
	return session
}

func SendMessage(session *noisesession, message []byte) (*noisesession, messagebuffer, error) {
	var err error
	var messageBuffer messagebuffer
	if session.mc == 0 {
		_, messageBuffer, err = writeMessageA(&session.hs, message)
	}
	if session.mc == 1 {
		session.h, messageBuffer, session.cs1, session.cs2, err = writeMessageB(&session.hs, message)
		session.hs = handshakestate{}
	}
	if session.mc > 1 {
		if session.i {
			_, messageBuffer, err = writeMessageRegular(&session.cs1, message)
		} else {
			_, messageBuffer, err = writeMessageRegular(&session.cs2, message)
		}
	}
	session.mc = session.mc + 1
	return session, messageBuffer, err
}

func RecvMessage(session *noisesession, message *messagebuffer) (*noisesession, []byte, bool, error) {
	var err error
	var plaintext []byte
	var valid bool
	if session.mc == 0 {
		_, plaintext, valid, err = readMessageA(&session.hs, message)
	}
	if session.mc == 1 {
		session.h, plaintext, valid, session.cs1, session.cs2, err = readMessageB(&session.hs, message)
		session.hs = handshakestate{}
	}
	if session.mc > 1 {
		if session.i {
			_, plaintext, valid, err = readMessageRegular(&session.cs2, message)
		} else {
			_, plaintext, valid, err = readMessageRegular(&session.cs1, message)
		}
	}
	session.mc = session.mc + 1
	return session, plaintext, valid, err
}

func main() {
	server := generateKeypair()
	client := generateKeypair()
	psk := generateKey()

	serverSecret := secret{
		static:       server,
		remotePublic: client.public,
		preShared:    psk,
	}
	clientSecret := secret{
		static:       client,
		remotePublic: server.public,
		preShared:    psk,
	}

	ssb64 := serverSecret.EncodeBase64()
	csh := clientSecret.EncodeHex()

	fmt.Printf("Server Secret (%d): %s\n", len(ssb64), ssb64)
	fmt.Printf("Client Secret (%d): %s\n\n", len(csh), csh)

	decodedServer, err := DecodeSecret(ssb64)
	fmt.Printf("%#v\n%#v\nErr: %s\n", serverSecret, decodedServer, err)
	decodedClient, err := DecodeSecret(csh)
	fmt.Printf("%#v\n%#v\nErr: %s\n", clientSecret, decodedClient, err)
}