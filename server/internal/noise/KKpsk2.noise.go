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

package noise

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
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

type Keypair struct {
	Public  [32]byte
	Private [32]byte
}

func (kp Keypair) String() string {
	return fmt.Sprintf("Private Key: %x\nPublic Key: %x\n", kp.Private, kp.Public)
}

type Secret struct {
	Static       Keypair
	RemotePublic [32]byte
	PreShared    [32]byte
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

func (s Secret) secretBytes() []byte {
	combined := make([]byte, 0, secretBytesLength)
	combined = append(combined, s.Static.Private[:]...)
	combined = append(combined, s.RemotePublic[:]...)
	combined = append(combined, s.PreShared[:]...)

	combined = binaryLE.AppendUint32(
		combined,
		crc32Checksum(combined),
	)

	return combined
}

func (s Secret) EncodeHex() []byte {
	combined := s.secretBytes()

	out := make([]byte, secretHexLength)
	hex.Encode(out, combined)
	return out
}

func (s Secret) EncodeBase64() []byte {
	combined := s.secretBytes()

	out := make([]byte, secretBase64Length)
	base64URL.Encode(out, combined)

	return out
}

func (s Secret) String() string {
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

func decodeSecretBytes(b []byte) (Secret, error) {
	if len(b) != secretBytesLength {
		return Secret{}, fmt.Errorf("incorrect length: got %d, wanted %d", len(b), secretBytesLength)
	}

	if err := verifySecretCRC(b); err != nil {
		return Secret{}, err
	}

	privateKey := [32]byte(b[0:32])

	return Secret{
		Static: Keypair{
			Public:  generatePublicKey(privateKey),
			Private: privateKey,
		},
		RemotePublic: [32]byte(b[32:64]),
		PreShared:    [32]byte(b[64:96]),
	}, nil
}

func DecodeSecretHex(s []byte) (Secret, error) {
	secretBytes := make([]byte, secretBytesLength)

	_, err := hex.Decode(secretBytes, s)
	if err != nil {
		return Secret{}, fmt.Errorf("decoding hex error: %w", err)
	}

	return decodeSecretBytes(secretBytes)
}

func DecodeSecretBase64(s []byte) (Secret, error) {
	secretBytes := make([]byte, secretBytesLength)

	_, err := base64URL.Decode(secretBytes, s)
	if err != nil {
		return Secret{}, fmt.Errorf("decoding hex error: %w", err)
	}

	return decodeSecretBytes(secretBytes)
}

func DecodeSecret(s []byte) (Secret, error) {
	switch len(s) {
	case secretBase64Length:
		return DecodeSecretBase64(s)
	case secretHexLength:
		return DecodeSecretHex(s)
	default:
		return Secret{}, fmt.Errorf("invalid secret length: %d", len(s))
	}
}

type MessageType byte

const (
	MessageTypeInvalid             MessageType = 0
	MessageTypeHandshakeInitiation MessageType = 1
	MessageTypeHandshakeResponse   MessageType = 2
	MessageTypeData                MessageType = 3
	MessageTypeClose               MessageType = 4
)

type MessageHandshakeInitiation struct {
	MessageType MessageType
	SenderIndex uint32
	Ephemeral   [32]byte
	Ciphertext  []byte
}

func (m MessageHandshakeInitiation) Encode() []byte {
	out := make([]byte,
		0,
		1+ // MessageType
			4+ // SenderIndex
			32+ // Ephemeral
			len(m.Ciphertext),
	)

	out = append(out, byte(m.MessageType))
	out = binary.LittleEndian.AppendUint32(out, m.SenderIndex)
	out = append(out, m.Ephemeral[:]...)
	out = append(out, m.Ciphertext...)

	return out
}

func MessageHandshakeInitiationDecode(b []byte) (MessageHandshakeInitiation, error) {
	if len(b) < 37 { // "header" part of the message buffer (Excluding the Ciphertext)
		return MessageHandshakeInitiation{}, errors.New("invalid message length")
	}

	m := MessageHandshakeInitiation{
		MessageType: MessageType(b[0]),
		SenderIndex: binary.LittleEndian.Uint32(b[1:5]),
		Ciphertext:  b[37:],
	}

	copy(m.Ephemeral[:], b[5:37])

	return m, nil
}

type MessageHandshakeResponse struct {
	MessageType   MessageType
	SenderIndex   uint32
	ReceiverIndex uint32
	Ephemeral     [32]byte
	Ciphertext    []byte
}

func (m MessageHandshakeResponse) Encode() []byte {
	out := make([]byte,
		0,
		1+ // MessageType
			4+ // SenderIndex
			4+ // RecieverIndex
			32+ // Ephemeral
			len(m.Ciphertext),
	)

	out = append(out, byte(m.MessageType))
	out = binary.LittleEndian.AppendUint32(out, m.SenderIndex)
	out = binary.LittleEndian.AppendUint32(out, m.ReceiverIndex)
	out = append(out, m.Ephemeral[:]...)
	out = append(out, m.Ciphertext...)

	return out
}

func MessageHandshakeResponseDecode(b []byte) (MessageHandshakeResponse, error) {
	if len(b) < 41 { // "header" part of the message buffer (Excluding the Ciphertext)
		return MessageHandshakeResponse{}, errors.New("invalid message length")
	}

	m := MessageHandshakeResponse{
		MessageType:   MessageType(b[0]),
		SenderIndex:   binary.LittleEndian.Uint32(b[1:5]),
		ReceiverIndex: binary.LittleEndian.Uint32(b[5:11]),
		Ciphertext:    b[41:],
	}

	copy(m.Ephemeral[:], b[11:41])

	return m, nil
}

type MessageData struct {
	MessageType   MessageType
	ReceiverIndex uint32
	Ciphertext    []byte
}

func (m MessageData) Encode() []byte {
	out := make([]byte,
		0,
		1+ // MessageType
			4+ // RecieverIndex
			len(m.Ciphertext),
	)

	out = append(out, byte(m.MessageType))
	out = binary.LittleEndian.AppendUint32(out, m.ReceiverIndex)
	out = append(out, m.Ciphertext...)

	return out
}

func MessageDataDecode(b []byte) (MessageData, error) {
	if len(b) < 5 {
		return MessageData{}, errors.New("invalid message length")
	}

	return MessageData{
		MessageType:   MessageType(b[0]),
		ReceiverIndex: binary.LittleEndian.Uint32(b[1:5]),
		Ciphertext:    b[5:],
	}, nil
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
	s   Keypair
	e   Keypair
	rs  [32]byte
	re  [32]byte
	psk [32]byte
}

type NoiseSession struct {
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

func getPublicKey(kp *Keypair) [32]byte {
	return kp.Public
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

func GenerateKey() [32]byte {
	var k [32]byte
	_, _ = rand.Read(k[:])
	return k
}

func GenerateKeypair() Keypair {
	privateKey := GenerateKey()
	publicKey := generatePublicKey(privateKey)

	if validatePublicKey(publicKey) {
		return Keypair{publicKey, privateKey}
	}
	return GenerateKeypair()
}

func generatePublicKey(privateKey [32]byte) [32]byte {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

func encrypt(k [32]byte, n uint64, ad []byte, plaintext []byte) ([]byte, error) {
	enc, err := chacha20poly1305.New(k[:])
	if err != nil {
		return []byte{}, fmt.Errorf("error initializing encryption: %w", err)
	}

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return enc.Seal(nil, nonce[:], plaintext, ad)
}

func decrypt(k [32]byte, n uint64, ad []byte, ciphertext []byte) ([]byte, error) {
	enc, err := chacha20poly1305.New(k[:])
	if err != nil {
		return []byte{}, fmt.Errorf("error initalizing encryption: %w", err)
	}

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	plaintext, err := enc.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting payload: %w", err)
	}

	return plaintext, nil
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

func (cs *cipherstate) hasKey() bool {
	return !isEmptyKey(cs.k)
}

func (cs *cipherstate) encryptWithAd(ad []byte, plaintext []byte) ([]byte, error) {
	if cs.n == math.MaxUint64-1 {
		return []byte{}, errors.New("encryptWithAd: maximum nonce size reached")
	}

	ciphertext, err := encrypt(cs.k, cs.n, ad, plaintext)
	cs.n += 1

	if err != nil {
		return []byte{}, fmt.Errorf("error encrypting with AD: %w", err)
	}

	return ciphertext, nil
}

func (cs *cipherstate) decryptWithAd(ad []byte, ciphertext []byte) ([]byte, error) {
	if cs.n == math.MaxUint64-1 {
		return []byte{}, errors.New("decryptWithAd: maximum nonce size reached")
	}

	plaintext, err := decrypt(cs.k, cs.n, ad, ciphertext)
	cs.n += 1

	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting with AD: %w", err)
	}

	return plaintext, nil
}

// func reKey(cs *cipherstate) *cipherstate {
// 	e := encrypt(cs.k, math.MaxUint64, []byte{}, emptyKey[:])
// 	copy(cs.k[:], e)
// 	return cs
// }

/* SymmetricState */

func initializeSymmetric(protocolName []byte) symmetricstate {
	h := hashProtocolName(protocolName)
	ck := h
	cs := initializeKey(emptyKey)
	return symmetricstate{cs, ck, h}
}

func (ss *symmetricstate) mixKey(ikm [32]byte) {
	ck, tempK, _ := getHkdf(ss.ck, ikm[:])
	ss.cs = initializeKey(tempK)
	ss.ck = ck
}

func (ss *symmetricstate) mixHash(data []byte) {
	ss.h = getHash(ss.h[:], data)
}

func (ss *symmetricstate) mixKeyAndHash(ikm [32]byte) {
	var tempH [32]byte
	var tempK [32]byte

	ss.ck, tempH, tempK = getHkdf(ss.ck, ikm[:])
	ss.mixHash(tempH[:])
	ss.cs = initializeKey(tempK)
}

func (ss *symmetricstate) encryptAndHash(plaintext []byte) ([]byte, error) {
	var ciphertext []byte
	var err error

	if ss.cs.hasKey() {
		ciphertext, err = ss.cs.encryptWithAd(ss.h[:], plaintext)
		if err != nil {
			return []byte{}, err
		}
	} else {
		ciphertext = plaintext
	}

	ss.mixHash(ciphertext)
	return ciphertext, err
}

func (ss *symmetricstate) decryptAndHash(ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	var err error

	if ss.cs.hasKey() {
		plaintext, err = ss.cs.decryptWithAd(ss.h[:], ciphertext)
		if err != nil {
			return []byte{}, err
		}
	} else {
		plaintext = ciphertext
	}

	ss.mixHash(ciphertext)
	return plaintext, nil
}

func (ss *symmetricstate) split() (cipherstate, cipherstate) {
	tempK1, tempK2, _ := getHkdf(ss.ck, []byte{})
	cs1 := initializeKey(tempK1)
	cs2 := initializeKey(tempK2)
	return cs1, cs2
}

/* HandshakeState */

func initializeInitiator(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var e Keypair
	var re [32]byte

	name := []byte("Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s")
	ss := initializeSymmetric(name)
	ss.mixHash(prologue)
	ss.mixHash(s.Public[:])
	ss.mixHash(rs[:])

	return handshakestate{ss, s, e, rs, re, psk}
}

func initializeResponder(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	ss.mixHash(prologue)
	ss.mixHash(rs[:])
	ss.mixHash(s.Public[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func (hs *handshakestate) writeMessageA(payload []byte) (MessageHandshakeInitiation, error) {
	hs.e = GenerateKeypair()

	hs.ss.mixHash(hs.e.Public[:])
	hs.ss.mixKey(hs.e.Public)
	hs.ss.mixKey(dh(hs.e.Private, hs.rs))
	hs.ss.mixKey(dh(hs.s.Private, hs.rs))

	ciphertext, err := hs.ss.encryptAndHash(payload)
	if err != nil {
		return MessageHandshakeInitiation{}, err
	}

	return MessageHandshakeInitiation{
		MessageType: MessageTypeHandshakeInitiation,
		Ephemeral:   hs.e.Public,
		Ciphertext:  ciphertext,
	}, nil
}

func (hs *handshakestate) writeMessageB(payload []byte) ([32]byte, MessageHandshakeResponse, cipherstate, cipherstate, error) {
	hs.e = GenerateKeypair()

	hs.ss.mixHash(hs.e.Public[:])
	hs.ss.mixKey(hs.e.Public)
	hs.ss.mixKey(dh(hs.e.Private, hs.re))
	hs.ss.mixKey(dh(hs.e.Private, hs.rs))
	hs.ss.mixKeyAndHash(hs.psk)

	ciphertext, err := hs.ss.encryptAndHash(payload)
	if err != nil {
		cs1, cs2 := hs.ss.split()
		return emptyKey, MessageHandshakeResponse{}, cs1, cs2, err
	}

	messageBuffer := MessageHandshakeResponse{
		MessageType: MessageTypeHandshakeResponse,
		Ephemeral:   hs.e.Public,
		Ciphertext:  ciphertext,
	}

	cs1, cs2 := hs.ss.split()
	return hs.ss.h, messageBuffer, cs1, cs2, err
}

func (hs *handshakestate) readMessageA(message MessageHandshakeInitiation) ([]byte, error) {
	if validatePublicKey(message.Ephemeral) {
		hs.re = message.Ephemeral
	}
	hs.ss.mixHash(hs.re[:])
	hs.ss.mixKey(hs.re)
	hs.ss.mixKey(dh(hs.s.Private, hs.re))
	hs.ss.mixKey(dh(hs.s.Private, hs.rs))

	return hs.ss.decryptAndHash(message.Ciphertext)
}

func (hs *handshakestate) readMessageB(message MessageHandshakeResponse) ([32]byte, []byte, cipherstate, cipherstate, error) {
	if validatePublicKey(message.Ephemeral) {
		hs.re = message.Ephemeral
	}
	hs.ss.mixHash(hs.re[:])
	hs.ss.mixKey(hs.re)
	hs.ss.mixKey(dh(hs.e.Private, hs.re))
	hs.ss.mixKey(dh(hs.s.Private, hs.re))
	hs.ss.mixKeyAndHash(hs.psk)

	plaintext, err := hs.ss.decryptAndHash(message.Ciphertext)
	cs1, cs2 := hs.ss.split()
	return hs.ss.h, plaintext, cs1, cs2, err
}

func (cs *cipherstate) readMessageRegular(ciphertext []byte) ([]byte, error) {
	return cs.decryptWithAd([]byte{}, ciphertext)
}
func (cs *cipherstate) writeMessageRegular(plaintext []byte) ([]byte, error) {
	return cs.encryptWithAd([]byte{}, plaintext)
}

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func InitSession(initiator bool, prologue []byte, secret Secret) NoiseSession {
	var session NoiseSession
	/* PSK defined by user */
	if initiator {
		session.hs = initializeInitiator(prologue, secret.Static, secret.RemotePublic, secret.PreShared)
	} else {
		session.hs = initializeResponder(prologue, secret.Static, secret.RemotePublic, secret.PreShared)
	}
	session.i = initiator
	session.mc = 0
	return session
}

func (s *NoiseSession) DecryptA(message MessageHandshakeInitiation) ([]byte, error) {
	return s.hs.readMessageA(message)
}

func (s *NoiseSession) DecryptB(message MessageHandshakeResponse) ([]byte, error) {
	var err error
	var plaintext []byte

	s.h, plaintext, s.cs1, s.cs2, err = s.hs.readMessageB(message)
	s.hs = handshakestate{}

	return plaintext, err
}

func (s *NoiseSession) Decrypt(message *MessageData) ([]byte, error) {
	if s.i {
		return s.cs2.readMessageRegular(message.Ciphertext)
	} else {
		return s.cs1.readMessageRegular(message.Ciphertext)
	}
}

func (s *NoiseSession) EncryptA() (MessageHandshakeInitiation, error) {
	timestamp := time.Now().UnixMilli()
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint64(payload, uint64(timestamp))

	return s.hs.writeMessageA(payload)
}

func (s *NoiseSession) EncryptB() (MessageHandshakeResponse, error) {
	var messageBuffer MessageHandshakeResponse
	var err error

	s.h, messageBuffer, s.cs1, s.cs2, err = s.hs.writeMessageB([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	s.hs = handshakestate{}

	return messageBuffer, err
}

func (s *NoiseSession) Encrypt(plaintext []byte) ([]byte, error) {
	if s.i {
		return s.cs1.writeMessageRegular(plaintext)
	} else {
		return s.cs2.writeMessageRegular(plaintext)
	}
}
