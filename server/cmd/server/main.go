package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/SN9NV/noise_ws/server/internal/noise"
)

type serverNoiseSession struct {
	session          noise.NoiseSession
	lastMessage      time.Time
	sessionStartTime time.Time
	localIndex       uint32
	remoteIndex      uint32
}

type server struct {
	secret    noise.Secret
	indexMap  map[uint32]*serverNoiseSession
	keyMap    map[[32]byte]*serverNoiseSession
	indexLock sync.Mutex
}

func (s *server) generateRandomIndex(session *serverNoiseSession) uint32 {
	s.indexLock.Lock()
	defer s.indexLock.Unlock()

	for {
		i := rand.Uint32()
		_, found := s.indexMap[i]

		if !found {
			s.indexMap[i] = session
			return i
		}
	}
}

func runServer(server *http.Server) {
	log.Println("Starting server on", server.Addr)

	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalln(err)
	}
}

func (s *server) handleHandshakeInit(w http.ResponseWriter, r *http.Request, ciphertext []byte) {
	prologue := []byte{0, 0, 0, 0, 0, 0, 0, 42}
	session := noise.InitSession(false, prologue, s.secret)

	messageA, err := noise.MessageHandshakeInitiationDecode(ciphertext)
	if err != nil {
		log.Printf("handle connect error: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	plaintext, err := session.DecryptA(messageA)
	if err != nil {
		log.Printf("decryptA error: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(plaintext) != 8 {
		log.Println("invalid handshake message length")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	unixMilli := binary.LittleEndian.Uint64(plaintext)
	timestamp := time.UnixMilli(int64(unixMilli))

	if time.Since(timestamp) > 2*time.Second {
		log.Println("invalid handshake timestamp too old")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	messageB, err := session.EncryptB()
	if err != nil {
		log.Printf("encrypting message B failed: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	messageB.ReceiverIndex = messageA.SenderIndex

	serverSession := serverNoiseSession{
		session:          session,
		lastMessage:      timestamp,
		sessionStartTime: timestamp,
		remoteIndex:      messageA.SenderIndex,
	}

	localIndex := s.generateRandomIndex(&serverSession)

	s.keyMap[messageA.Ephemeral] = &serverSession

	serverSession.localIndex = localIndex
	messageB.SenderIndex = localIndex

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(messageB.Encode())
	if err != nil {
		log.Printf("error writing handshake response: %s\n", err)
	}
}

func (s *server) handleHandshakeResponse(w http.ResponseWriter, r *http.Request, ciphertext []byte) {
}
func (s *server) handleMessageData(w http.ResponseWriter, r *http.Request, ciphertext []byte) {
}
func (s *server) handleMessageClose(w http.ResponseWriter, r *http.Request, ciphertext []byte) {
}

func (s *server) hander(w http.ResponseWriter, r *http.Request) {
	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("handle connect error reading body: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch noise.MessageType(ciphertext[0]) {
	case noise.MessageTypeHandshakeInitiation:
		s.handleHandshakeInit(w, r, ciphertext)
	case noise.MessageTypeHandshakeResponse:
		s.handleHandshakeResponse(w, r, ciphertext)
	case noise.MessageTypeData:
		s.handleMessageData(w, r, ciphertext)
	case noise.MessageTypeClose:
		s.handleMessageClose(w, r, ciphertext)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func main() {
	secret, err := noise.DecodeSecret([]byte(os.Args[1]))
	if err != nil {
		log.Fatalf("Failed to decode secret: %s\n", err)
	}

	server := server{
		secret:   secret,
		sessions: map[string]serverNoiseSession{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handler)
	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	go runServer(httpServer)

	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer close(wait)
	<-wait

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("Shutting down server")

	err := httpServer.Shutdown(ctx)
	if err != nil {
		log.Fatalln(err)
	}
}
