package main

// import "github.com/SN9NV/noise_ws/server/internal/noise"
import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SN9NV/noise_ws/server/internal/noise"
)

type serverNoiseSession struct {
	session     noise.NoiseSession
	lastMessage time.Time
}

type server struct {
	secret   noise.Secret
	sessions map[string]serverNoiseSession
}

func runServer(server *http.Server) {
	log.Println("Starting server on", server.Addr)

	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalln(err)
	}
}

func (s *server) handleConnect(w http.ResponseWriter, r *http.Request) {
	prologue := []byte{0, 0, 0, 0, 0, 0, 0, 42}
	session := noise.InitSession(false, prologue, s.secret)

	messageA, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("handle connect error reading body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	session.dec

}

func (s *server) hander(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleConnect(w, r)
	case http.MethodPut:
		s.handleMessage(w, r)
	case http.MethodDelete:
		s.handleClose(w, r)
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
