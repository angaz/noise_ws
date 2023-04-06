package main

// import "github.com/SN9NV/noise_ws/server/internal/noise"
import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func runServer(server *http.Server) {
	log.Println("Starting server on", server.Addr)

	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalln(err)
	}
}

func main() {
	server := &http.Server{
		Addr: ":8080",
	}
	go runServer(server)

	wait := make(chan os.Signal, 1)
	signal.Notify(wait, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer close(wait)
	<-wait

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("Shutting down server")

	err := server.Shutdown(ctx)
	if err != nil {
		log.Fatalln(err)
	}
}
