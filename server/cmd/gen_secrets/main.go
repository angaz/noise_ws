package main

import "fmt"
import "github.com/SN9NV/noise_ws/server/internal/noise"

func main() {
	server := noise.GenerateKeypair()
	client := noise.GenerateKeypair()
	psk := noise.GenerateKey()

	serverSecret := noise.Secret{
		Static:       server,
		RemotePublic: client.Public,
		PreShared:    psk,
	}
	clientSecret := noise.Secret{
		Static:       client,
		RemotePublic: server.Public,
		PreShared:    psk,
	}

	fmt.Printf("Server Secret: %s\nClient Secret: %s\n", serverSecret.EncodeBase64(), clientSecret.EncodeBase64())
}
