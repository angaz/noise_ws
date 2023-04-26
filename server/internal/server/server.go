package server

import (
	"sync"
	"sync/atomic"
)

type ServerState uint32

const (
	ServerStateUninitialized ServerState = 0
	ServerStateStarting      ServerState = 1
	ServerStateRunning       ServerState = 2
	ServerStateStopping      ServerState = 3
	ServerStateStopped       ServerState = 4
)

type Server struct {
	state struct {
		sync.Mutex
		state    atomic.Uint32
		stopping sync.WaitGroup
	}

	staticKey struct {
		sync.RWMutex
		privateKey PrivateKey
		publicKey  PublicKey
	}

	peers struct {
		sync.RWMutex
		keyMap map[PublicKey]*Peer
	}

	indexTable map[uint32]*Peer
}
