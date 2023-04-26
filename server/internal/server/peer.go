package server

import "sync"

type Handshake struct {
}

type Peer struct {
	sync.RWMutex

	handshake Handshake
}
