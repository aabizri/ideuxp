package ssu

import (
	"errors"
	"net"
)

const (
	sessionRequestMinUnpaddedPayloadLength = 304
	sessionRequestMaxUnpaddedPayloadLength = 320
)

type sessionRequest struct {
	// Begin the DH arrangement given a X
	X [256]byte

	// Receiver's IP address
	IP net.IP
}

func (sr *sessionRequest) MarshalBinary() ([]byte, error) {
	// Check IP addr len
	if len(sr.IP) != 4 && len(sr.IP) != 16 {
		return nil, errors.New("invalid IP address length")
	}

	// Marshal
	b := make([]byte, 256+1+len(sr.IP))
	copy(b, sr.X[:])
	b[256] = byte(len(sr.IP))
	copy(b[257:], sr.IP)

	return b, nil
}
