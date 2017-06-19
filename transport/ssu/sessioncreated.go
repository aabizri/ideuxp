package ssu

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	reasonableMaxSessionCreatedPayloadSize = 400
)

type sessionCreated struct {
	// Y part of the DH exchange
	Y [256]byte

	// Address of the requester
	Addr net.UDPAddr

	// Relay tag if applicable
	RelayTag [4]byte

	// Information to be signed
	X      [256]byte
	MyAddr net.UDPAddr

	// SessionKey to encrypt the signature

	RemoteIntroKey []byte
}

func (sc *sessionCreated) MarshalBinary() ([]byte, error) {
	// Sanity check for sessionCreated
	if len(sc.Addr.IP) != 4 && len(sc.Addr.IP) != 16 {
		return nil, errors.New("invalid IP address length")
	} else if sc.Addr.Port > 1<<16-1 {
		return nil, errors.New("port overflows uint16: cannot represent it in two bytes")
	}

	// Create the byte slice we will return
	b := make([]byte, 0, 400)

	// First we copy the Y
	copy(b[:256], sc.Y[:])

	// Write the size of the IP Addr
	b[256] = byte(len(sc.Addr.IP))

	// Write the IP addr
	cursor := 257 + len(sc.Addr.IP)
	copy(b[257:cursor], sc.Addr.IP)

	// Write the port number (2 byte long)
	binary.BigEndian.PutUint16(b[cursor:cursor+2], uint16(sc.Addr.Port))
	cursor += 2

	// Write the public relay tag
	copy(b[cursor:cursor+4], sc.RelayTag[:])
	cursor += 4

	// Create the signature
	// TODO
	// X + Y + Alice's IP + Alice's port + Bob's IP + Bob's port + Alice's new relay tag + Bob's signed on time (We are bob, remote is alice)

	// If the signature length is not a multiple of 16, pad it until it is.
	// Then, we encrypt it using the correct session key
	// TODO

	return b, errors.New("WIP")
}
