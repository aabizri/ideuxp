package ssu

import (
	"errors"
	"fmt"
	"net"
)

const (
	sessionRequestMinUnpaddedPayloadLength = 304
	sessionRequestMaxUnpaddedPayloadLength = 320
)

/*
  +----+----+----+----+----+----+----+----+
  |         X, as calculated from DH      |
  ~                .  .  .                ~
  |                                       |
  +----+----+----+----+----+----+----+----+
  |size| that many byte IP address (4-16) |
  +----+----+----+----+----+----+----+----+
  | arbitrary amount of uninterpreted data|
  ~                .  .  .                ~
*/
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

// Does not retain b
func (sr *sessionRequest) UnmarshalBinary(b []byte) error {
	// Check for correct minimum Len
	if len(b) < 256+1+4 {
		return errors.New("session request is invalid: too small")
	} else if b[256] != 4 && b[256] != 16 {
		return fmt.Errorf("IP size indicator is neither 4 nor 16 but %d", b[256])
	}

	// We know the 256 first bytes are the X
	copy(sr.X[:], b[:256])

	// Check for the size of the IP
	switch b[256] {
	case 4:
		copy(sr.IP[:], b[257:257+4])
	case 16:
		if len(b) < 256+1+16 {
			return errors.New("session request is invalid: too small")
		}
		copy(sr.IP[:], b[257:257+16])
	}

	// Finished
	return nil
}
