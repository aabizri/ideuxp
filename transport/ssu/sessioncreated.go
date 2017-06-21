package ssu

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"time"

	"errors"
)

const (
	reasonableMaxSCSize = 400
	minSCSize           = 256 + 1 + 16 + 2 + 4 + 4 // + signature ?
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

/* MarshalBinary marshals a sessionCreated to binary form

+----+----+----+----+----+----+----+----+
|         Y, as calculated from DH      |
~                .  .  .                ~
|                                       |
+----+----+----+----+----+----+----+----+
|size| that many byte IP address (4-16) |
+----+----+----+----+----+----+----+----+
| Port (A)| public relay tag  |  signed
+----+----+----+----+----+----+----+----+
  on time |                             |
+----+----+                             +
|                                       |
+                                       +
|             signature                 |
+                                       +
|                                       |
+                                       +
|                                       |
+         +----+----+----+----+----+----+
|         |   (0-15 bytes of padding)
+----+----+----+----+----+----+----+----+
          |                             |
+----+----+                             +
|           arbitrary amount            |
~        of uninterpreted data          ~
~                .  .  .                ~
*/
func (sc *sessionCreated) MarshalBinary() ([]byte, error) {
	// Sanity check for sessionCreated
	if len(sc.Addr.IP) != 4 && len(sc.Addr.IP) != 16 {
		return nil, errors.New("invalid IP address length")
	} else if sc.Addr.Port > 1<<16-1 {
		return nil, errors.New("port overflows uint16: cannot represent it in two bytes")
	}

	// Create the bytes buffer we will use
	buf := bytes.NewBuffer(make([]byte, 0, reasonableMaxSCSize))

	// First we copy the Y
	buf.Write(sc.Y[:])

	// Write the size of the IP Addr
	buf.Write([]byte{byte(len(sc.Addr.IP))})

	// Write the IP addr
	buf.Write(sc.Addr.IP)

	// Write the port number (2 byte long)
	binary.Write(buf, binary.BigEndian, uint16(sc.Addr.Port))

	// Write the public relay tag
	buf.Write(sc.RelayTag[:])

	// Create the signature

	// First we hash it all
	t := time.Now()
	hash := sessionCreatedHash(&sc.X, &sc.Y, sc.Addr.IP, uint16(sc.Addr.Port), sc.MyAddr.IP, uint16(sc.MyAddr.Port), &sc.RelayTag, t)

	// Then we sign
	signed := sessionCreatedSign(hash, make([]byte, 4)) //TODO HASH

	// If the signature length is not a multiple of 16, pad it until it is.
	padLen := 16 - (1 + 4 + len(signed)%16)
	if padLen == 16 {
		padLen = 0
	}
	n, err := io.CopyN(buf, rand.Reader, int64(padLen))
	if err != nil {
		return nil, err
	}
	if n != int64(padLen) {
		return nil, errors.New("didn't read the exact amount of random padding into sc buffer")
	}

	// Extract the bytes and push the buf back to the global pool
	b := buf.Bytes()
	buf.Reset()

	// done
	return b, errors.New("Not completely implemented")
}

func sessionCreatedHash(X *[256]byte, Y *[256]byte, reqIP net.IP, reqPort uint16, respIP net.IP, respPort uint16, relayTag *[4]byte, time time.Time) []byte {
	// X + Y + Alice's IP + Alice's port + Bob's IP + Bob's port + Alice's new relay tag + Bob's signed on time (We are bob, remote is alice)
	// This is DSA-SHA1, so we must first hash that data, and then sign it

	// Let's create the hasher
	hasher := sha1.New()

	// Let's establish the time
	timeU := uint32(time.Unix())

	// Copy X
	hasher.Write(X[:])

	// Copy Y
	hasher.Write(Y[:])

	// Copy reqIP
	hasher.Write(reqIP)

	// Copy reqPort
	binary.Write(hasher, binary.BigEndian, reqPort)

	// Copy respIP
	hasher.Write(respIP)

	// Copy respPort
	binary.Write(hasher, binary.BigEndian, respPort)

	// Copy relay tag
	hasher.Write(relayTag[:])

	// Copy time (uint32 = 4 bytes)
	binary.Write(hasher, binary.BigEndian, timeU)

	// Sum it
	sum := hasher.Sum(nil)

	// Return
	return sum
}

func sessionCreatedSign(hashed []byte, privKey []byte) []byte {
	return nil
}
