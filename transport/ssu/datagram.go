package ssu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

var datagramBufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, maximumDatagramSize)
	},
}

const (
	// nominalHeaderLen is the nominal header length in bytes
	nominalHeaderLen = 37 // 37B

	// maximumPayloadSize is the maximum size of payload in bytes
	maximumPayloadSize = 32 * 1024 // 32KB

	maximumDatagramSize = maximumPayloadSize + nominalHeaderLen

	// Cursors for datagram marshalling
	macPos     = 0
	ivPos      = 16
	flagPos    = 32
	timePos    = 33
	payloadPos = 37
)

type datagram struct {
	// the MACKey is necessary for calculation of the MAC - 16 bytes
	MACKey []byte

	// EncKey is the encryption key - 16 bytes
	EncKey []byte

	// Header
	Flag byte
	Time uint32 // Seconds since the UNIX epoch

	// Payload
	Payload []byte
}

// MarshalBinary marshals a given SSU datagram to binary
/* The format is like this:
+----+----+----+----+----+----+----+----+
|                  MAC                  |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|                   IV                  |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+
|flag|        time       |              |
+----+----+----+----+----+              +
| keying material (optional)            |
+                                       +
|                                       |
~                                       ~
|                                       |
+                        +----+----+----+
|                        |#opt|         |
+----+----+----+----+----+----+         +
| #opt extended option bytes (optional) |
~                                       ~
~                                       ~
+----+----+----+----+----+----+----+----+
| 		Payload			|
~                                       ~
~                                       ~
+----+----+----+----+----+----+----+----+
*/
func (d *datagram) MarshalBinary() ([]byte, error) {
	// We create the slice. We should use a buffer pool along with an unexported encode(dst []byte) function
	b := make([]byte, d.OutputLen())

	// Return it
	return b, d.MarshalBinaryTo(b)
}

// PadLen returns the padding length necessary
func (d *datagram) padLen() int {
	padLen := 16 - (1 + 4 + len(d.Payload)%16)
	if padLen == 16 {
		padLen = 0
	}
	return padLen
}

// OutputLen returns the length of the output
func (d *datagram) OutputLen() int { return nominalHeaderLen + len(d.Payload) + d.padLen() }

// MarshalBinaryTo marshals a datagram to a given slice of bytes, with the correct length
// If the slice is not large enough, it errors
func (d *datagram) MarshalBinaryTo(b []byte) error {
	// Copy the flag
	copy(b[flagPos:flagPos], []byte{d.Flag})

	// Copy the time
	binary.BigEndian.PutUint32(b[timePos:payloadPos], d.Time)

	// Copy the payload
	copy(b[payloadPos:], d.Payload)

	// Write random padding if necessary
	if padLen := d.padLen(); padLen != 0 {
		n, err := rand.Read(b[payloadPos+len(d.Payload):])
		if n != padLen {
			return errors.New("critical: didn't read enough random bytes of padding")
		} else if err != nil {
			return err
		}
	}

	// Now we generate the IV (we need it for the MAC)
	// Note: rand.Read calls ReadFull, so we don't need to check for the number of bytes read
	_, err := rand.Read(b[ivPos:flagPos])
	if err != nil {
		return err
	}

	// Let's create the AES cipher with the given encryption key
	c, err := aes.NewCipher(d.EncKey)
	if err != nil {
		return err
	}

	// Let's transform it into a CBC cipher by using the cipher in block chaining mode, with the IV we generated earlier
	enc := cipher.NewCBCEncrypter(c, b[16:32])

	// Let's encrypt the flag, time & payload, in-place
	enc.CryptBlocks(b[flagPos:payloadPos+len(d.Payload)], b[flagPos:payloadPos+len(d.Payload)])

	// Now we generate the MAC via the HMAC-MD5 method
	// 16 bytes MAC: HMAC-MD5(encryptedPayload + IV + (payloadLength | protocolVersion) with key macKey

	// Create the hasher
	hasher := hmac.New(md5.New, nil)

	// Write the data to be hashed
	// Note: we don't use append, as we do not wish to modify the underlying slice
	nP, err := hasher.Write(b[flagPos:]) // First the newly encrypted payload
	if err != nil {
		return err
	}
	nIV, err := hasher.Write(b[ivPos:flagPos]) // Then the IV
	if err != nil {
		return err
	}
	payloadLen := make([]byte, 2)
	binary.BigEndian.PutUint16(payloadLen, uint16(len(d.Payload)))
	nL, err := hasher.Write(payloadLen) // And finally the payload length
	if err != nil {
		return err
	}

	// Check len of copied info
	if nP+nIV+nL != 16+1+4+len(d.Payload)+4 {
		return fmt.Errorf("copied not enough data to hasher: %d instead of %d", nP+nIV+nL, 16+1+4+len(d.Payload)+4)
	} else if mod := (nP + nIV + nL) % 16; mod != 0 {
		return fmt.Errorf("copied data to hasher is not aligned to 16-byte bondary: mod is %d", mod)
	}

	// Sum & copy as MAC
	copy(b[:ivPos], hasher.Sum(nil))

	// DONE !
	return nil
}
