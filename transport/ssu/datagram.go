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
type datagram struct {
	// Header
	Flag byte
	Time uint32 // Seconds since the UNIX epoch

	// Payload
	Payload []byte
}

// MarshalBinary marshals a given SSU datagram to binary
func (d *datagram) MarshalBinary(macKey, cryptoKey []byte) ([]byte, error) {
	// We create the slice. We should use a buffer pool along with an unexported encode(dst []byte) function
	b := make([]byte, d.outputLen())

	// Return it
	return b, d.MarshalBinaryTo(b, macKey, cryptoKey)
}

// PadLen returns the padding length necessary
func (d *datagram) padLen() int {
	padLen := 16 - (1 + 4 + len(d.Payload)%16)
	if padLen == 16 {
		padLen = 0
	}
	return padLen
}

// outputLen returns the length of the output
func (d *datagram) outputLen() int { return nominalHeaderLen + len(d.Payload) + d.padLen() }

// MarshalBinaryTo marshals a datagram to a given slice of bytes, with the correct length
// If the slice is not large enough, it errors
func (d *datagram) MarshalBinaryTo(b []byte, macKey []byte, cryptoKey []byte) error {
	// Copy the flag
	b[flagPos] = d.Flag

	// Copy the time
	binary.BigEndian.PutUint32(b[timePos:payloadPos], d.Time)

	// Copy the payload
	copy(b[payloadPos:], d.Payload)

	// Write random padding if necessary
	if padLen := d.padLen(); padLen != 0 {
		n, err := rand.Read(b[payloadPos+len(d.Payload):])
		if err != nil {
			return err
		}
		if n != padLen {
			return errors.New("critical: didn't read enough random bytes of padding")
		}
	}

	// Now we generate the IV (we need it for the MAC)
	// Note: rand.Read calls ReadFull, so we don't need to check for the number of bytes read
	_, err := rand.Read(b[ivPos:flagPos])
	if err != nil {
		return err
	}

	// Let's create the AES cipher with the given encryption key
	c, err := aes.NewCipher(cryptoKey)
	if err != nil {
		return err
	}

	// Let's transform it into a CBC cipher by using the cipher in block chaining mode, with the IV we generated earlier
	enc := cipher.NewCBCEncrypter(c, b[16:32])

	// Let's encrypt the flag, time, payload & padding, in-place
	enc.CryptBlocks(b[flagPos:], b[flagPos:])

	// Generate the MAC
	mac, err := createDatagramHMAC(b[flagPos:], b[ivPos:flagPos], len(b)-flagPos, macKey)
	if err != nil {
		return err
	}
	copy(b[:ivPos], mac)

	// DONE !
	return nil
}

// createDatagramHMAC generates the MAC using HMAC-MD5
// 16 bytes MAC: HMAC-MD5(encryptedPayload + IV + (payloadLength | protocolVersion) with key macKey
func createDatagramHMAC(encPayload []byte, iv []byte, payloadLen int, macKey []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("invalid IV len")
	} else if len(macKey) != macKeySize {
		return nil, errors.New("invalid mac key size")
	} else if payloadLen > maximumPayloadSize || payloadLen < 0 {
		return nil, errors.New("payload len not in bounds")
	}

	// Create the hasher
	hasher := hmac.New(md5.New, macKey)

	// Write the data to be hashed
	// Note: we don't use append, as we do not wish to modify the underlying slice
	nP, err := hasher.Write(encPayload) // First the newly encrypted payload
	if err != nil {
		return nil, err
	}
	nIV, err := hasher.Write(iv) // Then the IV
	if err != nil {
		return nil, err
	}
	err = binary.Write(hasher, binary.BigEndian, uint16(payloadLen))
	if err != nil {
		return nil, err
	}

	// Check len of copied info
	if nP+nIV+2 != len(encPayload)+16+2 {
		return nil, fmt.Errorf("copied not enough data to hasher: %d instead of %d", nP+nIV+2, len(encPayload)+16+2)
	}

	// Return
	return hasher.Sum(nil), nil
}

// Does not retain b
func (d *datagram) unmarshal(b []byte, macKey []byte, decKey []byte) error {
	// First we'll store the values we'll be using the decrypt and unmarshal the message
	var (
		mac       = b[:ivPos]
		iv        = b[ivPos:flagPos]
		encrypted = b[flagPos:]
	)

	// Let's check the validity of the encrypted payload
	// To do so, we have to recreate the MAC, an(b)d then compare them using hmac.Equal
	calcMAC, err := createDatagramHMAC(encrypted, iv, len(b)-flagPos, macKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, calcMAC) {
		return fmt.Errorf("invalid MAC in datagram: %v != %v", mac, calcMAC)
	}

	// Now, let's use the IV & decKey to decrypt the payload
	c, err := aes.NewCipher(decKey)
	if err != nil {
		return err
	}

	// Let's transform it into a CBC cipher decrypter by using the cipher in block chaining mode, with the IV from the datagram
	dec := cipher.NewCBCDecrypter(c, iv)

	// Let's decrypt the data
	tmp := make([]byte, len(b)-flagPos)
	dec.CryptBlocks(tmp, b[flagPos:])

	// Split it into flag, time and payload
	d.Flag = tmp[0]
	d.Time = binary.BigEndian.Uint32(tmp[1:5])
	if len(d.Payload) < len(tmp)-5 {
		d.Payload = make([]byte, len(tmp)-5)
	}
	copy(d.Payload, tmp[5:])

	// Return
	return nil
}
