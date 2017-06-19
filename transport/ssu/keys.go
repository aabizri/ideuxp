package ssu

import (
	"crypto/sha256"
	"errors"
)

const (
	macKeySize     = 32
	sessionKeySize = 32
)

/*
The 32-byte session key is created as follows:

1. Take the exchanged DH key, represented as a positive minimal-length
   BigInteger byte array (two's complement big-endian)

2. If the most significant bit is 1 (i.e. array[0] & 0x80 != 0), prepend a 0x00
   byte, as in Java's BigInteger.toByteArray() representation

3. If the byte array is greater than or equal to 32 bytes, use the first (most
   significant) 32 bytes

4. If the byte array is less than 32 bytes, append 0x00 bytes to extend to 32
   bytes. *Very unlikely - See note below.*
*/
func sessionKeyFromDHKey(dhKey []byte) ([]byte, error) {
	if len(dhKey) == 0 {
		return nil, errors.New("dhKey length is 0: cannot proceed")
	}

	// If the most significant bit is 1, we prepend a 0x00 byte
	if dhKey[0]&0x80 != 0 {
		dhKey = append([]byte{0x00}, dhKey...)
	}

	// If the byte array length is more than or equal to 32 bytes, we slice it to 32 bytes
	if len(dhKey) >= 32 {
		return dhKey[:32], nil
	}

	// If it isn't, we append 0x00 bytes to extend it to 32 bytes in length
	prepend := make([]byte, 32-len(dhKey))
	return append(prepend, dhKey...), nil
}

/*
The 32-byte MAC key is created as follows:

1. Take the exchanged DH key byte array, prepended with a 0x00 byte if
   necessary, from step 2 in the Session Key Details above.

2. If that byte array is greater than or equal to 64 bytes, the MAC key is
   bytes 33-64 from that byte array.

3. If that byte array is less than 64 bytes, the MAC key is the SHA-256 Hash of
   that byte array. *As of release 0.9.8. See note below.*
*/
func macKeyFromDHKey(dhKey []byte) ([]byte, error) {
	if len(dhKey) == 0 {
		return nil, errors.New("dhKey length is 0: cannot proceed")
	}

	// If that byte array is greater than or equal to 64 bytes, the MAC key is bytes 33-64 from that byte array.
	if len(dhKey) >= 64 {
		return dhKey[33:64], nil
	}

	// Else, we take the SHA-256 Hash of the dhKey
	sha := sha256.Sum256(dhKey)
	return sha[:], nil
}
