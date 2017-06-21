package ssu

import (
	"testing"
	"time"
)

// TestDatagram_MarshallingCoherence tests datagram marshalling followed by unmarshalling, checking that we we have a coherence throughout the test
func TestDatagram_MarshallingCoherence(t *testing.T) {
	dhKey := []byte("this is the dh key")
	macKey, err := macKeyFromDHKey(dhKey)
	if err != nil {
		t.Fatalf("couldn't compute mac key: %v", err)
	}
	sessionKey, err := sessionKeyFromDHKey(dhKey)
	if err != nil {
		t.Fatalf("couldn't compute session key: %v", err)
	}

	origin := &datagram{
		Flag:    composeFlag(payloadSessionCreated, false, false),
		Time:    uint32(time.Now().Unix()),
		Payload: []byte("this is the payload"),
	}
	t.Logf("created datagram: %v", origin)

	b, err := origin.MarshalBinary(macKey, sessionKey)
	t.Logf("marshalled datagram is of len %d", len(b))
	if err != nil {
		t.Errorf("error in MarshalBinary: %v", err)
	}

	destination := new(datagram)
	err = destination.unmarshal(b, macKey, sessionKey)
	if err != nil {
		t.Errorf("error in unmarshal: %v", err)
	}
	t.Logf("decrypted payload: %v", destination)

}
