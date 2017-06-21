package ssu

import "testing"

func TestMacKey(t *testing.T) {
	mac, err := macKeyFromDHKey([]byte("test dh key"))
	t.Logf("mac: %v", mac)
	if err != nil {
		t.Errorf("error generating mac key: %v", err)
	} else if len(mac) != macKeySize {
		t.Errorf("mac key len (%d) is not expected key len (%d)", len(mac), macKeySize)
	}
}

func TestSessionKey(t *testing.T) {
	session, err := sessionKeyFromDHKey([]byte("test dh key"))
	t.Logf("session: %v", session)
	if err != nil {
		t.Errorf("error generating session key: %v", err)
	} else if len(session) != sessionKeySize {
		t.Errorf("session key len (%d) is not expected key len (%d)", len(session), sessionKeySize)
	}
}
