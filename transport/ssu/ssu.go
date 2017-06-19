// Package ssu implements the Secure Semireliable UDP protocol
package ssu

import "github.com/monnand/dhkx"

const (
	// These indicate the type of payload
	payloadSessionRequest = iota
	payloadSessionCreated
	payloadSessionConfirmed
	payloadRelayRequest
	payloadRelayIntro
	payloadData
	payloadPeerTest
	payloadSessionDestroyed
)

// The diffie helmann group has ID 14
var dhGroup, _ = dhkx.GetGroup(14)
