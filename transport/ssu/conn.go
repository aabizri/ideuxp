package ssu

import (
	"context"
	"errors"
	"net"
	"time"
)

// Conn is a SSU connection
type Conn struct {
	sessionKey        []byte
	underlying        net.Conn
	underlyingForeign bool
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (conn *Conn) Read(b []byte) (n int, err error) { return }

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (conn *Conn) Write(b []byte) (n int, err error) { return }

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (conn *Conn) Close() error {
	if !conn.underlyingForeign {
		return conn.underlying.Close()
	}
	return nil
}

// LocalAddr returns the local network address.
func (conn *Conn) LocalAddr() net.Addr { return conn.underlying.LocalAddr() }

// RemoteAddr returns the remote network address.
func (conn *Conn) RemoteAddr() net.Addr { return conn.underlying.RemoteAddr() }

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (conn *Conn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (conn *Conn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (conn *Conn) SetWriteDeadline(t time.Time) error { return nil }

// A Dialer contains options for connecting to a remote peer
type Dialer struct {
	SigningPubKey  []byte
	SigningPrivKey []byte
	Introkey       []byte
}

// Dial does a direct dial
func (d *Dialer) Dial(ctx context.Context, peer *net.UDPAddr, introkey []byte) (*Conn, error) {
	// Dial UDP
	udpConn, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return nil, err
	}

	// Pass it over to DialOverConn
	return d.DialOverConn(ctx, udpConn, introkey, peer.IP)
}

// DialOverConn does a direct dial over a pre-established net.Conn
// It is thus the caller's responsibility to close the given connection
/*
       Alice                         Bob
   SessionRequest --------------------->
         <--------------------- SessionCreated
   SessionConfirmed ------------------->
         <--------------------- DeliveryStatusMessage
         <--------------------- DatabaseStoreMessage
   DatabaseStoreMessage --------------->
   Data <---------------------------> Data

*/
func (d *Dialer) DialOverConn(ctx context.Context, udp net.Conn, introkey []byte, ip net.IP) (*Conn, error) {

	// STEP 1: Session Request

	// Generate private key
	priv, err := dhGroup.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}
	// Prepare the first message, a Session Request
	sr := &sessionRequest{
		IP: ip,
	}
	// Copy the public key over to the request
	copy(sr.X[:], priv.Bytes())
	// Marshal it
	srb, err := sr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Embed it into a datagram
	srd := &datagram{
		MACKey:  introkey,
		EncKey:  introkey,
		Flag:    composeFlag(payloadSessionRequest, false, false),
		Time:    uint32(time.Now().Unix()),
		Payload: srb,
	}
	// Marshal the datagram
	srdb, err := srd.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// Send the message over the UDP connection
	_, err = udp.Write(srdb)
	if err != nil {
		return nil, err
	}

	// Receive a Session Created or nothing
	//_, err := udp.Read()
	// dh.NewPublicKey(decryptedSessionCreated.Y[:])

	return nil, errors.New("not fully implemented")
}

// DialIndirect does an indirect dial
// NOT IMPLEMENTED
func (d *Dialer) DialIndirect() (*Conn, error) {
	return nil, nil
}
