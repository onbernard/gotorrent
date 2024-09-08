package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"time"
)

type ConnectionRequestParams struct {
	TransactionID uint32
}

func MakeConnectionRequest(p *ConnectionRequestParams) [16]byte {
	if p.TransactionID == 0 {
		p.TransactionID = rand.Uint32()
	}
	var request [16]byte
	binary.BigEndian.PutUint64(request[0:], 0x41727101980)
	binary.BigEndian.PutUint32(request[8:], 0x0)
	binary.BigEndian.PutUint32(request[12:], p.TransactionID)
	return request
}

type ConnectionResponse struct {
	Action        uint32
	TransactionID uint32
	ConnectionID  uint64
}

func ParseConnectionResponse(buffer []byte) (*ConnectionResponse, error) {
	if len(buffer) < 16 {
		return nil, fmt.Errorf("connection response too short: %v<16", len(buffer))
	}
	action := binary.BigEndian.Uint32(buffer[0:])
	recvTransactionID := binary.BigEndian.Uint32(buffer[4:])
	connectionID := binary.BigEndian.Uint64(buffer[8:])
	return &ConnectionResponse{
		Action:        action,
		TransactionID: recvTransactionID,
		ConnectionID:  connectionID,
	}, nil
}

type AnnounceRequestParams struct {
	ConnectionID  uint64
	TransactionID uint32
	InfoHash      string
	PeerID        string
	Downloaded    uint64
	Left          uint64
	Uploaded      uint64
	IpAdress      uint32
	Key           uint32
	NumWant       uint32
	Port          uint16
}

// If ipAddress is 0, tracker will infer it
func MakeAnnounceRequest(p *AnnounceRequestParams) ([98]byte, error) {
	if p.TransactionID == 0 {
		p.TransactionID = rand.Uint32()
	}
	if len(p.InfoHash) != 40 {
		return [98]byte{}, errors.New("infoHash should be a string of length 40")
	}
	if p.PeerID == "" {
		p.PeerID = RandStringBytes(40)
	}
	if len(p.PeerID) != 40 {
		return [98]byte{}, errors.New("if set, peerID should be a string of length 40")
	}
	if p.Left == 0 {
		p.Left = 0xFFFFFFFFFFFFFFFF
	}
	if p.Key == 0 {
		p.Key = rand.Uint32()
	}
	if p.NumWant == 0 {
		p.NumWant = 0xFFFFFFFF
	}
	if p.Port == 0 {
		p.Port = uint16(rand.Intn(int(16382))) + 49152
	}
	var buf [98]byte
	binary.BigEndian.PutUint64(buf[0:], p.ConnectionID)   // Connection ID
	binary.BigEndian.PutUint32(buf[8:], 0x1)              // Action, 1 for announce
	binary.BigEndian.PutUint32(buf[12:], p.TransactionID) // TransactionID
	copy(buf[16:], []byte(p.InfoHash))
	copy(buf[36:], []byte(p.PeerID))
	binary.BigEndian.PutUint64(buf[56:], p.Downloaded) // Downloaded
	binary.BigEndian.PutUint64(buf[64:], p.Left)       // left, -1 (0xFFFFFFFF) for default
	binary.BigEndian.PutUint64(buf[72:], p.Uploaded)   // Uploaded
	binary.BigEndian.PutUint32(buf[80:], 0x2)          // Event, 2 for started
	binary.BigEndian.PutUint32(buf[84:], p.IpAdress)   // Ip adress, optional
	binary.BigEndian.PutUint32(buf[88:], p.Key)        // Key, random
	binary.BigEndian.PutUint32(buf[92:], p.NumWant)    // Num want, -1 (0xFFFFFFFF) for default
	binary.BigEndian.PutUint16(buf[96:], p.Port)       // Port
	return buf, nil
}

type Peer struct {
	IP   net.IP
	Port uint16
}

type AnnounceResponse struct {
	TransactionID uint32
	Interval      uint32
	Leechers      uint32
	Seeders       uint32
	Peers         []Peer
}

func ParseAnnounceResponse(buffer []byte) (*AnnounceResponse, error) {
	if len(buffer) < 20 {
		return nil, fmt.Errorf("announce response too short: %v<16", len(buffer))
	}
	transactionID := binary.BigEndian.Uint32(buffer[4:])
	interval := binary.BigEndian.Uint32(buffer[8:])
	leechers := binary.BigEndian.Uint32(buffer[12:])
	seeders := binary.BigEndian.Uint32(buffer[16:])

	peers := []Peer{}
	peerData := buffer[20:]

	if len(peerData)%6 != 0 {
		return nil, errors.New("peer data length is not a multiple of 6")
	}

	for i := 0; i < len(peerData); i += 6 {
		ip := net.IPv4(peerData[i], peerData[i+1], peerData[i+2], peerData[i+3])
		port := binary.BigEndian.Uint16(peerData[i+4 : i+6])
		peers = append(peers, Peer{IP: ip, Port: port})
	}

	return &AnnounceResponse{
		TransactionID: transactionID,
		Interval:      interval,
		Leechers:      leechers,
		Seeders:       seeders,
		Peers:         peers,
	}, nil
}

func RequestUDPTracker(trackerURL string, hash string) (*AnnounceResponse, error) {
	u, err := url.Parse(trackerURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "udp" {
		return nil, fmt.Errorf("unexpected scheme: %v", u.Scheme)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", u.Host)
	if err != nil {
		return nil, err
	}
	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Set timeout
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, err
	}
	// Send connection request to the tracker
	connectionParams := ConnectionRequestParams{}
	connRequest := MakeConnectionRequest(&connectionParams)
	_, err = conn.Write(connRequest[:])
	if err != nil {
		return nil, err
	}
	// Receive connection response from the tracker
	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}
	if n < 16 {
		return nil, fmt.Errorf("connection response too short: %v<16", n)
	}
	connResponse, err := ParseConnectionResponse(buffer[0:n])
	if err != nil {
		return nil, err
	}
	if connResponse.Action != 0 {
		return nil, fmt.Errorf("unexpected action in connection response: %v", connResponse.Action)
	}
	// Send announce request to the tracker
	announceParams := AnnounceRequestParams{
		ConnectionID: connResponse.ConnectionID,
		InfoHash:     hash,
	}
	announceRequest, err := MakeAnnounceRequest(&announceParams)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write((announceRequest[:]))
	if err != nil {
		return nil, err
	}
	n, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}
	if n < 20 {
		return nil, fmt.Errorf("announce request too short: %v<20", n)
	}
	announceResponse, err := ParseAnnounceResponse(buffer[0:n])
	if err != nil {
		return nil, err
	}
	return announceResponse, nil
}
